"""Event adapters against the AWS-documented payload shapes (ADR-0012 §1)."""

from __future__ import annotations

import base64
import copy
import json
import pathlib
from types import SimpleNamespace
from typing import Any

import pytest
from atf_interceptor.events import (
    EventError,
    Phase,
    Shape,
    deny,
    forward_request,
    gateway_id_from_context,
    parse_event,
    pass_response,
    replace_response_text,
    request_id_from_context,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-alpha"


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())  # type: ignore[no-any-return]


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class TestParseDocumentedShapes:
    def test_mcp_request(self) -> None:
        ev = parse_event(fixture("aws_doc_mcp_request"))
        assert (ev.shape, ev.phase) == (Shape.MCP, Phase.REQUEST)
        assert ev.headers is not None
        assert ev.headers.get("authorization") == "<bearer_token>"
        assert ev.jsonrpc_id == 1
        assert ev.request_text is not None
        assert json.loads(ev.request_text) == {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

    def test_mcp_response(self) -> None:
        ev = parse_event(fixture("aws_doc_mcp_response"))
        assert (ev.shape, ev.phase, ev.response_status) == (Shape.MCP, Phase.RESPONSE, 200)
        assert ev.response_text is not None
        assert json.loads(ev.response_text)["result"] == {"tools": []}

    def test_http_request(self) -> None:
        ev = parse_event(fixture("aws_doc_http_request"))
        assert (ev.shape, ev.phase) == (Shape.HTTP, Phase.REQUEST)
        assert ev.request_text == '{"prompt": "hello"}'
        assert ev.headers is not None
        assert ev.headers.get("AUTHORIZATION") == "<bearer_token>"

    def test_http_response_with_null_request(self) -> None:
        """AWS: HTTP RESPONSE events carry gatewayRequest: null."""
        ev = parse_event(fixture("aws_doc_http_response"))
        assert (ev.shape, ev.phase, ev.response_status) == (Shape.HTTP, Phase.RESPONSE, 200)
        assert ev.response_text == '{"result": "ok"}'
        assert ev.headers is None

    def test_headers_absent_without_pass_request_headers(self) -> None:
        e = fixture("aws_doc_http_request")
        del e["http"]["gatewayRequest"]["headers"]
        assert parse_event(e).headers is None


@pytest.mark.security
class TestStrictParsing:
    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda e: e.update(interceptorInputVersion="2.0"), id="version"),
            pytest.param(lambda e: e.pop("interceptorInputVersion"), id="no-version"),
            pytest.param(lambda e: e.update(mcp={}), id="both-shapes"),
            pytest.param(lambda e: e.pop("http"), id="no-shape"),
            pytest.param(
                lambda e: e["http"]["gatewayRequest"].update(body="!!not-base64!!"), id="bad-b64"
            ),
            pytest.param(
                lambda e: e["http"]["gatewayRequest"].update(headers="x"), id="headers-not-map"
            ),
            pytest.param(
                lambda e: e["http"]["gatewayRequest"].update(headers={"A": 1}), id="header-not-str"
            ),
        ],
    )
    def test_rejects(self, mutate: Any) -> None:
        e = fixture("aws_doc_http_request")
        mutate(e)
        with pytest.raises(EventError):
            parse_event(e)

    @pytest.mark.parametrize(
        ("name", "mutate"),
        [
            pytest.param(
                "aws_doc_http_response",
                lambda e: e["http"]["gatewayResponse"].update(statusCode=True),
                id="status-bool",
            ),
            pytest.param(
                "aws_doc_http_response",
                lambda e: e["http"]["gatewayResponse"].update(statusCode=99),
                id="status-range",
            ),
            pytest.param(
                "aws_doc_http_response",
                lambda e: e["http"]["gatewayResponse"].update(body=5),
                id="http-body-type",
            ),
            pytest.param(
                "aws_doc_mcp_request",
                lambda e: e["mcp"]["gatewayRequest"].update(body="x"),
                id="mcp-body-type",
            ),
            pytest.param(
                "aws_doc_mcp_request", lambda e: e["mcp"].pop("gatewayRequest"), id="mcp-no-request"
            ),
        ],
    )
    def test_rejects_bad_fields(self, name: str, mutate: Any) -> None:
        e = fixture(name)
        mutate(e)
        with pytest.raises(EventError):
            parse_event(e)

    def test_http_request_without_body(self) -> None:
        e = fixture("aws_doc_http_request")
        del e["http"]["gatewayRequest"]["body"]
        assert parse_event(e).request_text is None

    @pytest.mark.parametrize("bad", [None, [], "x", 1, {}])
    def test_rejects_non_events(self, bad: Any) -> None:
        with pytest.raises(EventError):
            parse_event(bad)

    def test_duplicate_header_case_variants_rejected(self) -> None:
        """'Authorization' and 'authorization' both present is ambiguous (smuggling), so reject."""
        e = fixture("aws_doc_http_request")
        e["http"]["gatewayRequest"]["headers"]["authorization"] = "Bearer other"
        with pytest.raises(EventError):
            parse_event(e)

    def test_error_messages_do_not_echo_payload(self) -> None:
        e = fixture("aws_doc_http_request")
        e["http"]["gatewayRequest"]["body"] = "SECRET!!"
        with pytest.raises(EventError) as ei:
            parse_event(e)
        assert "SECRET" not in str(ei.value)


class TestContext:
    def ctx(self, custom: Any, request_id: str = "lambda-req") -> Any:
        return SimpleNamespace(
            client_context=SimpleNamespace(custom=custom), aws_request_id=request_id
        )

    def test_gateway_id(self) -> None:
        assert gateway_id_from_context(self.ctx({"GATEWAY_ARN": ARN})) == "gw-alpha"

    @pytest.mark.security
    @pytest.mark.parametrize(
        "custom",
        [
            None,
            {},
            {"GATEWAY_ARN": ""},
            {"GATEWAY_ARN": "gw-alpha"},
            {"GATEWAY_ARN": "arn:aws:lambda:us-east-1:123456789012:function:gw-alpha"},
            {"GATEWAY_ARN": ARN + "/extra"},
            {"GATEWAY_ARN": 7},
        ],
    )
    def test_gateway_id_rejects_anything_unexpected(self, custom: Any) -> None:
        """TM-ING-04"""
        assert gateway_id_from_context(self.ctx(custom)) is None

    def test_gateway_id_without_client_context(self) -> None:
        assert gateway_id_from_context(SimpleNamespace()) is None
        assert gateway_id_from_context(None) is None

    def test_request_id_precedence(self) -> None:
        assert request_id_from_context(self.ctx({"REQUEST_ID": "gw-req"})) == "gw-req"
        assert request_id_from_context(self.ctx({})) == "lambda-req"
        assert request_id_from_context(None) == "unknown"


class TestOutputs:
    def test_forward_request_http_keeps_body_and_sets_only_given_headers(self) -> None:
        ev = parse_event(fixture("aws_doc_http_request"))
        out = forward_request(ev, headers={"Authorization": "Bearer T2", "x-atf-decision": "allow"})
        assert out["interceptorOutputVersion"] == "1.0"
        req = out["http"]["transformedGatewayRequest"]
        assert req["body"] == fixture("aws_doc_http_request")["http"]["gatewayRequest"]["body"]
        assert req["headers"] == {"Authorization": "Bearer T2", "x-atf-decision": "allow"}
        assert "transformedGatewayResponse" not in out["http"]

    def test_forward_request_mcp(self) -> None:
        ev = parse_event(fixture("aws_doc_mcp_request"))
        out = forward_request(ev, headers={"Authorization": "Bearer T2"})
        assert out["mcp"]["transformedGatewayRequest"]["body"] == {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        }

    @pytest.mark.parametrize("status", [401, 403, 503])
    def test_deny_http(self, status: int) -> None:
        out = deny(Shape.HTTP, status=status, request_id="req-9")
        r = out["http"]["transformedGatewayResponse"]
        assert r["statusCode"] == status
        assert r["contentType"] == "application/json"
        assert json.loads(base64.b64decode(r["body"])) == {
            "error": "request_denied",
            "request_id": "req-9",
        }

    def test_deny_mcp_is_jsonrpc_error_with_request_id(self) -> None:
        out = deny(Shape.MCP, status=403, request_id="req-9", jsonrpc_id=7)
        r = out["mcp"]["transformedGatewayResponse"]
        assert r["statusCode"] == 403
        assert r["body"]["jsonrpc"] == "2.0"
        assert r["body"]["id"] == 7
        assert r["body"]["error"]["code"] == -32000
        assert r["body"]["error"]["data"] == {"request_id": "req-9"}

    def test_pass_response_http_is_empty_object(self) -> None:
        """AWS: an empty http object passes the response through unchanged."""
        out = pass_response(parse_event(fixture("aws_doc_http_response")))
        assert out == {"interceptorOutputVersion": "1.0", "http": {}}

    def test_pass_response_mcp_echoes_original(self) -> None:
        e = fixture("aws_doc_mcp_response")
        out = pass_response(parse_event(copy.deepcopy(e)))
        r = out["mcp"]["transformedGatewayResponse"]
        assert (r["statusCode"], r["body"]) == (200, e["mcp"]["gatewayResponse"]["body"])

    def test_replace_response_text(self) -> None:
        out = replace_response_text(
            parse_event(fixture("aws_doc_http_response")), '{"result": "[REDACTED]"}'
        )
        r = out["http"]["transformedGatewayResponse"]
        assert r["statusCode"] == 200
        assert base64.b64decode(r["body"]).decode() == '{"result": "[REDACTED]"}'
