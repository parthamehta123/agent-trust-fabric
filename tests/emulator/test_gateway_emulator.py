"""Gateway emulator conformance against documented AgentCore behaviour (ADR-0012/0014).

The emulator is the stand-in for AWS in every e2e test, so it is pinned to the docs. In
particular, it must be *at least as hostile* as the real gateway (A-5 pessimistic reading).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

import pytest

from gateway_emulator.core import GatewayEmulator, HttpTarget, InboundJwt, TargetResponse
from mock_idp.core import AuthorizationServer, MockIdp
from trustkit.policy import RESERVED_HEADERS, AllowlistViolationError

T0 = 1_800_000_000
ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-alpha"
ALLOW = frozenset({*RESERVED_HEADERS, "x-correlation-id"})


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> int:
        return self.t


class FakeTarget:
    def __init__(self) -> None:
        self.calls: list[tuple[dict[str, str], bytes]] = []
        self.response = TargetResponse(200, b'{"answer": "ok"}')

    def __call__(self, headers: Mapping[str, str], body: bytes) -> TargetResponse:
        self.calls.append((dict(headers), body))
        return self.response


class FakeInterceptor:
    def __init__(self) -> None:
        self.events: list[tuple[dict[str, Any], Any]] = []
        self.request_output: dict[str, Any] = {
            "interceptorOutputVersion": "1.0",
            "http": {"transformedGatewayRequest": {"headers": {"Authorization": "Bearer T2"}}},
        }
        self.response_output: dict[str, Any] = {"interceptorOutputVersion": "1.0", "http": {}}
        self.raise_on: str | None = None

    def __call__(self, event: Mapping[str, Any], context: Any) -> Mapping[str, Any]:
        self.events.append((json.loads(json.dumps(event)), context))
        phase = "response" if event["http"].get("gatewayResponse") else "request"
        if self.raise_on == phase:
            raise RuntimeError("interceptor bug")
        return self.request_output if phase == "request" else self.response_output


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def idp(clock: Clock) -> MockIdp:
    idp = MockIdp(now=clock)
    idp.add_authorization_server(
        AuthorizationServer("ingress", "api://agent-ingress", frozenset({"0oa-chat"}))
    )
    return idp


@pytest.fixture
def parts(idp: MockIdp, clock: Clock) -> tuple[GatewayEmulator, FakeInterceptor, FakeTarget]:
    target, interceptor = FakeTarget(), FakeInterceptor()
    gw = GatewayEmulator(
        gateway_arn=ARN,
        inbound=InboundJwt(
            idp.issuer("ingress"), frozenset({"api://agent-ingress"}), lambda: idp.jwks("ingress")
        ),
        targets={"agent-alpha": HttpTarget("agent-alpha", target, ALLOW)},
        interceptor=interceptor,
        now=clock,
    )
    return gw, interceptor, target


def caller_headers(idp: MockIdp, **extra: str) -> dict[str, str]:
    at, _ = idp.login("00u-alice", "0oa-chat", ingress_as_id="ingress")
    return {"Authorization": f"Bearer {at}", "Content-Type": "application/json", **extra}


PATH = "/agent-alpha/invocations"


class TestInbound:
    @pytest.mark.security
    @pytest.mark.parametrize("auth", [None, "Bearer garbage", "Basic x"])
    def test_invalid_caller_token_is_401_before_interceptor(
        self, parts: Any, auth: str | None
    ) -> None:
        gw, interceptor, target = parts
        headers = {} if auth is None else {"Authorization": auth}
        assert gw.invoke(PATH, headers, b"{}").status == 401
        assert interceptor.events == []
        assert target.calls == []

    @pytest.mark.security
    def test_expired_caller_token(self, parts: Any, idp: MockIdp, clock: Clock) -> None:
        gw, interceptor, _ = parts
        h = caller_headers(idp)
        clock.t += 7200
        assert gw.invoke(PATH, h, b"{}").status == 401
        assert interceptor.events == []

    def test_unknown_target(self, parts: Any, idp: MockIdp) -> None:
        gw, _, _ = parts
        assert gw.invoke("/nope/invocations", caller_headers(idp), b"{}").status == 404


class TestRequestInterception:
    def test_event_shape_and_client_context(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, _ = parts
        gw.invoke(PATH, caller_headers(idp), b'{"prompt": "hi"}', source_ip="10.0.0.7")
        event, ctx = interceptor.events[0]
        req = event["http"]["gatewayRequest"]
        assert event["interceptorInputVersion"] == "1.0"
        assert (req["path"], req["httpMethod"]) == (PATH, "POST")
        assert base64.b64decode(req["body"]) == b'{"prompt": "hi"}'
        assert "Authorization" in req["headers"]
        custom = ctx.client_context.custom
        assert custom["GATEWAY_ARN"] == ARN
        assert custom["GATEWAY_ACCOUNT_ID"] == "123456789012"
        assert custom["REQUEST_ID"]
        assert custom["SOURCE_IP"] == "10.0.0.7"

    def test_headers_omitted_without_pass_request_headers(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, _ = parts
        gw.pass_request_headers = False
        gw.invoke(PATH, caller_headers(idp), b"{}")
        assert "headers" not in interceptor.events[0][0]["http"]["gatewayRequest"]

    def test_short_circuit_skips_target_and_response_interceptor(
        self, parts: Any, idp: MockIdp
    ) -> None:
        gw, interceptor, target = parts
        body = base64.b64encode(b'{"error": "request_denied"}').decode()
        interceptor.request_output = {
            "interceptorOutputVersion": "1.0",
            "http": {
                "transformedGatewayResponse": {
                    "statusCode": 403,
                    "body": body,
                    "contentType": "application/json",
                }
            },
        }
        r = gw.invoke(PATH, caller_headers(idp), b"{}")
        assert (r.status, r.body) == (403, b'{"error": "request_denied"}')
        assert target.calls == []
        assert len(interceptor.events) == 1

    @pytest.mark.security
    @pytest.mark.parametrize(
        "output",
        [
            {"interceptorOutputVersion": "2.0", "http": {}},
            {"http": {}},
            {"interceptorOutputVersion": "1.0"},
            "not a dict",
        ],
    )
    def test_malformed_interceptor_output_fails_closed(
        self, parts: Any, idp: MockIdp, output: Any
    ) -> None:
        """A-6 is unknown on real AWS; the emulator must not be more lenient than fail-closed."""
        gw, interceptor, target = parts
        interceptor.request_output = output
        assert gw.invoke(PATH, caller_headers(idp), b"{}").status == 502
        assert target.calls == []

    @pytest.mark.security
    @pytest.mark.parametrize(
        "transformed",
        [{"headers": "not-a-map"}, {"body": "!!not-base64!!"}, {"body": 5}],
    )
    def test_malformed_transformed_request_fails_closed(
        self, parts: Any, idp: MockIdp, transformed: dict[str, Any]
    ) -> None:
        gw, interceptor, target = parts
        interceptor.request_output = {
            "interceptorOutputVersion": "1.0",
            "http": {"transformedGatewayRequest": transformed},
        }
        assert gw.invoke(PATH, caller_headers(idp), b"{}").status == 502
        assert target.calls == []

    @pytest.mark.security
    def test_interceptor_exception_fails_closed(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, target = parts
        interceptor.raise_on = "request"
        assert gw.invoke(PATH, caller_headers(idp), b"{}").status == 502
        assert target.calls == []


@pytest.mark.security
class TestHeaderPropagation:
    def test_authorization_only_from_interceptor(self, parts: Any, idp: MockIdp) -> None:
        gw, _, target = parts
        gw.invoke(PATH, caller_headers(idp), b"{}")
        assert target.calls[0][0]["Authorization"] == "Bearer T2"

    def test_caller_authorization_never_reaches_target(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, target = parts
        interceptor.request_output = {
            "interceptorOutputVersion": "1.0",
            "http": {"transformedGatewayRequest": {}},
        }
        gw.invoke(PATH, caller_headers(idp), b"{}")
        assert "authorization" not in {k.lower() for k in target.calls[0][0]}

    def test_allowlisted_client_header_survives_omission(self, parts: Any, idp: MockIdp) -> None:
        """A-5 pessimistic: omission is not removal, hence the interceptor always overwrites."""
        gw, _, target = parts
        gw.invoke(PATH, caller_headers(idp, **{"x-atf-decision": "forged"}), b"{}")
        assert target.calls[0][0]["x-atf-decision"] == "forged"

    def test_interceptor_wins_conflicts(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, target = parts
        interceptor.request_output["http"]["transformedGatewayRequest"]["headers"][
            "x-atf-decision"
        ] = "allow"
        gw.invoke(PATH, caller_headers(idp, **{"X-ATF-Decision": "forged"}), b"{}")
        hdrs = {k.lower(): v for k, v in target.calls[0][0].items()}
        assert hdrs["x-atf-decision"] == "allow"

    def test_non_allowlisted_headers_dropped(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, target = parts
        interceptor.request_output["http"]["transformedGatewayRequest"]["headers"]["x-internal"] = (
            "1"
        )
        gw.invoke(PATH, caller_headers(idp, **{"X-Subject-Token": "idt", "x-other": "1"}), b"{}")
        sent = {k.lower() for k in target.calls[0][0]}
        assert {"x-internal", "x-subject-token", "x-other"}.isdisjoint(sent)

    def test_original_body_when_interceptor_omits_it(self, parts: Any, idp: MockIdp) -> None:
        gw, _, target = parts
        gw.invoke(PATH, caller_headers(idp), b'{"prompt": "x"}')
        assert target.calls[0][1] == b'{"prompt": "x"}'


class TestResponseInterception:
    def test_response_event_has_null_request(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, _ = parts
        gw.invoke(PATH, caller_headers(idp), b"{}")
        event = interceptor.events[1][0]["http"]
        assert event["gatewayRequest"] is None
        assert event["gatewayResponse"]["statusCode"] == 200
        assert base64.b64decode(event["gatewayResponse"]["body"]) == b'{"answer": "ok"}'

    def test_empty_http_passes_through(self, parts: Any, idp: MockIdp) -> None:
        gw, _, _ = parts
        r = gw.invoke(PATH, caller_headers(idp), b"{}")
        assert (r.status, r.body) == (200, b'{"answer": "ok"}')

    def test_overrides_apply(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, _ = parts
        interceptor.response_output = {
            "interceptorOutputVersion": "1.0",
            "http": {
                "transformedGatewayResponse": {
                    "statusCode": 403,
                    "body": base64.b64encode(b"{}").decode(),
                }
            },
        }
        r = gw.invoke(PATH, caller_headers(idp), b"{}")
        assert (r.status, r.body) == (403, b"{}")

    @pytest.mark.security
    def test_response_interceptor_exception_fails_closed(self, parts: Any, idp: MockIdp) -> None:
        gw, interceptor, _ = parts
        interceptor.raise_on = "response"
        assert gw.invoke(PATH, caller_headers(idp), b"{}").status == 502


class TestConstruction:
    @pytest.mark.security
    def test_credential_header_on_allowlist_rejected(self, idp: MockIdp) -> None:
        with pytest.raises(AllowlistViolationError):
            GatewayEmulator(
                gateway_arn=ARN,
                inbound=InboundJwt("https://x", frozenset({"a"}), lambda: {"keys": []}),
                targets={
                    "t": HttpTarget(
                        "t", FakeTarget(), frozenset({*RESERVED_HEADERS, "x-subject-token"})
                    )
                },
            )

    @pytest.mark.parametrize(
        "arn", ["gw-alpha", "arn:aws:lambda:us-east-1:123456789012:function:x"]
    )
    def test_bad_arn_rejected(self, arn: str) -> None:
        with pytest.raises(ValueError, match="arn"):
            GatewayEmulator(
                gateway_arn=arn,
                inbound=InboundJwt("https://x", frozenset({"a"}), lambda: {"keys": []}),
                targets={},
            )
