"""Emulator remote adapters and HTTP shell (ADR-0015)."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway_emulator.app import HttpsTarget, RieInterceptor, create_app
from gateway_emulator.core import GatewayResponse

RIE = "http://interceptor:8080/2015-03-31/functions/function/invocations"


def ctx(custom: dict[str, str]) -> Any:
    return SimpleNamespace(client_context=SimpleNamespace(custom=custom))


class TestRieInterceptor:
    def test_posts_event_with_client_context_header(self) -> None:
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(200, json={"interceptorOutputVersion": "1.0", "http": {}})

        rie = RieInterceptor(RIE, client=httpx.Client(transport=httpx.MockTransport(handler)))
        out = rie(
            {"interceptorInputVersion": "1.0"}, ctx({"GATEWAY_ARN": "arn:x", "REQUEST_ID": "r1"})
        )
        assert out == {"interceptorOutputVersion": "1.0", "http": {}}
        (req,) = seen
        assert str(req.url) == RIE
        assert json.loads(req.content) == {"interceptorInputVersion": "1.0"}
        cc = json.loads(base64.b64decode(req.headers["x-amz-client-context"]))
        assert cc == {"custom": {"GATEWAY_ARN": "arn:x", "REQUEST_ID": "r1"}}

    @pytest.mark.security
    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(500, json={}),
            httpx.Response(200, content=b"not json"),
            httpx.Response(200, json=[1]),
        ],
    )
    def test_bad_responses_raise(self, response: httpx.Response) -> None:
        """Raising makes the emulator answer 502 (fail closed, ED-6)."""
        rie = RieInterceptor(
            RIE, client=httpx.Client(transport=httpx.MockTransport(lambda r: response))
        )
        with pytest.raises(Exception):  # noqa: B017, PT011 - any exception -> emulator 502
            rie({}, ctx({}))


class TestHttpsTarget:
    def test_https_only(self, tmp_path: Any) -> None:
        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        with pytest.raises(ValueError, match="https"):
            HttpsTarget("http://agent-runtime:8443/invocations", ca_bundle_path=str(ca))

    def test_forwards_headers_and_body(self, tmp_path: Any) -> None:
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(
                201, content=b'{"a":1}', headers={"content-type": "application/json"}
            )

        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        t = HttpsTarget(
            "https://agent-runtime:8443/invocations",
            ca_bundle_path=str(ca),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        r = t({"Authorization": "Bearer t2"}, b'{"p":1}')
        assert (r.status, r.body, r.content_type) == (201, b'{"a":1}', "application/json")
        assert seen[0].headers["authorization"] == "Bearer t2"
        assert seen[0].content == b'{"p":1}'


class TestShell:
    def test_routes_to_emulator(self) -> None:
        calls: list[tuple[str, dict[str, str], bytes, str | None]] = []

        class Fake:
            def invoke(
                self, path: str, headers: Any, body: bytes, *, source_ip: str | None = None
            ) -> GatewayResponse:
                calls.append((path, dict(headers), body, source_ip))
                return GatewayResponse(202, b'{"ok":true}', "application/json")

        client = TestClient(create_app(Fake()))  # type: ignore[arg-type]
        r = client.post(
            "/agent-alpha/invocations", content=b"{}", headers={"authorization": "Bearer x"}
        )
        assert (r.status_code, r.json()) == (202, {"ok": True})
        path, headers, body, ip = calls[0]
        assert (path, body) == ("/agent-alpha/invocations", b"{}")
        assert headers["authorization"] == "Bearer x"
        assert ip is not None

    def test_ping(self) -> None:
        class Idle:
            def invoke(self, *a: Any, **k: Any) -> GatewayResponse:
                raise AssertionError("not called")

        client = TestClient(create_app(Idle()))  # type: ignore[arg-type]
        assert client.get("/ping").status_code == 200


@pytest.mark.security
class TestShellHeaderSmuggling:
    def test_duplicate_header_names_rejected_at_edge(self) -> None:
        """Header smuggling: repeated names (any case) are rejected before the emulator runs."""

        class Never:
            def invoke(self, *a: Any, **k: Any) -> GatewayResponse:
                raise AssertionError("must not be called")

        client = TestClient(create_app(Never()))  # type: ignore[arg-type]
        r = client.post(
            "/agent-alpha/invocations",
            content=b"{}",
            headers=[("Authorization", "Bearer a"), ("authorization", "Bearer b")],
        )
        assert r.status_code == 400
