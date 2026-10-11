"""HTTP shell + remote adapters for the gateway emulator (ADR-0015). TEST INFRASTRUCTURE ONLY.

* ``RieInterceptor``: calls a Lambda RIE container's Invoke API with the event as the JSON body
  and the client context as ``X-Amz-Client-Context`` (base64 JSON ``{"custom": {...}}``, verified
  by probe). Any non-200 status, non-JSON body or transport error raises, so the emulator answers
  502 (fail closed, ED-6).
* ``HttpsTarget``: forwards to an agent runtime over TLS that trusts only the local CA.
* ``create_app``: ``POST /{target}/invocations`` -> ``GatewayEmulator.invoke`` (source IP passed
  through), ``GET /ping`` health.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from typing import Any, Final

import httpx
from fastapi import FastAPI, Request, Response

from gateway_emulator.core import GatewayEmulator, HttpTarget, InboundJwt, TargetResponse
from trustkit.policy import RESERVED_HEADERS
from trustkit_http.endpoint import HttpxTokenEndpoint, tls_context

_TIMEOUT: Final = httpx.Timeout(10.0, connect=2.0)


class RieInterceptor:
    def __init__(self, invoke_url: str, *, client: httpx.Client | None = None) -> None:
        if not invoke_url.startswith(("http://", "https://")):
            raise ValueError("invoke url must be http(s)")
        self._url = invoke_url
        self._client = client or httpx.Client(timeout=_TIMEOUT, follow_redirects=False)

    def __call__(self, event: Mapping[str, Any], context: Any) -> Mapping[str, Any]:
        custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
        client_context = base64.b64encode(json.dumps({"custom": dict(custom)}).encode()).decode()
        resp = self._client.post(
            self._url, json=dict(event), headers={"X-Amz-Client-Context": client_context}
        )
        if resp.status_code != 200:
            raise RuntimeError("interceptor invoke failed")
        out = resp.json()
        if not isinstance(out, dict):
            raise TypeError("interceptor returned a non-object")
        return out


class HttpsTarget:
    def __init__(
        self, url: str, *, ca_bundle_path: str, client: httpx.Client | None = None
    ) -> None:
        if not url.startswith("https://"):
            raise ValueError("target url must be https")
        self._url = url
        self._client = client or httpx.Client(
            verify=tls_context(ca_bundle_path), timeout=_TIMEOUT, follow_redirects=False
        )

    def __call__(self, headers: Mapping[str, str], body: bytes) -> TargetResponse:
        resp = self._client.post(self._url, content=body, headers=dict(headers))
        ctype = resp.headers.get("content-type", "application/json").split(";")[0].strip()
        return TargetResponse(resp.status_code, resp.content, ctype)


def _single_valued_headers(request: Request) -> dict[str, str] | None:
    """Raw headers -> dict, or None if any name repeats (case-insensitive): header smuggling."""
    out: dict[str, str] = {}
    for raw_name, raw_value in request.headers.raw:
        name = raw_name.decode("latin-1")
        if name.lower() in {k.lower() for k in out}:
            return None
        out[name] = raw_value.decode("latin-1")
    return out


def create_app(emulator: GatewayEmulator) -> FastAPI:
    app = FastAPI(title="gateway-emulator (test infrastructure)", docs_url=None, redoc_url=None)

    @app.post("/{target}/invocations")
    async def invoke(target: str, request: Request) -> Response:
        headers = _single_valued_headers(request)
        if headers is None:
            return Response(b'{"message": "Bad Request"}', 400, media_type="application/json")
        body = await request.body()
        source_ip = request.client.host if request.client else None
        r = emulator.invoke(f"/{target}/invocations", headers, body, source_ip=source_ip)
        return Response(r.body, r.status, media_type=r.content_type)

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app


def app_from_env() -> FastAPI:
    """uvicorn --factory entrypoint. All ATF_* variables are required."""
    env = os.environ
    ca = env["ATF_CA_BUNDLE"]
    jwks_client = HttpxTokenEndpoint(ca_bundle_path=ca)
    jwks_uri = env["ATF_INBOUND_JWKS_URI"]
    emulator = GatewayEmulator(
        gateway_arn=env["ATF_GATEWAY_ARN"],
        inbound=InboundJwt(
            env["ATF_INBOUND_ISSUER"],
            frozenset({env["ATF_INBOUND_AUDIENCE"]}),
            lambda: jwks_client.get_json(jwks_uri),
        ),
        targets={
            env["ATF_TARGET_NAME"]: HttpTarget(
                env["ATF_TARGET_NAME"],
                HttpsTarget(env["ATF_RUNTIME_URL"], ca_bundle_path=ca),
                frozenset(RESERVED_HEADERS),
            )
        },
        interceptor=RieInterceptor(env["ATF_INTERCEPTOR_URL"]),
    )
    return create_app(emulator)
