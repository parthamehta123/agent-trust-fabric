"""HTTP shell for the reference agent runtime (the AgentCore Runtime contract).

* ``POST /invocations``: ``AgentRuntime.invoke``, with status, body and ``WWW-Authenticate``
  propagated.
* ``GET /ping``: health.
* ``build_runtime_from_env``: issuer, audience and JWKS URI from env. JWKS is fetched over TLS
  that trusts only ``ATF_CA_BUNDLE``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.concurrency import run_in_threadpool

from atf_agent_runtime.runtime import AgentRuntime
from trustkit.jwt import JwksKeyResolver
from trustkit.resource import Principal, ResourceAuthorizer
from trustkit_http.endpoint import HttpxTokenEndpoint


def _single_valued_headers(request: Request) -> dict[str, str] | None:
    """Raw headers -> dict, or None if any name repeats (case-insensitive): header smuggling."""
    out: dict[str, str] = {}
    for raw_name, raw_value in request.headers.raw:
        name = raw_name.decode("latin-1")
        if name.lower() in {k.lower() for k in out}:
            return None
        out[name] = raw_value.decode("latin-1")
    return out


def create_app(runtime: AgentRuntime) -> FastAPI:
    app = FastAPI(title="agent-runtime", docs_url=None, redoc_url=None)

    @app.post("/invocations")
    async def invocations(request: Request) -> Response:
        headers = _single_valued_headers(request)
        if headers is None:
            return Response(b'{"error": "bad_request"}', 400, media_type="application/json")
        body = await request.body()
        # Blocking work (JWKS fetch, agent call) runs off the event loop (TM-ING-05).
        result = await run_in_threadpool(runtime.invoke, headers, body)
        extra = {k: v for k, v in result.headers.items() if k.lower() != "content-type"}
        return Response(result.body, result.status, headers=extra, media_type="application/json")

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app


def echo_agent(principal: Principal, request: Mapping[str, Any]) -> Mapping[str, Any]:
    """Reference agent: echoes the prompt. Real agents plug in here (Phase 3: LLM via LiteLLM)."""
    return {"output": str(request.get("prompt", ""))}


def build_runtime_from_env(env: Mapping[str, str]) -> AgentRuntime:
    """Required env: ATF_RESOURCE_ISSUER, ATF_RESOURCE_AUDIENCE, ATF_RESOURCE_JWKS_URI,
    ATF_CA_BUNDLE. A missing variable raises ``KeyError`` naming it."""
    issuer, audience = env["ATF_RESOURCE_ISSUER"], env["ATF_RESOURCE_AUDIENCE"]
    jwks_uri, ca = env["ATF_RESOURCE_JWKS_URI"], env["ATF_CA_BUNDLE"]
    http = HttpxTokenEndpoint(ca_bundle_path=ca)
    keys = JwksKeyResolver(fetch=lambda: http.get_json(jwks_uri))
    return AgentRuntime(
        authorizer=ResourceAuthorizer(issuer=issuer, audience=audience, keys=keys),
        agent=echo_agent,
    )


def app_from_env() -> FastAPI:
    """uvicorn --factory entrypoint."""
    return create_app(build_runtime_from_env(os.environ))
