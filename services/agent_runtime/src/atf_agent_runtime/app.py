"""HTTP shell for the reference agent runtime (the AgentCore Runtime contract).

* ``POST /invocations``: ``AgentRuntime.invoke``, with status, body and ``WWW-Authenticate``
  propagated.
* ``GET /ping``: health.
* ``build_runtime_from_env``: issuer, audience and JWKS URI from env. JWKS is fetched over TLS
  that trusts only ``ATF_CA_BUNDLE``.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.concurrency import run_in_threadpool

from atf_agent_runtime.runtime import AgentRuntime
from trustkit.config import ca_bundle
from trustkit.dpop import DpopKey, dpop_post
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


def echo_agent(
    principal: Principal, request: Mapping[str, Any], credential: str
) -> Mapping[str, Any]:
    """Reference agent: echoes the prompt. Real agents plug in here (Phase 3: LLM via LiteLLM)."""
    return {"output": str(request.get("prompt", ""))}


_TICKET = re.compile(r"\bT-\d{1,9}\b")


def tool_agent(
    *,
    mcp_url: str,
    workload_token: Callable[[], str],
    post_json: Callable[[str, Mapping[str, Any], Mapping[str, str]], tuple[int, Any]],
) -> Callable[[Principal, Mapping[str, Any], str], Mapping[str, Any]]:
    """A minimal tool-using agent (ADR-0024, 4c-ii): for a prompt naming a ticket (``T-<n>``)
    it lists tools at the MCP gateway, calls the ``get_ticket`` tool with its *own* workload
    token and the inbound (delegated) token as the subject, and returns the tool's text.
    Anything else: a fixed refusal. Tokens are never returned or logged."""
    refusal = {"output": "I can only fetch tickets (e.g. 'get ticket T-7')."}

    def agent(
        principal: Principal, request: Mapping[str, Any], credential: str
    ) -> Mapping[str, Any]:
        prompt = request.get("prompt")
        m = _TICKET.search(prompt) if isinstance(prompt, str) else None
        if m is None:
            return refusal
        headers = {"Authorization": f"Bearer {workload_token()}", "X-Subject-Token": credential}
        _, listing = post_json(
            mcp_url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers
        )
        tools = (
            (listing or {}).get("result", {}).get("tools", []) if isinstance(listing, dict) else []
        )
        name = next(
            (
                t["name"]
                for t in tools
                if isinstance(t, dict) and str(t.get("name", "")).endswith("__get_ticket")
            ),
            None,
        )
        if name is None:
            return {"output": "No ticket tool is available to me for you."}
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": {"id": m.group(0)}},
        }
        _, reply = post_json(mcp_url, call, headers)
        try:
            text = reply["result"]["content"][0]["text"]
        except (KeyError, IndexError, TypeError):
            return {"output": "The ticket tool refused the request."}
        return {"output": str(text)}

    return agent


def build_runtime_from_env(env: Mapping[str, str]) -> AgentRuntime:
    """Required: ATF_RESOURCE_ISSUER, ATF_RESOURCE_AUDIENCE, ATF_RESOURCE_JWKS_URI,
    ATF_CA_BUNDLE. A missing variable raises ``KeyError`` naming it.

    Optional (ADR-0024):
    * ``ATF_AGENT_ID`` + bundle settings: accept delegated tokens from an actor only when Cedar
      ``delegate`` actor -> this agent holds on the *current* bundle (no bundle -> refuse).
    * ``ATF_MCP_URL`` + ``ATF_WORKLOAD_*``: act as the minimal tool-using agent."""
    issuer, audience = env["ATF_RESOURCE_ISSUER"], env["ATF_RESOURCE_AUDIENCE"]
    jwks_uri, ca = env["ATF_RESOURCE_JWKS_URI"], ca_bundle(env)
    http = HttpxTokenEndpoint(ca_bundle_path=ca)
    keys = JwksKeyResolver(fetch=lambda: http.get_json(jwks_uri))

    accept_actor: Callable[[str], bool] | None = None
    if "ATF_AGENT_ID" in env:
        from trustkit_aws.s3_bundles import s3_source_factory
        from trustkit_policy.runtime import delegate_decision, policy_from_env

        me = env["ATF_AGENT_ID"]
        policy = policy_from_env(
            env, s3_factory=s3_source_factory(env.get("AWS_REGION", "us-east-1"))
        )

        def accept_actor(actor: str) -> bool:
            loaded = policy()
            return (
                loaded is not None
                and delegate_decision(
                    loaded, from_agent=actor, to_agent=me, user="", user_scopes=frozenset()
                ).allowed
            )

    agent: Callable[[Principal, Mapping[str, Any], str], Mapping[str, Any]] = echo_agent
    if "ATF_MCP_URL" in env:
        import httpx

        from trustkit.workload import WorkloadTokenProvider
        from trustkit_aws.signers import make_signer_factory
        from trustkit_http.endpoint import tls_context

        # ADR-0028: ATF_WORKLOAD_DPOP=1 binds the workload token to an ephemeral in-memory key
        # and proves possession on every egress call (agent-by-agent rollout).
        dpop_key = DpopKey() if env.get("ATF_WORKLOAD_DPOP") == "1" else None
        provider = WorkloadTokenProvider(
            http=http,
            signer=make_signer_factory(env)(env["ATF_WORKLOAD_SIGNING_KEY"]),
            client_id=env["ATF_WORKLOAD_CLIENT_ID"],
            token_endpoint=env["ATF_WORKLOAD_TOKEN_ENDPOINT"],
            scope="tools.invoke",
            dpop=dpop_key,
        )
        client = httpx.Client(verify=tls_context(ca), timeout=10, follow_redirects=False)

        def raw_post(
            url: str, payload: Mapping[str, Any], headers: Mapping[str, str]
        ) -> tuple[int, Any, Mapping[str, str]]:
            r = client.post(url, json=dict(payload), headers=dict(headers))
            rh = {k.lower(): v for k, v in r.headers.items()}
            try:
                return r.status_code, r.json(), rh
            except ValueError:
                return r.status_code, None, rh

        def plain_post(
            url: str, payload: Mapping[str, Any], headers: Mapping[str, str]
        ) -> tuple[int, Any]:
            status, body, _ = raw_post(url, payload, headers)
            return status, body

        post_json = dpop_post(dpop_key, raw_post) if dpop_key is not None else plain_post

        agent = tool_agent(
            mcp_url=env["ATF_MCP_URL"], workload_token=provider.token, post_json=post_json
        )
    return AgentRuntime(
        authorizer=ResourceAuthorizer(
            issuer=issuer, audience=audience, keys=keys, accept_actor=accept_actor
        ),
        agent=agent,
    )


def app_from_env() -> FastAPI:
    """uvicorn --factory entrypoint."""
    return create_app(build_runtime_from_env(os.environ))
