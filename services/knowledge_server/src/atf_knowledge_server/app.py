"""Knowledge server MCP endpoint (ADR-0025 §4).

* ``tools/list``: the ``search`` tool (discovery, unauthenticated like other MCP servers).
* ``tools/call search``: requires the MCP gateway's delegated token (``typ at+jwt``, this
  server's audience, ``act`` chain of at most two actors). The user's collections come from its
  ``kb.<collection>.read`` scopes; the agent chain from ``act``. Agents supply only ``query`` and
  ``top_k``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from atf_knowledge_server.retrieval import (
    MAX_QUERY_CHARS,
    MAX_TOP_K,
    RetrievalResult,
    RetrievalUnavailableError,
    Retriever,
)
from trustkit.binding import parse_act_chain
from trustkit.config import ca_bundle
from trustkit.jwt import TokenValidationError, TokenValidator

_TOOL: Final = {
    "name": "search",
    "description": "Search the knowledge base for documents you and the user may see.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "maxLength": MAX_QUERY_CHARS},
            "top_k": {"type": "integer", "minimum": 1, "maximum": MAX_TOP_K},
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}


@dataclass(frozen=True)
class Caller:
    user: str
    agent_id: str
    chain: tuple[str, ...]
    """Prior actors, oldest first."""
    scopes: frozenset[str]


CallerAuth = Callable[[Mapping[str, str]], Caller]
"""Headers -> validated caller; raises ``ValueError`` on any token problem."""


def _rpc(
    rid: Any, *, result: Any = None, code: int | None = None, status: int = 200
) -> JSONResponse:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": rid}
    if code is None:
        body["result"] = result
    else:
        body["error"] = {"code": code, "message": "error"}
    return JSONResponse(body, status_code=status)


def _arguments(params: Any) -> tuple[str, int] | None:
    if not isinstance(params, dict) or params.get("name") != "search":
        return None
    args = params.get("arguments")
    if not isinstance(args, dict) or not set(args) <= {"query", "top_k"}:
        return None  # agents can't supply or widen the filter
    query, top_k = args.get("query"), args.get("top_k", 5)
    if not isinstance(query, str) or not query or len(query) > MAX_QUERY_CHARS:
        return None
    if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= MAX_TOP_K:
        return None
    return query, top_k


def _render(result: RetrievalResult) -> str:
    """Only text, title, collection and classification (ADR-0025 §6)."""
    lines = [f"[{c.collection}/{c.classification}] {c.title}: {c.text}" for c in result.chunks]
    if not lines:
        lines.append("No matching documents you are allowed to see.")
    if result.withheld:
        lines.append(f"({result.withheld} result(s) withheld)")
    return "\n".join(lines)


def create_app(retriever: Retriever, caller: CallerAuth) -> FastAPI:
    app = FastAPI(title="knowledge-server", docs_url=None, redoc_url=None)

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        names = [n.decode("latin-1").lower() for n, _ in request.headers.raw]
        if len(names) != len(set(names)):
            return _rpc(None, code=-32600, status=400)
        try:
            body = json.loads(await request.body())
        except (ValueError, RecursionError):
            return _rpc(None, code=-32700, status=400)
        if not isinstance(body, dict):
            return _rpc(None, code=-32600, status=400)
        rid, method = body.get("id"), body.get("method")
        if method == "tools/list":
            return _rpc(rid, result={"tools": [_TOOL]})
        if method != "tools/call":
            return _rpc(rid, code=-32601)
        headers = {k.lower(): v for k, v in request.headers.items()}
        try:
            who = caller(headers)
        except ValueError:
            return _rpc(rid, code=-32001, status=401)
        parsed = _arguments(body.get("params"))
        if parsed is None:
            return _rpc(rid, code=-32602)
        query, top_k = parsed
        try:
            result = await run_in_threadpool(
                lambda: retriever.retrieve(
                    agent_id=who.agent_id,
                    chain=who.chain,
                    user=who.user,
                    user_scopes=who.scopes,
                    query=query,
                    top_k=top_k,
                )
            )
        except ValueError:
            return _rpc(rid, code=-32602)
        except RetrievalUnavailableError:
            return _rpc(rid, code=-32002, status=503)
        return _rpc(rid, result={"content": [{"type": "text", "text": _render(result)}]})

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app


def caller_from_token(validator: TokenValidator) -> CallerAuth:
    """Delegated-token validation for this server: ``sub`` = user, ``act`` = agent chain."""

    def caller(headers: Mapping[str, str]) -> Caller:
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer ") or len(auth) <= len("Bearer "):
            raise ValueError("missing token")
        try:
            token = validator.validate(auth.removeprefix("Bearer "))
        except TokenValidationError:
            raise ValueError("invalid token") from None
        actors = parse_act_chain(token.claims.get("act"))  # ValueError if malformed
        if not 1 <= len(actors) <= 2:
            raise ValueError("delegated token required (one or two actors)")
        scope = token.claims.get("scope")
        if not isinstance(scope, str):
            raise ValueError("token has no scope")  # noqa: TRY004 - CallerAuth contract: ValueError = 401
        return Caller(
            user=token.subject,
            agent_id=actors[-1],  # the current actor is outermost (newest)
            chain=actors[:-1],
            scopes=frozenset(scope.split()),
        )

    return caller


def build_app(env: Mapping[str, str]) -> FastAPI:
    """``ATF_KB_ISSUER``/``_AUDIENCE``/``_JWKS_URI`` (the delegated-token AS for this server),
    ``ATF_CA_BUNDLE``, bundle settings, and ``ATF_KB_INDEX_PATH`` (local) **or**
    ``ATF_KB_BEDROCK_ID`` (AWS)."""
    import pathlib
    import sys
    import time

    from atf_knowledge_server.store import LocalVectorStore, VectorStore
    from trustkit.audit import JsonLinesSink
    from trustkit.jwt import JwksKeyResolver, ValidationPolicy, access_token_profile_from_env
    from trustkit.scanning import LocalRulesScanner
    from trustkit_aws.s3_bundles import s3_source_factory
    from trustkit_http.endpoint import HttpxTokenEndpoint
    from trustkit_policy.runtime import policy_from_env

    issuer, audience, jwks_uri = (
        env["ATF_KB_ISSUER"],
        env["ATF_KB_AUDIENCE"],
        env["ATF_KB_JWKS_URI"],
    )
    region = env.get("AWS_REGION", "us-east-1")
    http = HttpxTokenEndpoint(ca_bundle_path=ca_bundle(env))
    validator = TokenValidator(
        ValidationPolicy(
            issuer=issuer,
            audiences=frozenset({audience}),
            expected_typ="at+jwt",
            access_token_profile=access_token_profile_from_env(env),
        ),
        JwksKeyResolver(fetch=lambda: http.get_json(jwks_uri)),
    )
    index, kb_id = env.get("ATF_KB_INDEX_PATH"), env.get("ATF_KB_BEDROCK_ID")
    store: VectorStore
    if index and not kb_id:
        store = LocalVectorStore(pathlib.Path(index))
    elif kb_id and not index:
        import boto3

        from atf_knowledge_server.bedrock_kb import BedrockKbStore

        store = BedrockKbStore(
            boto3.client("bedrock-agent-runtime", region_name=region), knowledge_base_id=kb_id
        )
    else:
        raise ValueError("knowledge backend: set ATF_KB_INDEX_PATH or ATF_KB_BEDROCK_ID")
    audit = JsonLinesSink(sys.stdout)
    retriever = Retriever(
        store=store,
        policy=policy_from_env(env, s3_factory=s3_source_factory(region), audit=audit),
        scanner=LocalRulesScanner(),
        audit=audit,
        now=lambda: int(time.time()),
    )
    return create_app(retriever, caller_from_token(validator))


def app_from_env() -> FastAPI:
    import os

    return build_app(dict(os.environ))
