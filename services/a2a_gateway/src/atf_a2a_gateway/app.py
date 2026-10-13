"""A2A gateway HTTP surface (ADR-0024).

* ``POST /agents/{target}/a2a``: JSON-RPC 2.0 ``message/send`` (text parts only). Caller =
  ``Authorization: Bearer <A's workload token>`` + ``X-Subject-Token: <A's T2>``; A must be the
  first actor (no chains into A2A).
* ``GET /agents/{target}/.well-known/agent-card.json``: workload token only; 404 unless the
  caller may delegate to ``target``.
* ``GET /ping``.
Errors never reveal whether an agent exists to a caller who may not see it.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from atf_a2a_gateway.broker import A2ABroker, A2AError, A2AFailure
from trustkit.binding import ActorBinding, ActorBindingError

_STATUS: Final = {
    A2AFailure.POLICY_UNAVAILABLE: (503, -32002),
    A2AFailure.AUDIT_UNAVAILABLE: (503, -32002),
    A2AFailure.UNKNOWN_AGENT: (404, -32004),
    A2AFailure.DELEGATION_DENIED: (403, -32003),
    A2AFailure.NOT_ENTITLED: (403, -32003),
    A2AFailure.BLOCKED: (403, -32003),
    A2AFailure.EXCHANGE_FAILED: (502, -32005),
    A2AFailure.TARGET_FAILED: (502, -32005),
    A2AFailure.RESPONSE_BLOCKED: (502, -32005),
    A2AFailure.INVALID: (400, -32602),
}


class PolicyUnavailableError(Exception):
    """No fresh bundle: 503."""


Binder = Callable[[Mapping[str, str]], ActorBinding]
"""Headers -> binding of the calling agent (workload + T2), from the bundle."""
ViewerAuth = Callable[[Mapping[str, str]], str]
"""Headers -> the calling agent's client id (workload token only), for card requests."""


def _headers(request: Request) -> dict[str, str] | None:
    """Lower-cased single-valued headers, or None on any repeat (header smuggling)."""
    out: dict[str, str] = {}
    for raw_name, raw_value in request.headers.raw:
        name = raw_name.decode("latin-1").lower()
        if name in out:
            return None
        out[name] = raw_value.decode("latin-1")
    return out


def _rpc_error(status: int, code: int, message: str, rid: Any = None) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}},
        status_code=status,
    )


def _message_text(body: Any) -> tuple[Any, str] | None:
    """JSON-RPC ``message/send`` with text parts only -> (id, text), or None if invalid."""
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
        return None
    if body.get("method") != "message/send":
        return None
    params = body.get("params")
    message = params.get("message") if isinstance(params, dict) else None
    parts = message.get("parts") if isinstance(message, dict) else None
    if not isinstance(parts, list) or not parts:
        return None
    texts: list[str] = []
    for part in parts:
        if not isinstance(part, dict) or part.get("kind") != "text":
            return None
        if not isinstance(part.get("text"), str):
            return None
        texts.append(part["text"])
    return body.get("id"), "\n".join(texts)


def create_app(broker: A2ABroker, binder: Binder, viewer: ViewerAuth) -> FastAPI:
    app = FastAPI(title="a2a-gateway", docs_url=None, redoc_url=None)

    @app.post("/agents/{target}/a2a")
    async def send(target: str, request: Request) -> Response:
        headers = _headers(request)
        if headers is None:
            return _rpc_error(400, -32600, "invalid request")
        try:  # authentication before the body is even read
            binding = await run_in_threadpool(binder, headers)
        except PolicyUnavailableError:
            return _rpc_error(503, -32002, "policy unavailable")
        except (ActorBindingError, ValueError):
            return _rpc_error(401, -32001, "unauthorized")
        try:
            parsed = _message_text(json.loads(await request.body()))
        except (ValueError, RecursionError):
            parsed = None
        if parsed is None:
            return _rpc_error(400, -32600, "invalid request")
        rid, text = parsed
        try:
            reply = await run_in_threadpool(broker.send, binding, target, text)
        except A2AError as e:
            status, code = _STATUS[e.failure]
            return _rpc_error(status, code, e.failure.value, rid)
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "kind": "message",
                    "role": "agent",
                    "messageId": str(uuid.uuid4()),
                    "parts": [{"kind": "text", "text": reply}],
                },
            }
        )

    @app.get("/agents/{target}/.well-known/agent-card.json")
    async def card(target: str, request: Request) -> Response:
        headers = _headers(request)
        if headers is None:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        try:
            who = await run_in_threadpool(viewer, headers)
            body = await run_in_threadpool(broker.card, who, target)
        except PolicyUnavailableError:
            return JSONResponse({"error": "policy_unavailable"}, status_code=503)
        except (ActorBindingError, ValueError):
            return JSONResponse(
                {"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"}
            )
        except A2AError as e:
            status, _ = _STATUS[e.failure]
            return JSONResponse({"error": e.failure.value}, status_code=status)
        return JSONResponse(body)

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_app(env: Mapping[str, str]) -> FastAPI:
    """``ATF_A2A_EGRESS_PROFILE_PATH`` (org IdP, this gateway's client, ``egress_inbound``),
    ``ATF_A2A_PUBLIC_URL``, ``ATF_A2A_TARGET_SCOPES``, ``ATF_CA_BUNDLE``, bundle settings
    (``trustkit_policy.runtime.policy_from_env``) and the local-only SSRF allowlist."""
    import pathlib
    import sys
    import time

    from atf_a2a_gateway.broker import BrokerConfig
    from trustkit.audit import JsonLinesSink
    from trustkit.binding import bind_actor
    from trustkit.breaker import BreakerRegistry
    from trustkit.exchange import IdJagExchanger
    from trustkit.jwt import JwksKeyResolver, KeyResolver, TokenValidator, ValidationPolicy
    from trustkit.profiles import EgressInbound
    from trustkit.scanning import LocalRulesScanner
    from trustkit_aws.s3_bundles import s3_source_factory
    from trustkit_aws.signers import make_signer_factory
    from trustkit_http.endpoint import HttpxTokenEndpoint
    from trustkit_http.ssrf import PinnedClient, parse_local_allowlist
    from trustkit_policy.runtime import actor_policies_from_bundle, policy_from_env

    egress = json.loads(pathlib.Path(env["ATF_A2A_EGRESS_PROFILE_PATH"]).read_text())
    public_url = env["ATF_A2A_PUBLIC_URL"].rstrip("/")
    target_scopes = frozenset(env["ATF_A2A_TARGET_SCOPES"].split())
    ca, region = env["ATF_CA_BUNDLE"], env.get("AWS_REGION", "us-east-1")
    allow = parse_local_allowlist(env)
    http = HttpxTokenEndpoint(ca_bundle_path=ca)
    resolvers: dict[str, KeyResolver] = {}

    def jwks(uri: str) -> KeyResolver:
        if uri not in resolvers:
            resolvers[uri] = JwksKeyResolver(fetch=lambda: http.get_json(uri))
        return resolvers[uri]

    ei = EgressInbound.model_validate_json(json.dumps(egress["egress_inbound"]))
    workload_v = TokenValidator(
        ValidationPolicy(issuer=ei.issuer, audiences=ei.audiences, expected_typ="at+jwt"),
        jwks(ei.jwks_uri),
    )
    audit = JsonLinesSink(sys.stdout)
    policy = policy_from_env(env, s3_factory=s3_source_factory(region), audit=audit)
    now = lambda: int(time.time())  # noqa: E731
    broker = A2ABroker(
        policy=policy,
        exchanger=IdJagExchanger(
            http=http, signers=make_signer_factory(env), jwks=jwks, breakers=BreakerRegistry()
        ),
        upstream=PinnedClient(ca_bundle_path=ca, allow=allow),
        scanner=LocalRulesScanner(),
        audit=audit,
        config=BrokerConfig(
            gateway_base_url=public_url, egress_base=egress, target_scopes=target_scopes
        ),
        now=now,
    )

    def binder(headers: Mapping[str, str]) -> ActorBinding:
        auth, subject = headers.get("authorization", ""), headers.get("x-subject-token")
        if not auth.startswith("Bearer ") or not subject:
            raise ValueError("missing credentials")
        loaded = policy()
        if loaded is None:
            raise PolicyUnavailableError
        agents = actor_policies_from_bundle(
            loaded,
            jwks,
            # Only agents that may delegate at all can call A2A.
            scopes_for=lambda g: target_scopes if g.delegation.may_delegate_to else frozenset(),
            now=now,
        )
        # max_prior_actors=0: the caller must be the first actor, so a chain stays <= 2.
        return bind_actor(
            auth.removeprefix("Bearer "), subject, workload_validator=workload_v, agents=agents
        )

    def viewer(headers: Mapping[str, str]) -> str:
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise ValueError("missing credentials")
        try:
            token = workload_v.validate(auth.removeprefix("Bearer "))
        except Exception:  # noqa: BLE001 - any invalid token is unauthenticated
            raise ValueError("invalid credentials") from None
        cid = token.claims.get("client_id")
        if not isinstance(cid, str) or token.claims.get("sub") != cid:
            raise ValueError("invalid credentials")
        return cid

    return create_app(broker, binder, viewer)


def app_from_env() -> FastAPI:
    import os

    return build_app(dict(os.environ))
