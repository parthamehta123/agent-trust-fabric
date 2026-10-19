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
from trustkit.audit import AuditEvent, Decision
from trustkit.binding import ActorBinding, ActorBindingError
from trustkit.config import ca_bundle, load_document
from trustkit.dpop import (
    DpopError,
    DpopGuard,
    auth_challenge,
    challenge_headers,
    dpop_guard_from_env,
    guard_error_status,
)
from trustkit.jwt import TokenValidationError
from trustkit_aws.secrets import secret_bytes_fetcher

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


def create_app(
    broker: A2ABroker, binder: Binder, viewer: ViewerAuth, dpop: DpopGuard | None = None
) -> FastAPI:
    app = FastAPI(title="a2a-gateway", docs_url=None, redoc_url=None)

    if dpop is not None:  # RFC 9449 §7.1/§7.2: generic 401s advertise what is actually accepted

        @app.middleware("http")
        async def _dpop_challenge(request: Request, call_next: Any) -> Response:
            response: Response = await call_next(request)
            if response.status_code == 401 and response.headers.get("www-authenticate") == "Bearer":
                response.headers["WWW-Authenticate"] = auth_challenge(dpop)
            return response

    @app.post("/agents/{target}/a2a")
    async def send(target: str, request: Request) -> Response:
        headers = _headers(request)
        if headers is None:
            return _rpc_error(400, -32600, "invalid request")
        if dpop is not None:  # ADR-0028
            try:
                headers = await run_in_threadpool(dpop.check, headers, "POST", request.url.path)
            except DpopError as e:
                r = _rpc_error(guard_error_status(e), -32001, e.reason.value)
                r.headers.update(challenge_headers(e))
                return r
            except (TokenValidationError, ValueError):  # missing or invalid workload token
                return _rpc_error(401, -32001, "unauthorized")
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
        if dpop is not None:  # ADR-0028
            try:
                headers = await run_in_threadpool(dpop.check, headers, "GET", request.url.path)
            except DpopError as e:
                return JSONResponse(
                    {"error": e.reason.value},
                    status_code=guard_error_status(e),
                    headers=challenge_headers(e),
                )
            except (TokenValidationError, ValueError):  # missing or invalid workload token
                return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    import sys
    import time

    from atf_a2a_gateway.broker import BrokerConfig
    from trustkit.audit import JsonLinesSink
    from trustkit.binding import bind_actor
    from trustkit.breaker import BreakerRegistry
    from trustkit.exchange import IdJagExchanger
    from trustkit.jwt import (
        JwksKeyResolver,
        KeyResolver,
        TokenValidator,
        ValidationPolicy,
        access_token_profile_from_env,
    )
    from trustkit.profiles import EgressInbound
    from trustkit.scanning import LocalRulesScanner
    from trustkit_aws.s3_bundles import s3_source_factory
    from trustkit_aws.signers import make_signer_factory
    from trustkit_http.endpoint import HttpxTokenEndpoint
    from trustkit_http.ssrf import PinnedClient, parse_internal_hosts, parse_local_allowlist
    from trustkit_policy.idps import TrustedIdps
    from trustkit_policy.runtime import actor_policies_from_bundle, policy_from_env

    egress = json.loads(load_document(env, "ATF_A2A_EGRESS_PROFILE"))
    public_url = env["ATF_A2A_PUBLIC_URL"].rstrip("/")
    target_scopes = frozenset(env["ATF_A2A_TARGET_SCOPES"].split())
    ca, region = ca_bundle(env), env.get("AWS_REGION", "us-east-1")
    allow = parse_local_allowlist(env)
    internal = parse_internal_hosts(env)  # agent runtimes by exact name (ADR-0026 §19)
    http = HttpxTokenEndpoint(ca_bundle_path=ca)
    resolvers: dict[str, KeyResolver] = {}

    def jwks(uri: str) -> KeyResolver:
        if uri not in resolvers:
            resolvers[uri] = JwksKeyResolver(fetch=lambda: http.get_json(uri))
        return resolvers[uri]

    trusted_idps = TrustedIdps.from_env(env)  # ADR-0027 review #1: T2 issuers must be on these
    atp = access_token_profile_from_env(env)  # A-15: the IdP's access-token shape
    ei = EgressInbound.model_validate_json(json.dumps(egress["egress_inbound"]))
    workload_v = TokenValidator(
        ValidationPolicy(
            issuer=ei.issuer,
            audiences=ei.audiences,
            expected_typ="at+jwt",
            access_token_profile=atp,
        ),
        jwks(ei.jwks_uri),
    )
    audit = JsonLinesSink(sys.stdout)
    policy = policy_from_env(env, s3_factory=s3_source_factory(region), audit=audit)
    now = lambda: int(time.time())  # noqa: E731
    broker = A2ABroker(
        policy=policy,
        exchanger=IdJagExchanger(
            http=http,
            signers=make_signer_factory(env),
            jwks=jwks,
            breakers=BreakerRegistry(),
            access_token_profile=atp,
        ),
        upstream=PinnedClient(ca_bundle_path=ca, allow=allow, internal_hosts=internal),
        scanner=LocalRulesScanner(),
        audit=audit,
        config=BrokerConfig(
            gateway_base_url=public_url,
            egress_base=egress,
            target_scopes=target_scopes,
            trusted_idps=trusted_idps,
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
            trusted_idps=trusted_idps,
            access_token_profile=atp,
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

    def on_unbound(client_id: str) -> None:  # ADR-0028 rollout: who still sends bearer tokens
        audit.emit(
            AuditEvent(
                event_type="dpop.unbound_workload_token",
                request_id="dpop",
                decision=Decision.ALLOW,
                reason="unbound_token_while_optional",
                client_id=client_id,
            )
        )

    dpop = dpop_guard_from_env(
        env,
        validate=workload_v.validate,
        fetch_secret=secret_bytes_fetcher(region),
        on_unbound=on_unbound,
    )
    return create_app(broker, binder, viewer, dpop)


def app_from_env() -> FastAPI:
    import os

    return build_app(dict(os.environ))
