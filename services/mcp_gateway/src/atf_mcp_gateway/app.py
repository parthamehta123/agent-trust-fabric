"""HTTP shells: data plane (agents) and admin plane, as separate apps (ADR-0018 §2).

Data plane ``POST /mcp``:

* Rejects duplicate header names (smuggling) with 400.
* Requires ``Authorization: Bearer <workload>`` + ``X-Subject-Token: <T2>``, bound by ``binder``.
  A binding failure gives HTTP 401 with a JSON-RPC error body.
* The body must be a JSON object (``-32700`` otherwise). The proxy builds the response.

Admin plane (separate listener, internal network only):

* ``POST /admin/servers`` (enrol), ``POST /admin/servers/{id}/refresh|approve|disable``,
  ``GET /admin/servers``.
* Every route is gated by ``authorize_admin``. Admin failures map to 401/403/400/404/409.
* Responses never include secret values, only ARNs and digests.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from atf_mcp_gateway.admin import (
    AdminError,
    AdminFailure,
    AdminPrincipal,
    AdminService,
    authorize_admin,
)
from atf_mcp_gateway.proxy import Authorizer, McpProxy
from atf_mcp_gateway.servers import Delegation, ServerRecord
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
from trustkit.exchange import KeyResolverFactory
from trustkit.jwt import TokenValidationError, TokenValidator
from trustkit_aws.secrets import secret_bytes_fetcher
from trustkit_policy.bundle import LoadedBundle

_ADMIN_STATUS: Final = {
    AdminFailure.UNAUTHORIZED: 401,
    AdminFailure.FORBIDDEN: 403,
    AdminFailure.SAME_PERSON: 403,
    AdminFailure.INVALID: 400,
    AdminFailure.NOT_FOUND: 404,
    AdminFailure.CONFLICT: 409,
    AdminFailure.SNAPSHOT_REJECTED: 422,
}

Binder = Callable[[Mapping[str, str]], ActorBinding]
"""Headers -> ActorBinding. Raises ``trustkit.binding.ActorBindingError`` or ``ValueError``."""


def _single_valued_headers(request: Request) -> dict[str, str] | None:
    """Raw headers -> lower-cased dict, or None if any name repeats (header smuggling)."""
    out: dict[str, str] = {}
    for raw_name, raw_value in request.headers.raw:
        name = raw_name.decode("latin-1").lower()
        if name in out:
            return None
        out[name] = raw_value.decode("latin-1")
    return out


def _rpc_error(status: int, code: int, message: str) -> JSONResponse:
    body = {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}}
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    return JSONResponse(body, status_code=status, headers=headers)


class PolicyUnavailableError(Exception):
    """No fresh policy bundle: every call is refused with 503 (ADR-0022 §6)."""


def bundle_binder(
    policy: Callable[[], LoadedBundle | None],
    workload_validator: TokenValidator,
    jwks: KeyResolverFactory,
    now: Callable[[], int],
) -> Binder:
    """``bind_actor`` with agents from the bundle (any grant with tools and a T2 binding).
    No fresh bundle -> ``PolicyUnavailableError``."""
    from trustkit.binding import bind_actor
    from trustkit_policy.runtime import actor_policies_from_bundle

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
            # Union of all granted tool scopes; per-server narrowing happens in the authorizer.
            scopes_for=lambda g: frozenset().union(*g.tools.values()),
            now=now,
        )
        return bind_actor(
            auth.removeprefix("Bearer "),
            subject,
            workload_validator=workload_validator,
            agents=agents,
            max_prior_actors=1,  # ADR-0024: B may act for A (user -> A -> B), never deeper
        )

    return binder


def bundle_authorizer(
    policy: Callable[[], LoadedBundle | None], now: Callable[[], int]
) -> Authorizer:
    """Requested = grant.tools[server] ∩ record.scopes ∩ the user's T2 scopes; Cedar
    ``invoke_tool`` must allow exactly that. Anything else -> ``None`` (deny)."""
    from trustkit_policy.runtime import authorize_tool, user_scopes

    def authorize(binding: ActorBinding, record: ServerRecord) -> frozenset[str] | None:
        loaded = policy()  # re-read per call: a revocation since binding takes effect now
        if loaded is None:
            return None
        grant = loaded.grant(binding.agent_client_id, now())
        if grant is None:
            return None
        decision, requested = authorize_tool(
            loaded,
            agent_id=binding.agent_client_id,
            user=binding.subject,
            user_scopes=user_scopes(binding.subject_token),
            server_id=record.server_id,
            delegation=record.delegation.value,
            granted=grant.tools.get(record.server_id, frozenset()) & record.scopes,
            chain=binding.prior_actors,  # every actor and edge re-checked (no amplification)
        )
        return requested if decision.allowed else None

    return authorize


def create_data_app(proxy: McpProxy, binder: Binder, dpop: DpopGuard | None = None) -> FastAPI:
    app = FastAPI(title="mcp-gateway (data plane)", docs_url=None, redoc_url=None)

    if dpop is not None:  # RFC 9449 §7.1/§7.2: generic 401s advertise what is actually accepted

        @app.middleware("http")
        async def _dpop_challenge(request: Request, call_next: Any) -> Response:
            response: Response = await call_next(request)
            if response.status_code == 401 and response.headers.get("www-authenticate") == "Bearer":
                response.headers["WWW-Authenticate"] = auth_challenge(dpop)
            return response

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        headers = _single_valued_headers(request)
        if headers is None:
            return _rpc_error(400, -32600, "invalid request")
        if dpop is not None:  # ADR-0028: proof of possession before anything uses the token
            try:
                headers = await run_in_threadpool(dpop.check, headers, "POST", request.url.path)
            except DpopError as e:
                r = _rpc_error(guard_error_status(e), -32001, e.reason.value)
                r.headers.update(challenge_headers(e))
                return r
            except (TokenValidationError, ValueError):  # missing or invalid workload token
                return _rpc_error(401, -32001, "unauthorized")
        try:
            binding = await run_in_threadpool(binder, headers)
        except PolicyUnavailableError:
            return _rpc_error(503, -32002, "policy unavailable")
        except (ActorBindingError, ValueError):
            return _rpc_error(401, -32001, "unauthorized")
        try:
            payload = json.loads(await request.body())
        except (ValueError, RecursionError):
            return _rpc_error(400, -32700, "parse error")
        result = await run_in_threadpool(proxy.handle, binding, payload)
        return JSONResponse(result)

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app


@dataclass(frozen=True)
class _Enrolment:
    server_id: str
    url: str
    delegation: Delegation
    audience: str | None
    scopes: frozenset[str]
    secret_arn: str | None


def _optional_str(body: Mapping[str, Any], key: str) -> str | None:
    value = body.get(key)
    if value is not None and not isinstance(value, str):
        raise TypeError(key)
    return value


def _parse_enrolment(raw: bytes) -> _Enrolment:
    """Shape-check the enrolment body. Semantic validation is AdminService.enroll's job."""
    try:
        body = json.loads(raw)
    except RecursionError:
        raise ValueError("body") from None
    if not isinstance(body, dict):
        raise TypeError("body")
    server_id, url, scopes = body.get("server_id"), body.get("url"), body.get("scopes", [])
    delegation = body.get("delegation")
    if (
        not isinstance(server_id, str)
        or not isinstance(url, str)
        or not isinstance(delegation, str)
    ):
        raise TypeError("server_id/url/delegation")
    if not isinstance(scopes, list) or not all(isinstance(x, str) for x in scopes):
        raise TypeError("scopes")
    return _Enrolment(
        server_id=server_id,
        url=url,
        delegation=Delegation(delegation),
        audience=_optional_str(body, "audience"),
        scopes=frozenset(scopes),
        secret_arn=_optional_str(body, "secret_arn"),
    )


def _record_view(r: ServerRecord) -> dict[str, Any]:
    """What admins may see: references and digests, never secret values."""
    return {
        "server_id": r.server_id,
        "url": r.url,
        "delegation": r.delegation.value,
        "audience": r.audience,
        "scopes": sorted(r.scopes),
        "secret_arn": r.secret_arn,
        "status": r.status.value,
        "enrolled_by": r.enrolled_by,
        "approved_by": r.approved_by,
        "approved_digest": r.approved_digest,
        "current_digest": r.current.digest if r.current else None,
        "tools": sorted(r.current.names()) if r.current else [],
    }


def create_admin_app(admin: AdminService, admin_validator: TokenValidator) -> FastAPI:
    app = FastAPI(title="mcp-gateway (admin plane)", docs_url=None, redoc_url=None)

    def principal(request: Request) -> AdminPrincipal:
        return authorize_admin(request.headers.get("authorization"), admin_validator)

    async def run(
        request: Request, fn: Callable[[AdminPrincipal], Any], status: int = 200
    ) -> Response:
        try:
            who = principal(request)
            result = await run_in_threadpool(fn, who)
        except AdminError as e:
            return JSONResponse({"error": e.failure.value}, status_code=_ADMIN_STATUS[e.failure])
        body = (
            [_record_view(r) for r in result] if isinstance(result, list) else _record_view(result)
        )
        return JSONResponse(body, status_code=status)

    @app.post("/admin/servers")
    async def enroll(request: Request) -> Response:
        try:
            req = _parse_enrolment(await request.body())
        except (ValueError, TypeError):
            # Authentication still comes first: an unauthenticated caller learns nothing.
            try:
                principal(request)
            except AdminError as e:
                return JSONResponse(
                    {"error": e.failure.value}, status_code=_ADMIN_STATUS[e.failure]
                )
            return JSONResponse({"error": "invalid"}, status_code=400)
        return await run(
            request,
            lambda who: admin.enroll(
                who,
                server_id=req.server_id,
                url=req.url,
                delegation=req.delegation,
                audience=req.audience,
                scopes=req.scopes,
                secret_arn=req.secret_arn,
            ),
            status=201,
        )

    @app.post("/admin/servers/{server_id}/{action}")
    async def act(server_id: str, action: str, request: Request) -> Response:
        handlers = {"refresh": admin.refresh, "approve": admin.approve, "disable": admin.disable}
        handler = handlers.get(action)
        if handler is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        return await run(request, lambda who: handler(who, server_id))

    @app.get("/admin/servers")
    async def listing(request: Request) -> Response:
        return await run(request, lambda who: admin.list_servers(who))

    @app.get("/ping")
    def ping() -> dict[str, str]:
        """Unauthenticated liveness only; reveals nothing about servers or configuration."""
        return {"status": "ok"}

    return app


# ----------------------------------------------------------------------------- env factories


def _common(env: Mapping[str, str]) -> dict[str, Any]:
    """Shared wiring. Required variables are read up front: a missing one fails cold start."""

    import boto3

    from atf_mcp_gateway.store_dynamo import DynamoServerStore
    from trustkit.jwt import JwksKeyResolver, KeyResolver
    from trustkit_http.endpoint import HttpxTokenEndpoint
    from trustkit_http.ssrf import PinnedClient, parse_internal_hosts, parse_local_allowlist

    ca, table, region = (
        ca_bundle(env),
        env["ATF_DDB_TABLE"],
        env.get("AWS_REGION", "us-east-1"),
    )
    allow = parse_local_allowlist(env)  # raises outside ATF_ENV=local (ADR-0018 §1)
    internal = parse_internal_hosts(env)  # named internal hosts only (ADR-0026 §19)
    from atf_mcp_gateway.authorities import load_authorities

    authorities = load_authorities(load_document(env, "ATF_TOOL_AUTHORITIES"))
    http = HttpxTokenEndpoint(ca_bundle_path=ca)
    resolvers: dict[str, KeyResolver] = {}

    def jwks(uri: str) -> KeyResolver:
        if uri not in resolvers:
            resolvers[uri] = JwksKeyResolver(fetch=lambda: http.get_json(uri))
        return resolvers[uri]

    ddb = boto3.client("dynamodb", region_name=region)
    return {
        "env": env,
        "http": http,
        "jwks": jwks,
        "allow": allow,
        "internal": internal,
        "ddb": ddb,
        "table": table,
        "store": DynamoServerStore(ddb, table),
        "upstream": PinnedClient(ca_bundle_path=ca, allow=allow, internal_hosts=internal),
        "region": region,
        "authorities": authorities,
    }


def build_data_app(env: Mapping[str, str]) -> FastAPI:
    import sys
    import time

    import boto3

    from atf_mcp_gateway.credentials import GatewayCredentials
    from trustkit.audit import JsonLinesSink
    from trustkit.breaker import BreakerRegistry
    from trustkit.exchange import IdJagExchanger
    from trustkit.jwt import ValidationPolicy
    from trustkit.profiles import EgressInbound
    from trustkit.scanning import LocalRulesScanner
    from trustkit_aws.s3_bundles import s3_source_factory
    from trustkit_aws.signers import make_signer_factory
    from trustkit_policy.runtime import policy_from_env

    c = _common(env)
    egress_doc = json.loads(load_document(env, "ATF_EGRESS_PROFILE"))
    ei = EgressInbound.model_validate_json(json.dumps(egress_doc["egress_inbound"]))
    workload_v = TokenValidator(
        ValidationPolicy(issuer=ei.issuer, audiences=ei.audiences, expected_typ="at+jwt"),
        c["jwks"](ei.jwks_uri),
    )
    exchanger = IdJagExchanger(
        http=c["http"], signers=make_signer_factory(env), jwks=c["jwks"], breakers=BreakerRegistry()
    )
    credentials = GatewayCredentials(
        exchanger=exchanger,
        secrets=boto3.client("secretsmanager", region_name=c["region"]),
        egress_base=egress_doc,
        authorities=c["authorities"],
    )
    policy = policy_from_env(
        env,
        s3_factory=s3_source_factory(c["region"]),
        audit=JsonLinesSink(sys.stdout),
    )
    now = lambda: int(time.time())  # noqa: E731
    proxy = McpProxy(
        store=c["store"],
        upstream=c["upstream"],
        credentials=credentials,
        scanner=LocalRulesScanner(),
        authorize=bundle_authorizer(policy, now),
    )

    def on_unbound(client_id: str) -> None:  # ADR-0028 rollout: who still sends bearer tokens
        JsonLinesSink(sys.stdout).emit(
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
        fetch_secret=secret_bytes_fetcher(c["region"]),
        on_unbound=on_unbound,
    )
    return create_data_app(proxy, bundle_binder(policy, workload_v, c["jwks"], now), dpop)


def build_admin_app(env: Mapping[str, str]) -> FastAPI:
    from trustkit.jwt import TokenValidator, ValidationPolicy
    from trustkit.scanning import LocalRulesScanner

    c = _common(env)
    if env.get("ATF_ENV") == "local":
        _ensure_local_table(c["ddb"], c["table"])
    validator = TokenValidator(
        ValidationPolicy(
            issuer=env["ATF_ADMIN_ISSUER"],
            audiences=frozenset({env["ATF_ADMIN_AUDIENCE"]}),
            expected_typ="at+jwt",
        ),
        c["jwks"](env["ATF_ADMIN_JWKS_URI"]),
    )
    upstream = c["upstream"]

    def fetch_tools(record: ServerRecord) -> Mapping[str, Any]:
        status, body = upstream.post_json(
            record.url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={}
        )
        result = body.get("result") if status == 200 and body is not None else None
        if not isinstance(result, Mapping):
            raise TypeError("discovery failed")
        return result

    admin = AdminService(
        store=c["store"],
        fetch_tools=fetch_tools,
        scanner=LocalRulesScanner(),
        audiences=frozenset(c["authorities"]),
        allow=c["allow"],
        internal_hosts=c["internal"],
    )
    return create_admin_app(admin, validator)


def _ensure_local_table(ddb: Any, table: str) -> None:
    """Local stack only (DynamoDB Local): create the table if missing. Phase 6 Terraform owns it."""
    try:
        ddb.describe_table(TableName=table)
    except ddb.exceptions.ResourceNotFoundException:
        ddb.create_table(
            TableName=table,
            KeySchema=[{"AttributeName": "server_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "server_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.get_waiter("table_exists").wait(TableName=table)


def data_app_from_env() -> FastAPI:
    import os

    return build_data_app(dict(os.environ))


def admin_app_from_env() -> FastAPI:
    import os

    return build_admin_app(dict(os.environ))
