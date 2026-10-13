"""Registry admin API (ADR-0021 §7). Authentication is checked before anything else."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from typing import Any, Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from atf_agent_registry.records import AgentSpec, AgentVersion, ApprovalRole, canonical_spec_json
from atf_agent_registry.workflow import (
    Failure,
    Principal,
    RegistryError,
    RegistryService,
    authorize,
)
from trustkit.config import ca_bundle
from trustkit.jwt import TokenValidator

_STATUS: Final = {
    Failure.UNAUTHORIZED: 401,
    Failure.FORBIDDEN: 403,
    Failure.INVALID: 400,
    Failure.NOT_FOUND: 404,
    Failure.CONFLICT: 409,
    Failure.SAME_PERSON: 403,
    Failure.UNAVAILABLE: 503,
}
_VERSION: Final = re.compile(r"^[1-9][0-9]{0,8}$")


def _err(failure: Failure) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if failure is Failure.UNAUTHORIZED else None
    return JSONResponse({"error": failure.value}, status_code=_STATUS[failure], headers=headers)


def view(v: AgentVersion) -> dict[str, Any]:
    def ts(t: Any) -> str | None:
        return None if t is None else t.isoformat()

    return {
        "agent_id": v.agent_id,
        "version": v.version,
        "state": v.state.value,
        "author": v.author,
        "spec": json.loads(canonical_spec_json(v.spec)),
        "approvals": [
            {"subject": a.subject, "role": a.role.value, "at": a.at.isoformat()}
            for a in v.approvals
        ],
        "created_at": ts(v.created_at),
        "updated_at": ts(v.updated_at),
        "approved_at": ts(v.approved_at),
        "expires_at": ts(v.expires_at),
        "decided_by": v.decided_by,
    }


def _spec(body: bytes) -> AgentSpec:
    return AgentSpec.model_validate_json(body)


def _role(body: bytes) -> ApprovalRole:
    doc = json.loads(body)
    if not isinstance(doc, dict) or set(doc) != {"role"} or not isinstance(doc["role"], str):
        raise ValueError("bad approve body")
    return ApprovalRole(doc["role"])


def create_app(service: RegistryService, validator: TokenValidator) -> FastAPI:
    app = FastAPI(title="agent-registry (admin)", docs_url=None, redoc_url=None)

    async def run(
        request: Request,
        action: Callable[[Principal, bytes], Any],
        *,
        status: int = 200,
        version: str | None = None,
    ) -> Response:
        names = [n.decode("latin-1").lower() for n, _ in request.headers.raw]
        if len(names) != len(set(names)):
            return _err(Failure.INVALID)  # header smuggling
        try:
            who = authorize(request.headers.get("authorization"), validator)
        except RegistryError as e:
            return _err(e.failure)
        if version is not None and not _VERSION.fullmatch(version):
            return _err(Failure.NOT_FOUND)
        body = await request.body()
        try:
            result = await run_in_threadpool(action, who, body)
        except RegistryError as e:
            return _err(e.failure)
        except (ValueError, ValidationError, RecursionError):
            return _err(Failure.INVALID)  # only reachable after authentication
        content = [view(v) for v in result] if isinstance(result, list) else view(result)
        return JSONResponse(content, status_code=status)

    base = "/registry/agents/{agent_id}"

    @app.post(f"{base}/versions")
    async def create(agent_id: str, request: Request) -> Response:
        return await run(
            request, lambda who, b: service.create_draft(who, agent_id, _spec(b)), status=201
        )

    @app.put(f"{base}/versions/{{version}}")
    async def update(agent_id: str, version: str, request: Request) -> Response:
        return await run(
            request,
            lambda who, b: service.update_draft(who, agent_id, int(version), _spec(b)),
            version=version,
        )

    @app.post(f"{base}/versions/{{version}}/{{action}}")
    async def act(agent_id: str, version: str, action: str, request: Request) -> Response:
        actions: dict[str, Callable[[Principal, bytes], Any]] = {
            "submit": lambda who, _: service.submit(who, agent_id, int(version)),
            "approve": lambda who, b: service.approve(who, agent_id, int(version), _role(b)),
            "reject": lambda who, _: service.reject(who, agent_id, int(version)),
        }
        handler = actions.get(action)
        if handler is None:
            return _err(Failure.NOT_FOUND)
        return await run(request, handler, version=version)

    @app.post(f"{base}/revoke")
    async def revoke(agent_id: str, request: Request) -> Response:
        return await run(request, lambda who, _: service.revoke(who, agent_id))

    @app.get(f"{base}/versions")
    async def history(agent_id: str, request: Request) -> Response:
        return await run(request, lambda who, _: list(service.history(who, agent_id)))

    @app.get(f"{base}/versions/{{version}}")
    async def get(agent_id: str, version: str, request: Request) -> Response:
        return await run(
            request, lambda who, _: service.get(who, agent_id, int(version)), version=version
        )

    @app.get("/ping")
    def ping() -> dict[str, str]:
        """Unauthenticated liveness only."""
        return {"status": "ok"}

    return app


def build_app(env: Mapping[str, str]) -> FastAPI:
    """``ATF_REGISTRY_ISSUER``/``_AUDIENCE``/``_JWKS_URI``, ``ATF_REGISTRY_TABLE``,
    ``ATF_CA_BUNDLE``, ``AWS_REGION``; table created only with ``ATF_ENV=local``."""
    import sys

    import boto3

    from atf_agent_registry.store_dynamo import DynamoRegistryStore, ensure_local_table
    from trustkit.audit import JsonLinesSink
    from trustkit.jwt import JwksKeyResolver, ValidationPolicy
    from trustkit_http.endpoint import HttpxTokenEndpoint

    issuer, audience = env["ATF_REGISTRY_ISSUER"], env["ATF_REGISTRY_AUDIENCE"]
    jwks_uri, table = env["ATF_REGISTRY_JWKS_URI"], env["ATF_REGISTRY_TABLE"]
    ca, region = ca_bundle(env), env.get("AWS_REGION", "us-east-1")

    http = HttpxTokenEndpoint(ca_bundle_path=ca)
    validator = TokenValidator(
        ValidationPolicy(issuer=issuer, audiences=frozenset({audience}), expected_typ="at+jwt"),
        JwksKeyResolver(fetch=lambda: http.get_json(jwks_uri)),
    )
    ddb = boto3.client("dynamodb", region_name=region)
    if env.get("ATF_ENV") == "local":
        ensure_local_table(ddb, table)
    service = RegistryService(DynamoRegistryStore(ddb, table), JsonLinesSink(sys.stdout))
    return create_app(service, validator)


def app_from_env() -> FastAPI:
    import os

    return build_app(dict(os.environ))
