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
from atf_mcp_gateway.proxy import McpProxy
from atf_mcp_gateway.servers import Delegation, ServerRecord
from trustkit.binding import ActorBinding, ActorBindingError
from trustkit.jwt import TokenValidator

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


def create_data_app(proxy: McpProxy, binder: Binder) -> FastAPI:
    app = FastAPI(title="mcp-gateway (data plane)", docs_url=None, redoc_url=None)

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        headers = _single_valued_headers(request)
        if headers is None:
            return _rpc_error(400, -32600, "invalid request")
        try:
            binding = await run_in_threadpool(binder, headers)
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

    return app
