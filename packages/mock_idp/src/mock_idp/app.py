"""HTTP shell for the mock IdP (ADR-0015 §7). TEST INFRASTRUCTURE ONLY.

* ``POST <token endpoint>``: ``application/x-www-form-urlencoded`` only. The raw body is
  checked for **repeated parameters** before parsing (RFC 6749 §3.2), giving ``invalid_request``.
* ``GET  /oauth2/v1/keys`` and ``/oauth2/{as_id}/v1/keys``: public JWKS.
* ``POST /_test/login``: ``{"user", "client_id", "ingress_as_id"}`` returns
  ``{"access_token", "id_token"}``. Exists for e2e only.
* ``create_app`` raises unless ``ATF_ENV=local``.
"""

from __future__ import annotations

import json
import os
import pathlib
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mock_idp.core import AuthorizationServer, ClientRegistration, MockIdp

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}  # RFC 6749 §5.1


def build_idp_from_topology(topology: Mapping[str, Any], *, base_url: str) -> MockIdp:
    """Topology JSON (from devstack.bootstrap) -> configured MockIdp."""
    idp = MockIdp(base_url)
    for srv in topology["authorization_servers"]:
        idp.add_authorization_server(
            AuthorizationServer(srv["as_id"], srv["resource_audience"], frozenset(srv["clients"]))
        )
    for c in topology["clients"]:
        policy = {aud: frozenset(scopes) for aud, scopes in c.get("exchange_policy", {}).items()}
        idp.register_client(ClientRegistration(c["client_id"], c["jwks"], policy))
    return idp


def _oauth_error(status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": "invalid_request", "error_description": "malformed token request"},
        status_code=status,
        headers=_NO_STORE,
    )


def create_app(idp: MockIdp, *, env: Mapping[str, str]) -> FastAPI:
    if env.get("ATF_ENV") != "local":
        raise RuntimeError("the mock IdP runs only with ATF_ENV=local")
    app = FastAPI(title="mock-idp (test infrastructure)", docs_url=None, redoc_url=None)

    async def token(request: Request, as_id: str | None) -> JSONResponse:
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            return _oauth_error()
        try:
            pairs = parse_qsl(
                (await request.body()).decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=True,
            )
        except (UnicodeDecodeError, ValueError):
            return _oauth_error()
        names = [k for k, _ in pairs]
        if len(names) != len(set(names)):  # RFC 6749 §3.2: no repeated parameters
            return _oauth_error()
        # The endpoint identity comes from configuration, never from the request's Host header.
        result = idp.token(idp.token_endpoint(as_id), dict(pairs))
        return JSONResponse(dict(result.body), status_code=result.status, headers=_NO_STORE)

    @app.post("/oauth2/v1/token")
    async def org_token(request: Request) -> JSONResponse:
        return await token(request, None)

    @app.post("/oauth2/{as_id}/v1/token")
    async def custom_token(as_id: str, request: Request) -> JSONResponse:
        return await token(request, as_id)

    @app.get("/oauth2/v1/keys")
    def org_keys() -> JSONResponse:
        return JSONResponse(idp.jwks())

    @app.get("/oauth2/{as_id}/v1/keys")
    def custom_keys(as_id: str) -> JSONResponse:
        try:
            return JSONResponse(idp.jwks(as_id))
        except KeyError:
            return JSONResponse({"error": "not_found"}, status_code=404)

    @app.post("/_test/login")
    async def test_login(request: Request) -> JSONResponse:
        try:
            body = await request.json()
            at, idt = idp.login(
                str(body["user"]), str(body["client_id"]), ingress_as_id=str(body["ingress_as_id"])
            )
        except (KeyError, TypeError, ValueError):
            return JSONResponse({"error": "bad_request"}, status_code=400)
        return JSONResponse({"access_token": at, "id_token": idt}, headers=_NO_STORE)

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app


def app_from_env() -> FastAPI:
    """uvicorn --factory entrypoint: ATF_ENV, ATF_IDP_BASE_URL, ATF_TOPOLOGY_PATH."""
    env = dict(os.environ)
    topology = json.loads(pathlib.Path(env["ATF_TOPOLOGY_PATH"]).read_text())
    return create_app(build_idp_from_topology(topology, base_url=env["ATF_IDP_BASE_URL"]), env=env)
