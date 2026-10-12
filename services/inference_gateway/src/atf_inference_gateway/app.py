"""HTTP shell: ``POST /v1/chat/completions`` (OpenAI-compatible subset) and ``GET /ping``.

Auth: ``Authorization: Bearer <workload token>`` validated by ``workload_validator``; the agent is
the token's ``client_id`` (== ``sub``). Duplicate header names are rejected. Errors are
``{"error": {"type": <code>}}`` with the ``ChatError`` status; nothing provider-specific leaks.
"""

from __future__ import annotations

import json

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from atf_inference_gateway.service import ChatError, InferenceService
from trustkit.jwt import TokenValidationError, TokenValidator


def _err(status: int, code: str) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    return JSONResponse({"error": {"type": code}}, status_code=status, headers=headers)


def create_app(service: InferenceService, workload_validator: TokenValidator) -> FastAPI:
    app = FastAPI(title="inference-gateway", docs_url=None, redoc_url=None)

    @app.post("/v1/chat/completions")
    async def completions(request: Request) -> Response:
        names = [n.decode("latin-1").lower() for n, _ in request.headers.raw]
        if len(names) != len(set(names)):
            return _err(400, "invalid_request")  # header smuggling
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return _err(401, "unauthorized")
        try:
            token = workload_validator.validate(auth.removeprefix("Bearer "))
        except TokenValidationError:
            return _err(401, "unauthorized")
        agent = token.claims.get("client_id")
        if not isinstance(agent, str) or token.claims.get("sub") != agent:
            return _err(401, "unauthorized")  # a workload token names the agent as sub == client_id
        try:
            body = json.loads(await request.body())
        except (ValueError, RecursionError):
            return _err(400, "invalid_request")
        try:
            result = await run_in_threadpool(service.chat, agent, body)
        except ChatError as e:
            return _err(e.status, e.code)
        return JSONResponse(result)

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app
