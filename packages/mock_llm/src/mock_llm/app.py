"""Mock OpenAI-compatible model server (TEST INFRASTRUCTURE ONLY; ``ATF_ENV=local`` required).

* ``POST /v1/chat/completions``: requires a bearer key equal to ``ATF_MOCK_LLM_KEY`` (proves the
  gateway sends the provider credential and agents' tokens never reach the provider). Replies
  ``mock reply to: <last user message>``. A last message containing ``EMIT_SECRET`` makes the
  reply carry an AWS-access-key-shaped string, to exercise completion scanning (TM-INF-03).
* ``GET /_test/calls``: number of completions served, so e2e can prove a blocked prompt never
  reached the model.

Only reachable on the internal ``llm`` network.
"""

from __future__ import annotations

import hmac
import os
import time
import uuid
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# AWS documentation example key, not a credential.
SECRET_SHAPED = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105


def create_app(*, env: Mapping[str, str]) -> FastAPI:
    if env.get("ATF_ENV") != "local":
        raise RuntimeError("the mock LLM server runs only with ATF_ENV=local")
    key = env["ATF_MOCK_LLM_KEY"]
    state = {"calls": 0}
    app = FastAPI(title="mock-llm (test infrastructure)", docs_url=None, redoc_url=None)

    @app.post("/v1/chat/completions")
    async def completions(request: Request) -> JSONResponse:
        auth = request.headers.get("authorization", "")
        if not hmac.compare_digest(auth.encode(), f"Bearer {key}".encode()):
            return JSONResponse({"error": {"type": "invalid_api_key"}}, status_code=401)
        try:
            body: Any = await request.json()
            messages = body["messages"]
            last = str(messages[-1]["content"])
            model = str(body["model"])
        except (ValueError, KeyError, IndexError, TypeError):
            return JSONResponse({"error": {"type": "invalid_request"}}, status_code=400)
        state["calls"] += 1
        text = f"mock reply to: {last[:200]}"
        if "EMIT_SECRET" in last:
            text = f"here you go: {SECRET_SHAPED}"
        prompt_tokens = sum(len(str(m.get("content", ""))) for m in messages) // 4 + 1
        completion_tokens = len(text) // 4 + 1
        return JSONResponse(
            {
                "id": f"chatcmpl-{uuid.uuid4().hex}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
            }
        )

    @app.get("/_test/calls")
    def calls() -> dict[str, int]:
        return {"calls": state["calls"]}

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app


def app_from_env() -> FastAPI:
    return create_app(env=dict(os.environ))
