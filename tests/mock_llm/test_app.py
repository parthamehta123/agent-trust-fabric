"""Mock LLM server (test infrastructure) behaves as the e2e suite assumes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mock_llm.app import SECRET_SHAPED, create_app

ENV = {"ATF_ENV": "local", "ATF_MOCK_LLM_KEY": "localdummy"}
AUTH = {"Authorization": "Bearer localdummy"}


def body(text: str = "hi") -> dict[str, object]:
    return {"model": "mock-sonnet", "messages": [{"role": "user", "content": text}]}


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(env=ENV))


def test_refuses_outside_local() -> None:
    with pytest.raises(RuntimeError):
        create_app(env={**ENV, "ATF_ENV": "prod"})


def test_reply_and_usage(client: TestClient) -> None:
    r = client.post("/v1/chat/completions", json=body("hello"), headers=AUTH)
    assert r.status_code == 200
    j = r.json()
    assert j["choices"][0]["message"]["content"] == "mock reply to: hello"
    assert (
        j["usage"]["total_tokens"] == j["usage"]["prompt_tokens"] + j["usage"]["completion_tokens"]
    )
    assert client.get("/_test/calls").json() == {"calls": 1}


def test_secret_trigger(client: TestClient) -> None:
    r = client.post("/v1/chat/completions", json=body("EMIT_SECRET"), headers=AUTH)
    assert SECRET_SHAPED in r.json()["choices"][0]["message"]["content"]


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}])
def test_requires_provider_key(client: TestClient, headers: dict[str, str]) -> None:
    r = client.post("/v1/chat/completions", json=body(), headers=headers)
    assert r.status_code == 401
    assert client.get("/_test/calls").json() == {"calls": 0}


@pytest.mark.parametrize("bad", [b"nope", b"{}", b'{"model": "m", "messages": []}'])
def test_bad_request(client: TestClient, bad: bytes) -> None:
    r = client.post("/v1/chat/completions", content=bad, headers=AUTH)
    assert r.status_code == 400


def test_ping(client: TestClient) -> None:
    assert client.get("/ping").json() == {"status": "ok"}
