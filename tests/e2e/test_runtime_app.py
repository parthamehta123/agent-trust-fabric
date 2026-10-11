"""Runtime HTTP shell."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from atf_agent_runtime.app import build_runtime_from_env, create_app
from atf_agent_runtime.runtime import AgentRuntime
from fastapi.testclient import TestClient
from joserfc.jwk import RSAKey

from tests.conftest import NOW, Mint, StaticKeys, good_claims
from trustkit.resource import Principal, ResourceAuthorizer

ISS, AUD = "https://idp.example.test/oauth2/agent-alpha", "api://agent-alpha"


def echo(p: Principal, req: Mapping[str, Any]) -> Mapping[str, Any]:
    return {"output": "ok"}


@pytest.fixture
def client(rsa_key: RSAKey) -> TestClient:
    authz = ResourceAuthorizer(issuer=ISS, audience=AUD, keys=StaticKeys(rsa_key), now=lambda: NOW)
    return TestClient(create_app(AgentRuntime(authorizer=authz, agent=echo)))


class TestRuntimeApp:
    def test_invocation(self, client: TestClient, mint: Mint) -> None:
        claims = good_claims(iss=ISS, aud=AUD, client_id="c", scope="agent.invoke")
        tok = mint(claims, header={"typ": "at+jwt"})
        r = client.post("/invocations", content=b"{}", headers={"authorization": f"Bearer {tok}"})
        assert (r.status_code, r.json()) == (200, {"output": "ok"})

    def test_challenge_header_propagated(self, client: TestClient) -> None:
        r = client.post("/invocations", content=b"{}")
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == "Bearer"

    def test_ping(self, client: TestClient) -> None:
        assert client.get("/ping").status_code == 200

    @pytest.mark.parametrize(
        "missing",
        ["ATF_RESOURCE_ISSUER", "ATF_RESOURCE_AUDIENCE", "ATF_RESOURCE_JWKS_URI", "ATF_CA_BUNDLE"],
    )
    def test_env_is_required(self, tmp_path: Any, missing: str) -> None:
        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        env = {
            "ATF_RESOURCE_ISSUER": ISS,
            "ATF_RESOURCE_AUDIENCE": AUD,
            "ATF_RESOURCE_JWKS_URI": f"{ISS}/v1/keys",
            "ATF_CA_BUNDLE": str(ca),
        }
        del env[missing]
        with pytest.raises(KeyError, match=missing):
            build_runtime_from_env(env)


@pytest.mark.security
def test_runtime_rejects_duplicate_header_names(client: TestClient) -> None:
    r = client.post(
        "/invocations",
        content=b"{}",
        headers=[("Authorization", "Bearer a"), ("AUTHORIZATION", "Bearer b")],
    )
    assert r.status_code == 400
