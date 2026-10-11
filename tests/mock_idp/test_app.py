"""Mock IdP HTTP shell (ADR-0015 §7)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mock_idp.app import create_app
from mock_idp.core import AuthorizationServer, MockIdp

BASE = "https://testserver"


@pytest.fixture
def idp() -> MockIdp:
    idp = MockIdp(BASE)
    idp.add_authorization_server(
        AuthorizationServer("ingress", "api://agent-ingress", frozenset({"c"}))
    )
    return idp


@pytest.fixture
def client(idp: MockIdp) -> TestClient:
    return TestClient(create_app(idp, env={"ATF_ENV": "local"}), base_url=BASE)


class TestApp:
    @pytest.mark.parametrize("env", [{}, {"ATF_ENV": "prod"}, {"ATF_ENV": "LOCAL"}])
    def test_refuses_to_start_outside_local(self, idp: MockIdp, env: dict[str, str]) -> None:
        with pytest.raises(RuntimeError, match="local"):
            create_app(idp, env=env)

    def test_jwks_endpoints(self, client: TestClient, idp: MockIdp) -> None:
        assert client.get("/oauth2/v1/keys").json() == idp.jwks()
        assert client.get("/oauth2/ingress/v1/keys").json() == idp.jwks("ingress")
        assert client.get("/oauth2/nope/v1/keys").status_code == 404

    def test_token_endpoint_forwards_to_core(self, client: TestClient) -> None:
        r = client.post("/oauth2/v1/token", data={"grant_type": "x"})
        assert r.status_code == 401
        assert r.json()["error"] == "invalid_client"

    @pytest.mark.security
    def test_repeated_parameters_rejected(self, client: TestClient) -> None:
        """RFC 6749 §3.2: parameters MUST NOT be included more than once (parser-differential)."""
        r = client.post(
            "/oauth2/v1/token",
            content=b"grant_type=a&grant_type=b",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_request"

    @pytest.mark.security
    def test_non_form_content_type_rejected(self, client: TestClient) -> None:
        r = client.post("/oauth2/v1/token", json={"grant_type": "x"})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_request"

    def test_test_login(self, client: TestClient) -> None:
        r = client.post(
            "/_test/login", json={"user": "u", "client_id": "c", "ingress_as_id": "ingress"}
        )
        assert r.status_code == 200
        assert set(r.json()) == {"access_token", "id_token"}
