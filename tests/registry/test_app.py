"""Registry admin API over HTTP (ADR-0021 §7)."""

from __future__ import annotations

import json
import pathlib
from typing import Any

import boto3
import pytest
from atf_agent_registry.app import build_app, create_app
from fastapi.testclient import TestClient
from joserfc.jwk import RSAKey
from moto import mock_aws

from tests.conftest import AUDIENCE, ISSUER, NOW, Mint, StaticKeys, good_claims
from tests.registry.test_workflow import AGENT, Env
from trustkit.jwt import TokenValidator, ValidationPolicy

BASE = f"/registry/agents/{AGENT}/versions"
GROUPS = {
    "dave": ["team-alpha"],
    "bob": ["atf-registry-approvers"],
    "carol": ["atf-security-approvers"],
    "eve": ["team-beta"],
}


def spec_doc(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "display_name": "Alpha",
        "owner_team": "alpha",
        "tier": "standard",
        "tools": {"tickets": ["tickets.read"]},
    }
    doc.update(over)
    return doc


@pytest.fixture
def client(rsa_key: RSAKey) -> TestClient:
    v = TokenValidator(
        ValidationPolicy(issuer=ISSUER, audiences=frozenset({AUDIENCE}), expected_typ="at+jwt"),
        StaticKeys(rsa_key),
        now=lambda: NOW,
    )
    return TestClient(create_app(Env().svc, v))


def as_(mint: Mint, who: str, **over: Any) -> dict[str, str]:
    claims = good_claims(sub=who, scope="registry.admin", groups=GROUPS.get(who, []))
    claims.update(over)
    tok = mint({k: v for k, v in claims.items() if v is not None}, header={"typ": "at+jwt"})
    return {"Authorization": f"Bearer {tok}"}


class TestFlow:
    def test_create_submit_approve(self, client: TestClient, mint: Mint) -> None:
        r = client.post(BASE, json=spec_doc(), headers=as_(mint, "dave"))
        assert r.status_code == 201, r.text
        body = r.json()
        assert (body["agent_id"], body["version"], body["state"]) == (AGENT, 1, "draft")
        assert body["spec"]["tools"] == {"tickets": ["tickets.read"]}

        r = client.put(f"{BASE}/1", json=spec_doc(display_name="B"), headers=as_(mint, "dave"))
        assert r.json()["spec"]["display_name"] == "B"
        r = client.post(f"{BASE}/1/submit", headers=as_(mint, "dave"))
        assert r.json()["state"] == "in_review"
        r = client.post(f"{BASE}/1/approve", json={"role": "approver"}, headers=as_(mint, "bob"))
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["state"] == "approved"
        assert j["approvals"] == [{"subject": "bob", "role": "approver", "at": j["approved_at"]}]

        r = client.get(BASE, headers=as_(mint, "carol"))
        assert [v["version"] for v in r.json()] == [1]
        assert client.get(f"{BASE}/1", headers=as_(mint, "dave")).json()["state"] == "approved"

        r = client.post(f"/registry/agents/{AGENT}/revoke", headers=as_(mint, "carol"))
        assert r.json()["state"] == "revoked"

    def test_reject(self, client: TestClient, mint: Mint) -> None:
        client.post(BASE, json=spec_doc(), headers=as_(mint, "dave"))
        client.post(f"{BASE}/1/submit", headers=as_(mint, "dave"))
        r = client.post(f"{BASE}/1/reject", headers=as_(mint, "bob"))
        assert r.json()["state"] == "rejected"


@pytest.mark.security
class TestErrors:
    @pytest.mark.parametrize(
        "headers",
        [{}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic x"}],
    )
    def test_unauthenticated(self, client: TestClient, headers: dict[str, str]) -> None:
        r = client.post(BASE, json=spec_doc(), headers=headers)
        assert (r.status_code, r.json()) == (401, {"error": "unauthorized"})
        assert r.headers["www-authenticate"] == "Bearer"

    def test_auth_checked_before_body(self, client: TestClient) -> None:
        """An unauthenticated caller learns nothing, not even that the body was invalid."""
        r = client.post(BASE, content=b"{not json")
        assert r.status_code == 401

    def test_wrong_scope(self, client: TestClient, mint: Mint) -> None:
        r = client.post(BASE, json=spec_doc(), headers=as_(mint, "dave", scope="mcp.admin"))
        assert (r.status_code, r.json()) == (403, {"error": "forbidden"})

    @pytest.mark.parametrize(
        "body",
        [b"{not json", b"[]", json.dumps(spec_doc(extra=1)).encode(), b'{"tier": "god"}'],
    )
    def test_invalid_spec(self, client: TestClient, mint: Mint, body: bytes) -> None:
        r = client.post(BASE, content=body, headers=as_(mint, "dave"))
        assert (r.status_code, r.json()) == (400, {"error": "invalid"})

    @pytest.mark.parametrize("body", [{}, {"role": "god"}, {"role": "approver", "x": 1}, []])
    def test_invalid_approve_body(self, client: TestClient, mint: Mint, body: Any) -> None:
        client.post(BASE, json=spec_doc(), headers=as_(mint, "dave"))
        client.post(f"{BASE}/1/submit", headers=as_(mint, "dave"))
        r = client.post(f"{BASE}/1/approve", json=body, headers=as_(mint, "bob"))
        assert r.status_code == 400

    def test_status_mapping(self, client: TestClient, mint: Mint) -> None:
        r = client.post(BASE, json=spec_doc(), headers=as_(mint, "eve"))
        assert r.status_code == 403
        client.post(BASE, json=spec_doc(), headers=as_(mint, "dave"))
        assert client.post(BASE, json=spec_doc(), headers=as_(mint, "dave")).status_code == 409
        assert client.post(f"{BASE}/9/submit", headers=as_(mint, "dave")).status_code == 404
        client.post(f"{BASE}/1/submit", headers=as_(mint, "dave"))
        r = client.post(f"{BASE}/1/reject", headers=as_(mint, "dave"))
        assert r.status_code == 403  # dave isn't an approver
        assert client.get(BASE, headers=as_(mint, "eve")).status_code == 404

    def test_unknown_action(self, client: TestClient, mint: Mint) -> None:
        r = client.post(f"{BASE}/1/delete", headers=as_(mint, "dave"))
        assert r.status_code == 404

    @pytest.mark.parametrize("version", ["abc", "0", "-1", "99999999999999999999"])
    def test_bad_version_path(self, client: TestClient, mint: Mint, version: str) -> None:
        r = client.post(f"{BASE}/{version}/submit", headers=as_(mint, "dave"))
        assert r.status_code in (400, 404)

    def test_duplicate_headers(self, client: TestClient, mint: Mint) -> None:
        h = as_(mint, "dave")["Authorization"]
        r = client.post(BASE, json=spec_doc(), headers=[("Authorization", h), ("Authorization", h)])
        assert r.status_code == 400

    def test_audit_down_is_503(self, rsa_key: RSAKey, mint: Mint) -> None:
        env = Env()
        env.audit.fail = True
        v = TokenValidator(
            ValidationPolicy(issuer=ISSUER, audiences=frozenset({AUDIENCE}), expected_typ="at+jwt"),
            StaticKeys(rsa_key),
            now=lambda: NOW,
        )
        c = TestClient(create_app(env.svc, v))
        r = c.post(BASE, json=spec_doc(), headers=as_(mint, "dave"))
        assert (r.status_code, r.json()) == (503, {"error": "unavailable"})

    def test_ping_reveals_nothing(self, client: TestClient) -> None:
        assert client.get("/ping").json() == {"status": "ok"}


# ----------------------------------------------------------------------------- build_app


def _ca_pem() -> bytes:
    from tests.inference.test_wiring import _ca_pem as make

    return make()


@pytest.fixture
def env_vars(tmp_path: pathlib.Path) -> dict[str, str]:
    (tmp_path / "ca.pem").write_bytes(_ca_pem())
    return {
        "ATF_ENV": "local",
        "ATF_REGISTRY_ISSUER": "https://mock-idp:8443/oauth2/registry",
        "ATF_REGISTRY_AUDIENCE": "api://agent-registry",
        "ATF_REGISTRY_JWKS_URI": "https://mock-idp:8443/oauth2/registry/v1/keys",
        "ATF_REGISTRY_TABLE": "agents",
        "ATF_TRUSTED_IDP_ORIGINS": "https://mock-idp:8443",
        "ATF_CA_BUNDLE": str(tmp_path / "ca.pem"),
        "AWS_REGION": "us-east-1",
    }


class TestBuildApp:
    def test_local_creates_table(self, env_vars: dict[str, str]) -> None:
        with mock_aws():
            app = build_app(env_vars)
            assert TestClient(app).get("/ping").status_code == 200
            names = boto3.client("dynamodb", region_name="us-east-1").list_tables()["TableNames"]
            assert names == ["agents"]
            assert TestClient(app).post(BASE, json=spec_doc()).status_code == 401

    def test_no_table_creation_outside_local(self, env_vars: dict[str, str]) -> None:
        with mock_aws():
            build_app({**env_vars, "ATF_ENV": "prod"})
            names = boto3.client("dynamodb", region_name="us-east-1").list_tables()["TableNames"]
            assert names == []

    @pytest.mark.parametrize("missing", ["ATF_REGISTRY_ISSUER", "ATF_REGISTRY_TABLE"])
    def test_missing_env(self, env_vars: dict[str, str], missing: str) -> None:
        with mock_aws(), pytest.raises(KeyError):
            build_app({k: v for k, v in env_vars.items() if k != missing})

    def test_app_from_env(self, env_vars: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
        from atf_agent_registry.app import app_from_env

        for k, v in env_vars.items():
            monkeypatch.setenv(k, v)
        with mock_aws():
            assert TestClient(app_from_env()).get("/ping").status_code == 200
