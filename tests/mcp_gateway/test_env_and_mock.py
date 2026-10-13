"""Env factories (ADR-0018) and the mock MCP server (test infra)."""

from __future__ import annotations

import json
import pathlib
from collections.abc import Iterator
from typing import Any

import pytest
from atf_mcp_gateway.app import build_admin_app, build_data_app
from atf_mcp_gateway.ssrf import SsrfConfigError
from fastapi.testclient import TestClient
from joserfc.jwk import RSAKey
from moto import mock_aws

from mock_mcp.app import create_app as mock_mcp_app
from tests.conftest import NOW, Mint, good_claims

TOOL_ISS, TOOL_AUD = "https://idp.example.test/oauth2/tool-tickets", "api://tool-tickets"


@pytest.fixture
def env(tmp_path: pathlib.Path) -> Iterator[dict[str, str]]:
    from devstack.bootstrap import bootstrap
    from tests.policy.test_bundle import SIGNER

    r = bootstrap(tmp_path / "ca")
    (tmp_path / "bundle-key.jwk").write_text(json.dumps(SIGNER.public_jwk()))
    with mock_aws():
        yield {
            "ATF_BUNDLE_ISSUER": "atf-bundle-publisher",
            "ATF_BUNDLE_PUBLIC_JWK_PATH": str(tmp_path / "bundle-key.jwk"),
            "ATF_BUNDLE_PATH": str(tmp_path / "bundle.jws"),
            "ATF_ENV": "local",
            "ATF_CA_BUNDLE": str(r.ca_cert),
            "ATF_DDB_TABLE": "mcp-servers",
            "ATF_EGRESS_PROFILE_PATH": str(r.out_dir / "mcp-egress.json"),
            "ATF_LOCAL_KEYS_DIR": str(r.out_dir / "client-keys"),
            "ATF_SSRF_ALLOW_CIDRS": "172.30.0.0/16",
            "ATF_ADMIN_ISSUER": "https://mock-idp:8443/oauth2/admin",
            "ATF_ADMIN_AUDIENCE": "api://mcp-admin",
            "ATF_ADMIN_JWKS_URI": "https://mock-idp:8443/oauth2/admin/v1/keys",
            "AWS_REGION": "us-east-1",
        }


class TestFactories:
    def test_admin_app_builds_and_creates_local_table(self, env: dict[str, str]) -> None:
        import boto3

        TestClient(build_admin_app(env))
        assert (
            "mcp-servers"
            in boto3.client("dynamodb", region_name="us-east-1").list_tables()["TableNames"]
        )

    def test_data_app_builds(self, env: dict[str, str]) -> None:
        assert TestClient(build_data_app(env)).get("/ping").status_code == 200

    @pytest.mark.security
    @pytest.mark.parametrize("build", [build_admin_app, build_data_app])
    def test_ssrf_allowlist_refused_outside_local(self, env: dict[str, str], build: Any) -> None:
        with pytest.raises(SsrfConfigError):
            build({**env, "ATF_ENV": "prod"})

    @pytest.mark.parametrize(
        "missing",
        ["ATF_CA_BUNDLE", "ATF_DDB_TABLE", "ATF_BUNDLE_ISSUER", "ATF_BUNDLE_PUBLIC_JWK_PATH"],
    )
    def test_required_env(self, env: dict[str, str], missing: str) -> None:
        with pytest.raises(KeyError):
            build_data_app({k: v for k, v in env.items() if k != missing})


@pytest.fixture
def mcp(rsa_key: RSAKey) -> TestClient:
    env = {"ATF_ENV": "local", "ATF_TOOL_ISSUER": TOOL_ISS, "ATF_TOOL_AUDIENCE": TOOL_AUD}
    jwks = {"keys": [rsa_key.as_dict(private=False)]}
    return TestClient(mock_mcp_app(env=env, keys=lambda: jwks, now=lambda: NOW))


def tok(mint: Mint, **kw: Any) -> str:
    claims = good_claims(iss=TOOL_ISS, aud=TOOL_AUD, act={"sub": "0oa-agent-alpha"})
    claims.update(kw)
    return mint({k: v for k, v in claims.items() if v is not None}, header={"typ": "at+jwt"})


def call(client: TestClient, token: str | None) -> Any:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    body = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "get_ticket", "arguments": {"id": "T-9"}},
    }
    return client.post("/mcp", json=body, headers=headers)


class TestMockMcp:
    def test_refuses_outside_local(self) -> None:
        with pytest.raises(RuntimeError):
            mock_mcp_app(
                env={"ATF_ENV": "prod", "ATF_TOOL_ISSUER": "x", "ATF_TOOL_AUDIENCE": "y"}, keys=dict
            )

    def test_call_echoes_user_and_agent(self, mcp: TestClient, mint: Mint) -> None:
        r = call(mcp, tok(mint))
        assert (
            r.json()["result"]["content"][0]["text"]
            == "ticket T-9 for 00u-user-1 via 0oa-agent-alpha"
        )

    @pytest.mark.security
    @pytest.mark.parametrize(
        "kw", [{"act": None}, {"aud": "api://other"}, {"iss": "https://evil"}, {"exp": NOW - 1}]
    )
    def test_rejects_non_delegated_or_wrong_tokens(
        self, mcp: TestClient, mint: Mint, kw: dict[str, Any]
    ) -> None:
        assert call(mcp, tok(mint, **kw)).status_code == 401

    def test_rejects_missing_token(self, mcp: TestClient) -> None:
        assert call(mcp, None).status_code == 401

    def test_rug_pull_changes_description(self, mcp: TestClient) -> None:
        before = mcp.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()
        mcp.post("/_test/rug-pull")
        after = mcp.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()
        assert before != after
        assert json.dumps(after).count("forward") == 1
