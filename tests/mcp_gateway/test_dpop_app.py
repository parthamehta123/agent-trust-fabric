"""DPoP at the MCP gateway's HTTP surface (ADR-0028 Phase 1, TM-TOK-01)."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any

import boto3
import pytest
from atf_mcp_gateway.app import create_data_app
from atf_mcp_gateway.proxy import McpProxy
from atf_mcp_gateway.servers import InMemoryServerStore
from fastapi.testclient import TestClient
from joserfc.jwk import RSAKey
from moto import mock_aws

from tests.conftest import AUDIENCE, ISSUER, NOW, Mint, StaticKeys, good_claims
from tests.mcp_gateway.test_proxy import BINDING, Upstream, call, overlap, record
from tests.mcp_gateway.test_snapshot import TOOLS
from trustkit.binding import ActorBindingError, ActorBindingReason
from trustkit.dpop import (
    DpopError,
    DpopGuard,
    DpopKey,
    DpopMode,
    DpopVerifier,
    NonceIssuer,
    ReplayCache,
    dpop_guard_from_env,
)
from trustkit.jwt import TokenValidator, ValidationPolicy
from trustkit.scanning import LocalRulesScanner
from trustkit_aws.secrets import SecretUnavailableError, secret_bytes_fetcher

PUBLIC = "https://mcp.atf.example.com"
NONCE_KEY = b"n" * 32


class Clock:
    def __init__(self) -> None:
        self.t = float(NOW)

    def __call__(self) -> float:
        return self.t


def client(rsa_key: RSAKey, mode: DpopMode, unbound: list[str]) -> tuple[TestClient, list[str]]:
    seen: list[str] = []
    store = InMemoryServerStore()
    store.put(record("tickets", TOOLS), expected_status=None)

    class Creds:
        def delegated_token(self, b: Any, r: Any) -> str:
            return "DELEGATED"

        def server_secret(self, r: Any) -> str:
            return "S"

    def binder(headers: Mapping[str, str]) -> Any:
        auth = headers.get("authorization", "")
        if (
            not auth.startswith("Bearer ")
            or "dpop" in headers
            or headers.get("x-subject-token") != "t2"
        ):
            raise ActorBindingError(ActorBindingReason.WORKLOAD_INVALID)
        seen.append(auth)
        return BINDING

    proxy = McpProxy(
        store=store,
        upstream=Upstream(),
        credentials=Creds(),
        scanner=LocalRulesScanner(),
        authorize=overlap,
    )
    clock = Clock()
    validator = TokenValidator(
        ValidationPolicy(issuer=ISSUER, audiences=frozenset({AUDIENCE})),
        StaticKeys(rsa_key),
        now=lambda: NOW,
    )
    nonces = NonceIssuer(NONCE_KEY, now=clock)
    guard = DpopGuard(
        public_url=PUBLIC,
        mode=mode,
        verifier=DpopVerifier(nonces=nonces, replay=ReplayCache(now=clock), now=lambda: NOW),
        validate=validator.validate,
        on_unbound=unbound.append,
    )
    return TestClient(create_data_app(proxy, binder, guard)), seen


def bound_token(mint: Mint, key: DpopKey) -> str:
    return mint({**good_claims(), "client_id": "0oa-agent", "cnf": {"jkt": key.jkt}})


def proof(key: DpopKey, token: str, nonce: str | None) -> str:
    return key.proof("POST", f"{PUBLIC}/mcp", access_token=token, nonce=nonce, now=lambda: NOW)


@pytest.mark.security
class TestMcpDpop:
    def test_nonce_challenge_then_success(self, rsa_key: RSAKey, mint: Mint) -> None:
        c, seen = client(rsa_key, DpopMode.REQUIRED, [])
        key = DpopKey()
        tok = bound_token(mint, key)
        r = c.post(
            "/mcp",
            json=call("tools/list"),
            headers={
                "Authorization": f"DPoP {tok}",
                "DPoP": proof(key, tok, None),
                "X-Subject-Token": "t2",
            },
        )
        assert r.status_code == 401
        assert 'error="use_dpop_nonce"' in r.headers["www-authenticate"]
        nonce = r.headers["dpop-nonce"]
        r = c.post(
            "/mcp",
            json=call("tools/list"),
            headers={
                "Authorization": f"DPoP {tok}",
                "DPoP": proof(key, tok, nonce),
                "X-Subject-Token": "t2",
            },
        )
        assert r.status_code == 200, r.text
        assert seen == [f"Bearer {tok}"]  # the binder sees exactly what it always did

    def test_stolen_pair_without_the_key_is_refused(self, rsa_key: RSAKey, mint: Mint) -> None:
        c, seen = client(rsa_key, DpopMode.REQUIRED, [])
        agent, thief = DpopKey(), DpopKey()
        tok = bound_token(mint, agent)
        nonce = NonceIssuer(NONCE_KEY, now=Clock()).issue("0oa-agent")
        r = c.post(
            "/mcp",
            json=call("tools/list"),
            headers={
                "Authorization": f"DPoP {tok}",
                "DPoP": proof(thief, tok, nonce),
                "X-Subject-Token": "t2",
            },
        )
        assert r.status_code == 401
        assert r.json()["error"]["message"] == "dpop_key_mismatch"
        assert seen == []

    def test_bound_token_replayed_as_bearer_is_refused(self, rsa_key: RSAKey, mint: Mint) -> None:
        c, seen = client(rsa_key, DpopMode.OPTIONAL, [])
        tok = bound_token(mint, DpopKey())
        r = c.post(
            "/mcp",
            json=call("tools/list"),
            headers={"Authorization": f"Bearer {tok}", "X-Subject-Token": "t2"},
        )
        assert r.status_code == 401
        assert seen == []

    def test_optional_mode_admits_and_audits_unbound(self, rsa_key: RSAKey, mint: Mint) -> None:
        unbound: list[str] = []
        c, seen = client(rsa_key, DpopMode.OPTIONAL, unbound)
        tok = mint({**good_claims(), "client_id": "0oa-legacy"})
        assert seen == []
        r = c.post(
            "/mcp",
            json=call("tools/list"),
            headers={"Authorization": f"Bearer {tok}", "X-Subject-Token": "t2"},
        )
        assert r.status_code == 200
        assert unbound == ["0oa-legacy"]
        assert seen == [f"Bearer {tok}"]

    def test_required_mode_refuses_unbound(self, rsa_key: RSAKey, mint: Mint) -> None:
        c, seen = client(rsa_key, DpopMode.REQUIRED, [])
        tok = mint(good_claims())
        r = c.post(
            "/mcp",
            json=call("tools/list"),
            headers={"Authorization": f"Bearer {tok}", "X-Subject-Token": "t2"},
        )
        assert r.status_code == 401
        assert r.json()["error"]["message"] == "dpop_required"
        assert seen == []

    def test_invalid_token_is_plain_unauthorized(self, rsa_key: RSAKey) -> None:
        c, _ = client(rsa_key, DpopMode.OPTIONAL, [])
        r = c.post(
            "/mcp",
            json=call("tools/list"),
            headers={"Authorization": "Bearer not-a-jwt", "X-Subject-Token": "t2"},
        )
        assert (r.status_code, r.json()["error"]["message"]) == (401, "unauthorized")


class TestGuardFromEnv:
    def test_off_by_default(self) -> None:
        assert dpop_guard_from_env({}, validate=lambda t: None) is None

    def test_local_key_file(self, tmp_path: Any) -> None:
        (tmp_path / "k").write_bytes(NONCE_KEY)
        env = {
            "ATF_DPOP_MODE": "optional",
            "ATF_PUBLIC_URL": PUBLIC,
            "ATF_DPOP_NONCE_KEY_PATH": str(tmp_path / "k"),
        }
        assert isinstance(dpop_guard_from_env(env, validate=lambda t: None), DpopGuard)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "env",
        [
            {"ATF_DPOP_MODE": "loose", "ATF_PUBLIC_URL": PUBLIC, "ATF_DPOP_NONCE_KEY_PATH": "/k"},
            {"ATF_DPOP_MODE": "required", "ATF_PUBLIC_URL": PUBLIC},  # no key
            {
                "ATF_DPOP_MODE": "required",
                "ATF_PUBLIC_URL": PUBLIC,
                "ATF_DPOP_NONCE_KEY_PATH": "/k",
                "ATF_DPOP_NONCE_KEY_SECRET_ARN": "arn",
            },
            {
                "ATF_DPOP_MODE": "required",
                "ATF_PUBLIC_URL": "http://plain",
                "ATF_DPOP_NONCE_KEY_SECRET_ARN": "arn",
            },
        ],
    )
    def test_misconfiguration_fails_cold_start(self, env: dict[str, str]) -> None:
        with pytest.raises((ValueError, KeyError, DpopError)):
            dpop_guard_from_env(env, validate=lambda t: None, fetch_secret=lambda arn: NONCE_KEY)

    def test_short_secret_refused(self) -> None:
        env = {
            "ATF_DPOP_MODE": "required",
            "ATF_PUBLIC_URL": PUBLIC,
            "ATF_DPOP_NONCE_KEY_SECRET_ARN": "arn",
        }
        with pytest.raises(ValueError, match="32 bytes"):
            dpop_guard_from_env(env, validate=lambda t: None, fetch_secret=lambda arn: b"short")


class TestSecretFetcher:
    def test_base64_secret_string(self) -> None:
        with mock_aws():
            sm = boto3.client("secretsmanager", region_name="us-east-1")
            arn = sm.create_secret(
                Name="atf/dpop", SecretString=base64.b64encode(NONCE_KEY).decode()
            )["ARN"]
            assert secret_bytes_fetcher("us-east-1", sm)(arn) == NONCE_KEY

    @pytest.mark.security
    def test_missing_or_garbage_secret(self) -> None:
        with mock_aws():
            sm = boto3.client("secretsmanager", region_name="us-east-1")
            arn = sm.create_secret(Name="atf/bad", SecretString="not base64 !!")["ARN"]
            fetch = secret_bytes_fetcher("us-east-1", sm)
            with pytest.raises(SecretUnavailableError):
                fetch(arn)
            with pytest.raises(SecretUnavailableError):
                fetch("arn:aws:secretsmanager:us-east-1:123456789012:secret:nope")
