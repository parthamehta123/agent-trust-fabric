"""DPoP on the running stack (ADR-0028 Phase 1, TM-TOK-01).

agent-beta's IdP client requires DPoP; the gateways run in ``optional`` mode (alpha is still
bearer). These tests attack the live MCP gateway with a stolen-token scenario and check the real
user -> alpha -> beta -> tool chain runs with beta's hop bound."""

from __future__ import annotations

import base64
import json
import os
import ssl
from typing import Any

import httpx
import pytest

from tests.compose.conftest import BETA
from tests.compose.dpop_harness import bound_workload_token, dpop_call, dpop_request
from tests.compose.test_mcp_e2e import CA, DATA, _compose
from trustkit.dpop import DpopKey

pytestmark = [
    pytest.mark.compose,
    pytest.mark.skipif(os.environ.get("ATF_COMPOSE") != "1", reason="needs the compose stack"),
]

MCP_PUBLIC = "https://mcp-gateway:8443/mcp"


@pytest.fixture(scope="module")
def http() -> httpx.Client:
    """TLS to the stack, trusting only its ephemeral CA (as every compose suite does)."""
    return httpx.Client(verify=ssl.create_default_context(cafile=str(CA)), timeout=15)


LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def claims(token: str) -> dict[str, Any]:
    seg = token.split(".")[1]
    out: dict[str, Any] = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    return out


def message(r: httpx.Response) -> str:
    return str(r.json()["error"]["message"])


@pytest.fixture
def beta_key_and_token(http: httpx.Client) -> tuple[DpopKey, str]:
    key = DpopKey()
    token, attempts = bound_workload_token(http, BETA, "agent-beta", key)
    assert attempts == 2  # the IdP challenged the first proof for a nonce, as Okta does
    assert claims(token)["cnf"] == {"jkt": key.jkt}
    return key, token


@pytest.mark.security
class TestStolenBoundToken:
    def test_idp_refuses_bearer_for_a_dpop_client(self, http: httpx.Client) -> None:
        """No downgrade at issuance either: a DPoP-required client gets no unbound token."""
        from tests.compose.test_a2a_e2e import beta_workload

        with pytest.raises(AssertionError):
            beta_workload(http)

    def test_replayed_as_bearer_is_refused(
        self,
        http: httpx.Client,
        beta_key_and_token: Any,
    ) -> None:
        _, token = beta_key_and_token
        r = http.post(
            DATA, json=LIST, headers={"Authorization": f"Bearer {token}", "X-Subject-Token": "t2"}
        )
        assert (r.status_code, message(r)) == (401, "dpop_missing")

    def test_thiefs_proof_is_refused(self, http: httpx.Client, beta_key_and_token: Any) -> None:
        _, token = beta_key_and_token
        r = dpop_call(
            http,
            "POST",
            host_url=DATA,
            public_url=MCP_PUBLIC,
            token=token,
            key=DpopKey(),
            json=LIST,
            headers={"X-Subject-Token": "t2"},
        )
        assert (r.status_code, message(r)) == (401, "dpop_key_mismatch")

    def test_holder_passes_the_guard_and_replay_is_refused(
        self,
        http: httpx.Client,
        beta_key_and_token: Any,
    ) -> None:
        """With the right key the proof is accepted (the binder then refuses the junk subject
        token: a different, later error). Resending that exact accepted proof is a replay."""
        key, token = beta_key_and_token
        first = dpop_request(
            http,
            "POST",
            host_url=DATA,
            public_url=MCP_PUBLIC,
            token=token,
            key=key,
            json=LIST,
            headers={"X-Subject-Token": "t2"},
        )
        assert first.status_code == 401
        assert 'error="use_dpop_nonce"' in first.headers["www-authenticate"]
        nonce = first.headers["dpop-nonce"]
        proof = key.proof("POST", MCP_PUBLIC, access_token=token, nonce=nonce)
        sent = {"Authorization": f"DPoP {token}", "DPoP": proof, "X-Subject-Token": "t2"}
        r = http.post(DATA, json=LIST, headers=sent)
        assert (r.status_code, message(r)) == (
            401,
            "unauthorized",
        )  # past the guard, binder says no
        again = http.post(DATA, json=LIST, headers=sent)
        assert (again.status_code, message(again)) == (401, "dpop_replay")


class TestChainWithBoundBeta:
    def test_chain_runs_and_beta_is_never_audited_as_unbound(self, http: httpx.Client) -> None:
        from tests.compose.test_a2a_e2e import chain_works

        assert chain_works(http)  # user -> alpha -> (A2A) -> beta -> MCP gateway -> tool
        logs = _compose("logs", "--no-color", "mcp-gateway")
        unbound = [
            json.loads(line.split("|", 1)[1])
            for line in logs.splitlines()
            if "dpop.unbound_workload_token" in line and "|" in line
        ]
        assert BETA not in {e.get("client_id") for e in unbound}  # beta's hop was proven
