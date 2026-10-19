"""DPoP on the running stack (ADR-0028 Phase 1, TM-TOK-01).

End state of the ADR-0028 rollout: both agents' IdP clients require DPoP and the data-plane
gateways run in ``required`` mode. No bearer workload token can be obtained, and none is accepted.
These tests attack the live gateways with stolen-token scenarios and run the real
user -> alpha -> beta -> tool chain with every agent hop proven."""

from __future__ import annotations

import base64
import json
import os
import ssl
from typing import Any

import httpx
import pytest

from tests.compose.conftest import AGENT, BETA
from tests.compose.dpop_harness import bound_workload_token, dpop_call, dpop_request, mint_bound
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
    @pytest.mark.parametrize(("client", "key_name"), [(AGENT, "agent"), (BETA, "agent-beta")])
    def test_idp_issues_no_unbound_workload_token(
        self, http: httpx.Client, client: str, key_name: str
    ) -> None:
        """No downgrade at issuance: neither agent can get a token without proving a key."""
        from tests.compose.test_mcp_e2e import token

        form = {"grant_type": "client_credentials", "scope": "tools.invoke"}
        with pytest.raises(AssertionError):
            token(http, "/oauth2/workload/v1/token", client, key_name, form, bind=False)

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


@pytest.mark.security
class TestRequiredEverywhere:
    @pytest.mark.parametrize(
        ("as_path", "scope", "host", "path", "body"),
        [
            ("/oauth2/workload/v1/token", "tools.invoke", "https://localhost:8444", "/mcp", LIST),
            (
                "/oauth2/inference/v1/token",
                "inference.invoke",
                "https://localhost:8445",
                "/v1/chat/completions",
                {"model": "x", "messages": []},
            ),
            (
                "/oauth2/workload/v1/token",
                "tools.invoke",
                "https://localhost:8446",
                f"/agents/{BETA}/a2a",
                LIST,
            ),
        ],
    )
    def test_bound_token_stripped_to_bearer_is_refused_at_every_gateway(
        self, http: httpx.Client, as_path: str, scope: str, host: str, path: str, body: Any
    ) -> None:
        key = DpopKey()
        form = {"grant_type": "client_credentials", "scope": scope}
        token, _ = mint_bound(http, as_path, AGENT, "agent", form, key)
        r = http.post(
            f"{host}{path}",
            json=body,
            headers={"Authorization": f"Bearer {token}", "X-Subject-Token": "t2"},
        )
        assert r.status_code == 401
        assert "dpop_missing" in r.text


class TestChainFullyBound:
    def test_chain_runs_with_every_agent_hop_proven(self, http: httpx.Client) -> None:
        """user -> alpha -(A2A)-> beta -> MCP gateway -> tool, with alpha's and beta's workload
        tokens both DPoP-bound (the gateways would refuse anything else)."""
        from tests.compose.dpop_harness import harness_client
        from tests.compose.test_a2a_e2e import chain_works
        from tests.compose.test_mcp_e2e import CA

        with harness_client(CA) as agent_http:
            assert chain_works(agent_http)
        for svc in ("mcp-gateway", "inference-gateway", "a2a-gateway"):
            env = _compose("exec", "-T", svc, "printenv", "ATF_DPOP_MODE").strip()
            assert env == "required", svc
