"""Agent -> agent -> tool across real containers (ADR-0024). Run with `make up e2e`.

user (alice) -> agent-alpha (this test, with alpha's workload token + alice's T2)
  -> a2a-gateway (Cedar delegate, exchange at beta's AS) -> agent-beta runtime (validates act)
  -> MCP gateway (chain-aware Cedar) -> mock tool (verifies the nested act and echoes it).
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx
import pytest

from tests.compose.conftest import (
    A2A_SERVER_ID,
    AGENT,
    BETA,
    approve_new_version,
    beta_spec,
    wait_until,
)
from tests.compose.test_mcp_e2e import (
    ADMIN,
    TOOL_URL,
    _compose,
    admin_token,
    http,  # noqa: F401 - fixture
    t2_for,
    token,
    workload_token,
)

pytestmark = [
    pytest.mark.compose,
    pytest.mark.skipif(os.environ.get("ATF_COMPOSE") != "1", reason="needs the compose stack"),
]

A2A = "https://localhost:8446"
CHAIN_REPLY = f"ticket T-7 for 00u-alice via {BETA} on behalf of {AGENT}"


@pytest.fixture(scope="module", autouse=True)
def a2a_tool_server(http: httpx.Client) -> str:  # noqa: F811
    """A fresh tool server granted to both agents (enrol: alice, approve: bob)."""
    _compose("restart", "mock-mcp")
    _compose("up", "-d", "--wait", "mock-mcp")
    alice = {"Authorization": f"Bearer {admin_token(http, 'alice')}"}
    bob = {"Authorization": f"Bearer {admin_token(http, 'bob')}"}
    enrol = {
        "server_id": A2A_SERVER_ID,
        "url": TOOL_URL,
        "delegation": "token",
        "audience": "api://tool-tickets",
        "scopes": ["tickets.read"],
    }
    assert http.post(ADMIN, json=enrol, headers=alice).status_code == 201
    assert http.post(f"{ADMIN}/{A2A_SERVER_ID}/refresh", headers=alice).status_code == 200
    assert http.post(f"{ADMIN}/{A2A_SERVER_ID}/approve", headers=bob).status_code == 200
    return A2A_SERVER_ID


def send(
    client: httpx.Client, text: str = "please get ticket T-7", user: str = "00u-alice"
) -> httpx.Response:
    return client.post(
        f"{A2A}/agents/{BETA}/a2a",
        json={
            "jsonrpc": "2.0",
            "id": "e2e-1",
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "messageId": str(uuid.uuid4()),
                    "parts": [{"kind": "text", "text": text}],
                }
            },
        },
        headers={
            "Authorization": f"Bearer {workload_token(client)}",
            "X-Subject-Token": t2_for(client, user),
        },
    )


def reply_text(r: httpx.Response) -> str:
    assert r.status_code == 200, r.text
    return str(r.json()["result"]["parts"][0]["text"])


def chain_works(http: httpx.Client) -> bool:  # noqa: F811
    r = send(http)
    return r.status_code == 200 and reply_text(r) == CHAIN_REPLY


def beta_workload(http: httpx.Client) -> str:  # noqa: F811
    return token(
        http,
        "/oauth2/workload/v1/token",
        BETA,
        "agent-beta",
        {"grant_type": "client_credentials", "scope": "tools.invoke"},
    )


class TestChain:
    def test_user_to_alpha_to_beta_to_tool(self, http: httpx.Client) -> None:  # noqa: F811
        """The tool independently verified a token with act = {beta, act: {alpha}} for alice."""
        wait_until(lambda: chain_works(http), timeout=30, what="chain end to end")
        assert reply_text(send(http)) == CHAIN_REPLY

    def test_card_for_permitted_delegator(self, http: httpx.Client) -> None:  # noqa: F811
        r = http.get(
            f"{A2A}/agents/{BETA}/.well-known/agent-card.json",
            headers={"Authorization": f"Bearer {workload_token(http)}"},
        )
        assert r.status_code == 200, r.text
        card: dict[str, Any] = r.json()
        assert card["url"] == f"{A2A}/agents/{BETA}/a2a"
        assert "agents.internal" not in r.text  # the runtime endpoint is never disclosed
        assert [s["id"] for s in card["skills"]] == ["get-ticket"]


@pytest.mark.security
class TestDenies:
    def test_card_hidden_from_agent_without_edge(self, http: httpx.Client) -> None:  # noqa: F811
        r = http.get(
            f"{A2A}/agents/{AGENT}/.well-known/agent-card.json",
            headers={"Authorization": f"Bearer {beta_workload(http)}"},  # beta -> alpha: no edge
        )
        assert (r.status_code, r.json()) == (404, {"error": "unknown_agent"})

    def test_unentitled_user_reaches_beta_but_not_the_tool(self, http: httpx.Client) -> None:  # noqa: F811
        """Bob may invoke beta, but his T2 lacks tickets.read (IdP downscoping): beta's tool
        listing is empty for him, so no ticket is ever fetched."""
        assert (
            reply_text(send(http, user="00u-bob")) == "No ticket tool is available to me for you."
        )

    def test_laundering_denied_end_to_end(self, http: httpx.Client) -> None:  # noqa: F811
        """Alpha loses its own ticket grant (keeps the edge): beta can no longer read tickets
        for alpha's users, although beta's own grant is unchanged."""
        try:
            approve_new_version(http, tools={})
            wait_until(
                lambda: reply_text(send(http)) == "No ticket tool is available to me for you.",
                timeout=20,
                what="laundering denied",
            )
        finally:
            approve_new_version(http)
            wait_until(lambda: chain_works(http), timeout=20, what="restored")

    def test_caller_without_edges_cannot_even_bind(self, http: httpx.Client) -> None:  # noqa: F811
        """Alpha drops its only edge: it is no longer an A2A caller at all (401 at binding)."""
        try:
            approve_new_version(http, delegation={})
            wait_until(lambda: send(http).status_code == 401, timeout=20, what="binding refused")
        finally:
            approve_new_version(http)
            wait_until(lambda: chain_works(http), timeout=20, what="restored")

    def test_target_withdrawing_acceptance_denies(self, http: httpx.Client) -> None:  # noqa: F811
        """Alpha still offers, beta stops accepting: a one-sided edge is no edge (403)."""
        try:
            approve_new_version(http, BETA, beta_spec(delegation={}))
            wait_until(lambda: send(http).status_code == 403, timeout=20, what="edge one-sided")
            assert send(http).json()["error"]["message"] == "delegation_denied"
        finally:
            approve_new_version(http, BETA, beta_spec())
            wait_until(lambda: chain_works(http), timeout=20, what="restored")

    def test_beta_revoked_refuses_delegation(self, http: httpx.Client) -> None:  # noqa: F811
        from tests.compose.conftest import REGISTRY, reg_headers

        try:
            http.post(f"{REGISTRY}/{BETA}/revoke", headers=reg_headers(http, "carol"))
            wait_until(lambda: send(http).status_code == 404, timeout=20, what="beta revoked")
        finally:
            approve_new_version(http, BETA, beta_spec())
            wait_until(lambda: chain_works(http), timeout=20, what="restored")

    @pytest.mark.parametrize(
        ("service", "target"),
        [
            ("inference-gateway", "agent-beta"),  # only the A2A gateway reaches beta's runtime
            ("mcp-admin", "agent-beta"),
            ("a2a-gateway", "mcp-admin"),
            ("a2a-gateway", "mock-mcp.tools.internal"),
            ("agent-beta", "agent-registry"),
        ],
    )
    def test_isolation(self, service: str, target: str) -> None:
        probe = (
            "import socket,sys\n"
            "try:\n"
            f"    socket.create_connection(({target!r}, 8443), timeout=2)\n"
            "except OSError:\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        _compose("exec", "-T", service, "python", "-c", probe)
