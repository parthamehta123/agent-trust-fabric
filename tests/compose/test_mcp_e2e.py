"""MCP gateway end to end over HTTPS (ADR-0016/0017/0018). Run with `make up e2e`.

Real tokens from the mock IdP, signed on the host with the bootstrap's local keys; real
DynamoDB Local; real SSRF pinning to the tools network; trust = the ephemeral CA only.
"""

from __future__ import annotations

import json
import os
import pathlib
import ssl
import subprocess
import time
import uuid
from typing import Any

import httpx
import pytest

from tests.compose.conftest import MCP_SERVER_ID
from trustkit.signing import InMemoryEs256Signer, build_client_assertion

pytestmark = [
    pytest.mark.compose,
    pytest.mark.skipif(os.environ.get("ATF_COMPOSE") != "1", reason="needs the compose stack"),
]

ROOT = pathlib.Path(__file__).parents[2]
CA = ROOT / ".local-ca" / "ca.pem"
KEYS = ROOT / ".local-ca" / "client-keys"
IDP_HOST, IDP_CONFIGURED = "https://localhost:9443", "https://mock-idp:8443"
DATA, ADMIN = "https://localhost:8444/mcp", "https://localhost:9445/admin/servers"
TOOL_URL = "https://mock-mcp.tools.internal:8443/mcp"
ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


@pytest.fixture(scope="module")
def http() -> httpx.Client:
    return httpx.Client(verify=ssl.create_default_context(cafile=str(CA)), timeout=15)


def _compose(*args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["docker", "compose", *args],  # noqa: S607
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "ATF_UID": str(os.getuid()), "ATF_GID": str(os.getgid())},
    ).stdout


def token(http: httpx.Client, as_path: str, client_id: str, key: str, form: dict[str, str]) -> str:
    """POST to the IdP from the host; the assertion audience is the IdP's *configured* endpoint."""
    signer = InMemoryEs256Signer((KEYS / f"{key}.pem").read_bytes())
    configured = f"{IDP_CONFIGURED}{as_path}"
    assertion = build_client_assertion(
        signer,
        client_id=client_id,
        token_endpoint=configured,
        now=lambda: int(time.time()),
    )
    r = http.post(
        f"{IDP_HOST}{as_path}",
        data={**form, "client_assertion_type": ASSERTION, "client_assertion": assertion},
    )
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


def admin_token(http: httpx.Client, who: str) -> str:
    return token(
        http,
        "/oauth2/admin/v1/token",
        f"0oa-admin-{who}",
        f"admin-{who}",
        {"grant_type": "client_credentials", "scope": "mcp.admin"},
    )


def workload_token(http: httpx.Client) -> str:
    return token(
        http,
        "/oauth2/workload/v1/token",
        "0oa-agent-alpha",
        "agent",
        {"grant_type": "client_credentials", "scope": "tools.invoke"},
    )


def t2_for(http: httpx.Client, user: str = "00u-alice") -> str:
    """User T2 requesting the delegated tool scope; the IdP downscopes unentitled users."""
    login = http.post(
        f"{IDP_HOST}/_test/login",
        json={"user": user, "client_id": "0oa-chat", "ingress_as_id": "ingress"},
    ).json()
    jag = token(
        http,
        "/oauth2/v1/token",
        "0oa-chat",
        "chat",
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            "subject_token": login["id_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "audience": f"{IDP_CONFIGURED}/oauth2/agent-alpha",
            "scope": "agent.invoke tickets.read",
        },
    )
    return token(
        http,
        "/oauth2/agent-alpha/v1/token",
        "0oa-chat",
        "chat",
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jag,
        },
    )


def agent_call(http: httpx.Client, body: dict[str, Any], user: str = "00u-alice") -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {workload_token(http)}",
        "X-Subject-Token": t2_for(http, user),
    }
    r = http.post(DATA, json=body, headers=headers)
    assert r.status_code == 200, r.text
    return dict(r.json())


@pytest.fixture(scope="module")
def server_id(http: httpx.Client) -> str:
    """Fresh mock-mcp state, then enrol + refresh (alice) + approve (bob)."""
    _compose("restart", "mock-mcp")
    _compose("up", "-d", "--wait", "mock-mcp")
    sid = MCP_SERVER_ID  # the id agent-alpha's registry grant names (conftest)
    alice = {"Authorization": f"Bearer {admin_token(http, 'alice')}"}
    bob = {"Authorization": f"Bearer {admin_token(http, 'bob')}"}
    enrol = {
        "server_id": sid,
        "url": TOOL_URL,
        "delegation": "token",
        "audience": "api://tool-tickets",
        "scopes": ["tickets.read"],
    }
    assert http.post(ADMIN, json=enrol, headers=alice).status_code == 201
    assert http.post(f"{ADMIN}/{sid}/refresh", headers=alice).status_code == 200
    assert http.post(f"{ADMIN}/{sid}/approve", headers=alice).status_code == 403, "two-person rule"
    assert http.post(f"{ADMIN}/{sid}/approve", headers=bob).status_code == 200
    return sid


class TestMcpEndToEnd:
    def test_agent_calls_tool_with_delegated_token(
        self, http: httpx.Client, server_id: str
    ) -> None:
        names = [
            t["name"]
            for t in agent_call(http, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})[
                "result"
            ]["tools"]
        ]
        assert f"{server_id}__get_ticket" in names
        r = agent_call(
            http,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": f"{server_id}__get_ticket", "arguments": {"id": "T-1"}},
            },
        )
        # The tool independently verified a delegated token naming both the user and the agent.
        assert r["result"]["content"][0]["text"] == "ticket T-1 for 00u-alice via 0oa-agent-alpha"

    @pytest.mark.security
    def test_unentitled_user_denied_by_guardrail(self, http: httpx.Client, server_id: str) -> None:
        """ADR-0023: bob isn't entitled to tickets.read, so the IdP downscopes his T2 and
        Cedar's user-scope guardrail denies, even though the agent's grant allows it."""
        call = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": f"{server_id}__get_ticket", "arguments": {"id": "T-1"}},
        }
        r = agent_call(http, call, user="00u-bob")
        assert r["error"]["message"] == "unknown tool"  # indistinguishable from a missing tool
        listing = agent_call(http, {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}, "00u-bob")
        assert listing["result"]["tools"] == []

    @pytest.mark.security
    def test_unbound_agent_is_401(self, http: httpx.Client, server_id: str) -> None:
        r = http.post(
            DATA,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {workload_token(http)}"},
        )
        assert r.status_code == 401

    @pytest.mark.security
    def test_ssrf_enrolment_refused(self, http: httpx.Client, server_id: str) -> None:
        alice = {"Authorization": f"Bearer {admin_token(http, 'alice')}"}
        for url in (
            "https://mock-idp.tools.internal/mcp",
            "https://169.254.169.254/latest/meta-data/",
        ):
            enrol = {
                "server_id": f"x-{uuid.uuid4().hex[:6]}",
                "url": url,
                "delegation": "token",
                "audience": "api://x",
                "scopes": ["x.read"],
            }
            assert http.post(ADMIN, json=enrol, headers=alice).status_code == 400

    @pytest.mark.security
    def test_admin_plane_unreachable_from_data_plane(self) -> None:
        cfg = json.loads(_compose("config", "--format", "json"))
        data = set(cfg["services"]["mcp-gateway"]["networks"])
        admin = set(cfg["services"]["mcp-admin"]["networks"])
        assert data.isdisjoint(admin)
        probe = (
            "import socket,sys\ntry:\n socket.getaddrinfo('mcp-admin',8443)\n sys.exit(1)\n"
            "except OSError:\n sys.exit(0)"
        )
        _compose("exec", "-T", "mcp-gateway", "python", "-c", probe)

    @pytest.mark.security
    def test_rug_pull_quarantines_server(self, http: httpx.Client, server_id: str) -> None:
        """TM-TOOL-03 end to end. Runs last in this module: it mutates the mock server."""
        rug = (
            "import ssl,urllib.request as u; u.urlopen(u.Request('https://mock-mcp.tools.internal:8443/_test/rug-pull',"
            " method='POST'), context=ssl.create_default_context(cafile='/run/certs/ca.pem'))"
        )
        _compose("exec", "-T", "mock-mcp", "python", "-c", rug)
        alice = {"Authorization": f"Bearer {admin_token(http, 'alice')}"}
        r = http.post(f"{ADMIN}/{server_id}/refresh", headers=alice)
        assert (r.status_code, r.json()["status"]) == (200, "pending_review")
        names = [
            t["name"]
            for t in agent_call(http, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})[
                "result"
            ]["tools"]
        ]
        assert f"{server_id}__get_ticket" not in names
        r2 = agent_call(
            http,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": f"{server_id}__get_ticket", "arguments": {"id": "T-1"}},
            },
        )
        assert "error" in r2
