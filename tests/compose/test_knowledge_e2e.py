"""Retrieval-time authorization across real containers (ADR-0025). Run with `make up e2e`.

alice/bob -> agent-alpha (this test) -> MCP gateway (Cedar, delegated token for api://knowledge,
narrowed to the user) -> knowledge server (validates the token, server-side filter, per-chunk
Cedar, response scan). Corpus: deploy/local/corpus (ingested by `make kb-index`).
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

import httpx
import pytest

from tests.compose.conftest import KB_SCOPES, KB_SERVER_ID
from tests.compose.test_mcp_e2e import (
    ADMIN,
    ROOT,
    _compose,
    admin_token,
    agent_call,
    http,  # noqa: F401 - fixture
)

pytestmark = [
    pytest.mark.compose,
    pytest.mark.skipif(os.environ.get("ATF_COMPOSE") != "1", reason="needs the compose stack"),
]

KB_URL = "https://knowledge.tools.internal:8443/mcp"
QUERY = "deploy release pipeline canary postmortem salary bands handbook"


@pytest.fixture(scope="module", autouse=True)
def kb_server(http: httpx.Client) -> str:  # noqa: F811
    alice = {"Authorization": f"Bearer {admin_token(http, 'alice')}"}
    bob = {"Authorization": f"Bearer {admin_token(http, 'bob')}"}
    enrol = {
        "server_id": KB_SERVER_ID,
        "url": KB_URL,
        "delegation": "token",
        "audience": "api://knowledge",
        "scopes": KB_SCOPES,
    }
    assert http.post(ADMIN, json=enrol, headers=alice).status_code == 201
    assert http.post(f"{ADMIN}/{KB_SERVER_ID}/refresh", headers=alice).status_code == 200
    assert http.post(f"{ADMIN}/{KB_SERVER_ID}/approve", headers=bob).status_code == 200
    return KB_SERVER_ID


def search(http: httpx.Client, user: str, query: str = QUERY) -> dict[str, Any]:  # noqa: F811
    return agent_call(
        http,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": f"{KB_SERVER_ID}__search",
                "arguments": {"query": query, "top_k": 10},
            },
        },
        user=user,
    )


def text_of(r: dict[str, Any]) -> str:
    assert "result" in r, r
    return str(r["result"]["content"][0]["text"])


@pytest.mark.security
class TestRetrievalAuthorization:
    def test_alice_sees_only_what_user_and_agent_both_allow(self, http: httpx.Client) -> None:  # noqa: F811
        text = text_of(search(http, "00u-alice"))
        assert "[eng/internal] Deploy runbook" in text
        assert "[public/public] Employee handbook" in text
        assert "Incident postmortem" not in text  # confidential > alpha's internal ceiling
        assert "Salary bands" not in text  # hr: alice may, alpha may not

    def test_bob_narrowed_to_public(self, http: httpx.Client) -> None:  # noqa: F811
        """Bob holds only kb.public.read: the gateway narrows the request instead of denying."""
        text = text_of(search(http, "00u-bob"))
        assert "[public/public] Employee handbook" in text
        assert "Deploy runbook" not in text

    def test_no_provenance_or_vectors_leak(self, http: httpx.Client) -> None:  # noqa: F811
        blob = str(search(http, "00u-alice"))
        for leak in ("s3://", "sha256", "ingested_by", "vector"):
            assert leak not in blob

    def test_agent_cannot_widen_filter(self, http: httpx.Client) -> None:  # noqa: F811
        r = agent_call(
            http,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": f"{KB_SERVER_ID}__search",
                    "arguments": {"query": "salary", "collections": ["hr"]},
                },
            },
        )
        assert "error" in r or "Salary bands" not in str(r)


@pytest.mark.security
class TestIngestionAndIsolation:
    def test_poisoned_corpus_refused_and_nothing_written(self, tmp_path: Any) -> None:
        out = tmp_path / "index.jsonl"
        r = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "uv",
                "run",
                "python",
                "-m",
                "atf_knowledge_server.ingest",
                "--corpus",
                str(ROOT / "deploy/local/corpus-poisoned"),
                "--config",
                str(ROOT / "deploy/local/kb-collections.json"),
                "--out",
                str(out),
                "--ingested-by",
                "e2e",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert r.returncode == 1
        assert "rejected faq: content_blocked" in r.stderr
        assert not out.exists()

    @pytest.mark.parametrize(
        ("service", "target"),
        [
            ("inference-gateway", "knowledge.tools.internal"),
            ("a2a-gateway", "knowledge.tools.internal"),
            ("agent-registry", "knowledge.tools.internal"),
            ("knowledge-server", "agent-registry"),
            ("knowledge-server", "inference-gateway"),
            # Not asserted: tool servers can reach the MCP admin listener on tools-admin (RR-7).
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

    def test_index_read_only_in_container(self) -> None:
        probe = (
            "import sys\n"
            "try:\n"
            "    open('/run/kb/index.jsonl', 'a').close()\n"
            "except OSError:\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        _compose("exec", "-T", "knowledge-server", "python", "-c", probe)
