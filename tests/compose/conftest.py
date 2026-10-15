"""Compose e2e session setup (ADR-0021/0022/0023).

Agent-alpha is approved through the *real* registry workflow (dave submits, bob approves), the
publisher signs a bundle, and the session waits until the gateways enforce it. Nothing is seeded
behind the workflow's back.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

REGISTRY = "https://localhost:9446/registry/agents"
AGENT = "0oa-agent-alpha"
MCP_SERVER_ID = f"tickets-{uuid.uuid4().hex[:8]}"
"""Enrolled by the MCP suite; granted to agent-alpha here."""
A2A_SERVER_ID = f"tickets-a2a-{uuid.uuid4().hex[:8]}"
"""Enrolled by the A2A suite; granted to *both* agents (no amplification, ADR-0024 §3)."""
BETA = "0oa-agent-beta"
KB_SERVER_ID = f"kb-{uuid.uuid4().hex[:8]}"
"""The knowledge server's enrolment (knowledge suite); its tool scopes are granted to alpha."""
KB_SCOPES = ["kb.eng.read", "kb.hr.read", "kb.public.read"]
IDP_CONFIGURED = "https://mock-idp:8443"


TIMEOUT_SCALE = float(os.environ.get("ATF_E2E_TIMEOUT_SCALE", "1"))
"""CI runners are slower at stack churn; this stretches how long tests *wait*, never what the
system is allowed to do (bundle ages and refresh periods are fixed by the stack)."""


def wait_until(check: Callable[[], bool], timeout: float = 30.0, what: str = "") -> None:
    deadline = time.monotonic() + timeout * TIMEOUT_SCALE
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for {what or check}")


def reg_headers(http: httpx.Client, who: str) -> dict[str, str]:
    from tests.compose.test_mcp_e2e import token

    tok = token(
        http,
        "/oauth2/registry/v1/token",
        f"0oa-reg-{who}",
        f"reg-{who}",
        {"grant_type": "client_credentials", "scope": "registry.admin"},
    )
    return {"Authorization": f"Bearer {tok}"}


def alpha_spec(**over: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "display_name": "Agent alpha",
        "owner_team": "alpha",
        "tier": "standard",
        "ingress": {
            "t2_issuer": f"{IDP_CONFIGURED}/oauth2/agent-alpha",
            "t2_audience": "api://agent-alpha",
            "t2_jwks_uri": f"{IDP_CONFIGURED}/oauth2/agent-alpha/v1/keys",
        },
        "tools": {
            MCP_SERVER_ID: ["tickets.read"],
            A2A_SERVER_ID: ["tickets.read"],
            KB_SERVER_ID: KB_SCOPES,
        },
        # ADR-0025: what alpha may retrieve, independent of the user's own entitlements.
        "knowledge": {"collections": ["eng", "public"], "max_classification": "internal"},
        "models": {"claude-sonnet": {"daily_token_budget": 20000, "max_output_tokens": 256}},
        "delegation": {"may_delegate_to": [BETA]},
    }
    spec.update(over)
    return spec


def beta_spec(**over: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "display_name": "Agent beta",
        "description": "Fetches tickets on behalf of other agents",
        "owner_team": "alpha",
        "tier": "standard",
        "ingress": {
            "t2_issuer": f"{IDP_CONFIGURED}/oauth2/agent-beta",
            "t2_audience": "api://agent-beta",
            "t2_jwks_uri": f"{IDP_CONFIGURED}/oauth2/agent-beta/v1/keys",
        },
        "tools": {A2A_SERVER_ID: ["tickets.read"]},
        "delegation": {"accepts_delegation_from": [AGENT]},
        "card": {
            "endpoint": "https://agent-beta.agents.internal:8443/invocations",
            "skills": [{"id": "get-ticket", "name": "Get ticket"}],
        },
    }
    spec.update(over)
    return spec


def approve_new_version(
    http: httpx.Client, agent: str = AGENT, spec: dict[str, Any] | None = None, **over: Any
) -> int:
    """dave creates + submits, bob approves; carol adds security approval when the version adds
    a delegation edge (ADR-0024 §4). Returns the approved version."""
    dave, bob = reg_headers(http, "dave"), reg_headers(http, "bob")
    body = spec if spec is not None else alpha_spec(**over)
    r = http.post(f"{REGISTRY}/{agent}/versions", json=body, headers=dave)
    assert r.status_code == 201, r.text
    v = r.json()["version"]
    base = f"{REGISTRY}/{agent}/versions/{v}"
    assert http.post(f"{base}/submit", headers=dave).status_code == 200
    r = http.post(f"{base}/approve", json={"role": "approver"}, headers=bob)
    assert r.status_code == 200, r.text
    if r.json()["state"] == "in_review":
        r = http.post(
            f"{base}/approve", json={"role": "security"}, headers=reg_headers(http, "carol")
        )
    assert (r.status_code, r.json()["state"]) == (200, "approved"), r.text
    return int(v)


def inference_status(http: httpx.Client) -> int:
    from tests.compose.test_inference_e2e import chat, inference_token

    return chat(http, inference_token(http), "ping").status_code


@pytest.fixture(scope="session", autouse=True)
def approved_alpha() -> Iterator[None]:
    if os.environ.get("ATF_COMPOSE") != "1":
        yield
        return
    import ssl

    from tests.compose.test_mcp_e2e import CA

    with httpx.Client(verify=ssl.create_default_context(cafile=str(CA)), timeout=15) as http:
        approve_new_version(http, BETA, beta_spec())
        approve_new_version(http)
        wait_until(lambda: inference_status(http) == 200, what="gateways to enforce bundle")
    yield
