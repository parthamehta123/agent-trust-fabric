"""Registry -> signed bundle -> gateway enforcement, end to end (ADR-0021/0022/0023).

Local ages: publisher heartbeat 5 s, bundle max age 20 s, gateway refresh 2 s. Every scenario
leaves agent-alpha approved again so the suites stay independent.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx
import pytest

from tests.compose.conftest import (
    AGENT,
    REGISTRY,
    alpha_spec,
    approve_new_version,
    inference_status,
    reg_headers,
    wait_until,
)
from tests.compose.test_mcp_e2e import (
    DATA,
    ROOT,
    _compose,
    admin_token,
    http,  # noqa: F401 - fixture
    t2_for,
    workload_token,
)

pytestmark = [
    pytest.mark.compose,
    pytest.mark.skipif(os.environ.get("ATF_COMPOSE") != "1", reason="needs the compose stack"),
]

BUNDLE_FILE = ROOT / ".local-ca" / "bundles" / "bundle.jws"


def mcp_status(http: httpx.Client) -> int:  # noqa: F811
    """The MCP binder's verdict for agent-alpha: 200 bound, 401 not in bundle, 503 no bundle."""
    r = http.post(
        DATA,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "Authorization": f"Bearer {workload_token(http)}",
            "X-Subject-Token": t2_for(http),
        },
    )
    return r.status_code


def both(http: httpx.Client) -> tuple[int, int]:  # noqa: F811
    return inference_status(http), mcp_status(http)


def restart_publisher() -> None:
    # --no-deps --no-recreate: some Compose versions (GitHub runners) otherwise recreate the
    # publisher's dependencies, and a recreated mock IdP mints with new keys that every gateway's
    # cached JWKS rejects (seen as 401s that no wait could fix).
    _compose("start", "bundle-publisher")
    _compose("up", "-d", "--no-deps", "--no-recreate", "--wait", "bundle-publisher")


def restore(http: httpx.Client) -> None:  # noqa: F811
    approve_new_version(http)
    wait_until(lambda: both(http) == (200, 200), what="access restored")


# ----------------------------------------------------------------------------- workflow


class TestWorkflowOverHttps:
    SCRATCH = "0oa-agent-scratch"

    def test_two_person_rule_and_roles(self, http: httpx.Client) -> None:  # noqa: F811
        dave, bob, carol = (reg_headers(http, w) for w in ("dave", "bob", "carol"))
        spec = alpha_spec(display_name="Scratch", ingress=None, tools={}, models={}, delegation={})
        r = http.post(f"{REGISTRY}/{self.SCRATCH}/versions", json=spec, headers=dave)
        assert r.status_code == 201, r.text
        v = r.json()["version"]
        base = f"{REGISTRY}/{self.SCRATCH}/versions/{v}"
        assert http.post(f"{base}/submit", headers=dave).status_code == 200
        approve = {"role": "approver"}
        assert http.post(f"{base}/approve", json=approve, headers=dave).status_code == 403
        r = http.post(f"{base}/approve", json={"role": "security"}, headers=carol)
        assert r.status_code == 400  # security isn't a required role for standard
        r = http.post(f"{base}/approve", json=approve, headers=bob)
        assert r.json()["state"] == "approved"
        assert http.post(f"{REGISTRY}/{self.SCRATCH}/revoke", headers=bob).status_code == 403
        r = http.post(f"{REGISTRY}/{self.SCRATCH}/revoke", headers=carol)
        assert r.json()["state"] == "revoked"

    @pytest.mark.security
    def test_outsider_cannot_create(self, http: httpx.Client) -> None:  # noqa: F811
        r = http.post(
            f"{REGISTRY}/0oa-agent-x/versions", json=alpha_spec(), headers=reg_headers(http, "bob")
        )
        assert r.status_code == 403  # bob approves, but isn't on team-alpha

    @pytest.mark.security
    def test_mcp_admin_token_rejected(self, http: httpx.Client) -> None:  # noqa: F811
        """Separate control planes: an MCP admin credential is useless at the registry."""
        r = http.get(
            f"{REGISTRY}/{AGENT}/versions",
            headers={"Authorization": f"Bearer {admin_token(http, 'alice')}"},
        )
        assert r.status_code == 401


# ----------------------------------------------------------------------------- lifecycle


@pytest.mark.security
class TestLifecycle:
    def test_revocation_reaches_every_gateway(self, http: httpx.Client) -> None:  # noqa: F811
        assert both(http) == (200, 200)
        r = http.post(f"{REGISTRY}/{AGENT}/revoke", headers=reg_headers(http, "carol"))
        assert r.json()["state"] == "revoked"
        started = time.monotonic()
        wait_until(lambda: both(http) == (403, 401), timeout=15, what="revocation enforced")
        assert time.monotonic() - started < 15
        restore(http)

    def test_rollback_attack_rejected(self, http: httpx.Client) -> None:  # noqa: F811
        """Write an older, validly signed bundle (agent allowed) back after **every gateway has
        seen** the revocation: they keep the newer bundle, the agent stays denied, and the
        attempt is audited. (A gateway that never saw the newer bundle can't detect a replay;
        that window is bounded by the max age, RR-6.)"""
        allowed_bundle = BUNDLE_FILE.read_bytes()
        http.post(f"{REGISTRY}/{AGENT}/revoke", headers=reg_headers(http, "carol"))
        wait_until(lambda: both(http) == (403, 401), timeout=15, what="revocation at both")
        _compose("stop", "bundle-publisher")  # so it doesn't overwrite our replay
        try:
            tmp = BUNDLE_FILE.with_suffix(".replay")
            tmp.write_bytes(allowed_bundle)
            tmp.replace(BUNDLE_FILE)
            time.sleep(5)  # > 2 gateway refreshes, well inside the 20 s max age
            assert both(http) == (403, 401), "rollback must not restore access"
            logs = _compose("logs", "--no-color", "inference-gateway", "mcp-gateway")
            assert logs.count("rejected_rollback") >= 2  # both gateways refused and audited it
        finally:
            restart_publisher()
            restore(http)

    def test_publisher_death_fails_closed(self, http: httpx.Client) -> None:  # noqa: F811
        assert both(http) == (200, 200)
        _compose("stop", "bundle-publisher")
        try:
            wait_until(lambda: both(http) == (503, 503), timeout=45, what="fail closed")
            from tests.compose.test_inference_e2e import chat, inference_token

            body: Any = chat(http, inference_token(http), "hi").json()
            assert body == {"error": {"type": "policy_unavailable"}}
        finally:
            restart_publisher()
            wait_until(lambda: both(http) == (200, 200), what="recovery after restart")


# ----------------------------------------------------------------------------- isolation


@pytest.mark.security
class TestIsolation:
    @pytest.mark.parametrize(
        ("service", "target"),
        [
            ("bundle-publisher", "mock-idp"),  # signer reaches only its table
            ("bundle-publisher", "inference-gateway"),
            ("inference-gateway", "agent-registry"),  # data planes can't reach the registry
            ("mcp-gateway", "agent-registry"),
            ("agent-registry", "mcp-admin"),  # admin planes don't share networks
        ],
    )
    def test_unreachable(self, service: str, target: str) -> None:
        probe = (
            "import socket,sys\n"
            "try:\n"
            f"    socket.create_connection(({target!r}, 8443), timeout=2)\n"
            "except OSError:\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        _compose("exec", "-T", service, "python", "-c", probe)

    @pytest.mark.parametrize("service", ["inference-gateway", "mcp-gateway"])
    def test_gateways_cannot_write_bundles(self, service: str) -> None:
        probe = (
            "import sys\n"
            "try:\n"
            "    open('/run/bundles/bundle.jws', 'ab').close()\n"
            "except OSError:\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        _compose("exec", "-T", service, "python", "-c", probe)

    def test_signing_key_only_in_publisher(self) -> None:
        for service in ("agent-registry", "inference-gateway", "mcp-gateway", "interceptor"):
            probe = "import os,sys; sys.exit(1 if os.path.exists('/run/keys/bundle.pem') else 0)"
            _compose("exec", "-T", service, "python", "-c", probe)

    def test_interceptor_has_only_its_own_key(self) -> None:
        probe = "import os; print(sorted(os.listdir('/run/keys')))"
        assert (
            _compose("exec", "-T", "interceptor", "python", "-c", probe).strip() == "['chat.pem']"
        )
