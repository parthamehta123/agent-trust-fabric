"""A2A gateway HTTP surface (ADR-0024)."""

from __future__ import annotations

from typing import Any

import pytest
from atf_a2a_gateway.app import PolicyUnavailableError, create_app
from fastapi.testclient import TestClient

from tests.a2a.test_broker import GATEWAY, A, B, Rig, a_grant, b_grant
from tests.exchange.conftest import World, mint_t2, mint_workload
from trustkit.binding import ActorBindingError, ActorBindingReason


def rpc(text: Any = "get ticket T-7", rid: Any = 1, **over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": "m-1",
                "parts": [{"kind": "text", "text": text}],
            }
        },
    }
    body.update(over)
    return body


@pytest.fixture
def client(world: World) -> tuple[TestClient, Rig]:
    rig = Rig(world)

    def binder(headers: Any) -> Any:
        if headers.get("x-test-policy") == "down":
            raise PolicyUnavailableError
        if not headers.get("authorization", "").startswith("Bearer ") or not headers.get(
            "x-subject-token"
        ):
            raise ValueError("missing credentials")
        if headers.get("x-test-bind") == "deny":
            raise ActorBindingError(ActorBindingReason.AGENT_NOT_ALLOWED)
        return rig.binding()

    def viewer(headers: Any) -> str:
        if not headers.get("authorization", "").startswith("Bearer "):
            raise ValueError("missing credentials")
        return str(headers.get("x-test-viewer", A))

    return TestClient(create_app(rig.broker, binder, viewer)), rig


def auth(world: World) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {mint_workload(world, A)}",
        "X-Subject-Token": mint_t2(world),
    }


class TestSend:
    def test_message_send(self, client: Any, world: World) -> None:
        c, _ = client
        r = c.post(f"/agents/{B}/a2a", json=rpc(rid="r-9"), headers=auth(world))
        assert r.status_code == 200, r.text
        j = r.json()
        assert (j["jsonrpc"], j["id"]) == ("2.0", "r-9")
        res = j["result"]
        assert (res["kind"], res["role"]) == ("message", "agent")
        assert res["parts"] == [{"kind": "text", "text": "ticket T-7 is open"}]
        assert res["messageId"]

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("headers", "status", "code"),
        [
            ({}, 401, -32001),
            ({"Authorization": "Bearer x"}, 401, -32001),
            (
                {"Authorization": "Bearer x", "X-Subject-Token": "y", "X-Test-Bind": "deny"},
                401,
                -32001,
            ),
            (
                {"Authorization": "Bearer x", "X-Subject-Token": "y", "X-Test-Policy": "down"},
                503,
                -32002,
            ),
        ],
    )
    def test_auth_failures(
        self, client: Any, headers: dict[str, str], status: int, code: int
    ) -> None:
        c, rig = client
        r = c.post(f"/agents/{B}/a2a", json=rpc(), headers=headers)
        assert (r.status_code, r.json()["error"]["code"]) == (status, code)
        assert rig.upstream.calls == []

    @pytest.mark.security
    def test_auth_before_body(self, client: Any) -> None:
        c, _ = client
        assert c.post(f"/agents/{B}/a2a", content=b"{not json").status_code == 401

    @pytest.mark.parametrize(
        "body",
        [
            rpc(method="tasks/get"),
            rpc(jsonrpc="1.0"),
            rpc(params={}),
            rpc(params={"message": {"role": "user", "parts": []}}),
            rpc(params={"message": {"role": "user", "parts": [{"kind": "file", "uri": "x"}]}}),
            rpc(text=7),
            [rpc()],
        ],
    )
    def test_invalid_requests(self, client: Any, world: World, body: Any) -> None:
        c, rig = client
        r = c.post(f"/agents/{B}/a2a", json=body, headers=auth(world))
        assert r.status_code == 400
        assert rig.upstream.calls == []

    @pytest.mark.security
    def test_denials_are_typed_and_bare(self, world: World) -> None:
        rig = Rig(world, a_grant(delegation={}), b_grant())
        c = TestClient(create_app(rig.broker, lambda h: rig.binding(), lambda h: A))
        r = c.post(f"/agents/{B}/a2a", json=rpc(), headers=auth(world))
        assert r.status_code == 403
        assert r.json()["error"] == {"code": -32003, "message": "delegation_denied"}

    @pytest.mark.security
    def test_duplicate_headers(self, client: Any, world: World) -> None:
        c, _ = client
        h = auth(world)
        r = c.post(
            f"/agents/{B}/a2a",
            json=rpc(),
            headers=[("Authorization", h["Authorization"]), ("authorization", "Bearer evil")],
        )
        assert r.status_code == 400


class TestCards:
    def test_card(self, client: Any) -> None:
        c, _ = client
        r = c.get(f"/agents/{B}/.well-known/agent-card.json", headers={"Authorization": "Bearer w"})
        assert r.status_code == 200
        assert r.json()["url"] == f"{GATEWAY}/agents/{B}/a2a"

    @pytest.mark.security
    def test_card_requires_auth(self, client: Any) -> None:
        c, _ = client
        assert c.get(f"/agents/{B}/.well-known/agent-card.json").status_code == 401

    @pytest.mark.security
    def test_hidden_card_is_404(self, client: Any) -> None:
        c, _ = client
        r = c.get(
            f"/agents/{B}/.well-known/agent-card.json",
            headers={"Authorization": "Bearer w", "X-Test-Viewer": "0oa-nobody"},
        )
        assert (r.status_code, r.json()) == (404, {"error": "unknown_agent"})


def test_ping(client: Any) -> None:
    c, _ = client
    assert c.get("/ping").json() == {"status": "ok"}


class TestBuildApp:
    @pytest.fixture
    def env(self, tmp_path: Any) -> dict[str, str]:
        import json

        from tests.a2a.test_broker import egress_base
        from tests.inference.test_wiring import _ca_pem
        from tests.policy.test_bundle import SIGNER

        (tmp_path / "ca.pem").write_bytes(_ca_pem())
        (tmp_path / "k.jwk").write_text(json.dumps(SIGNER.public_jwk()))
        (tmp_path / "egress.json").write_text(json.dumps(egress_base()))
        return {
            "ATF_ENV": "local",
            "ATF_A2A_EGRESS_PROFILE_PATH": str(tmp_path / "egress.json"),
            "ATF_A2A_PUBLIC_URL": "https://a2a-gateway:8443/",
            "ATF_A2A_TARGET_SCOPES": "agent.invoke tickets.read",
            "ATF_CA_BUNDLE": str(tmp_path / "ca.pem"),
            "ATF_BUNDLE_ISSUER": "atf-bundle-publisher",
            "ATF_BUNDLE_PUBLIC_JWK_PATH": str(tmp_path / "k.jwk"),
            "ATF_BUNDLE_PATH": str(tmp_path / "bundle.jws"),
            "ATF_LOCAL_KEYS_DIR": str(tmp_path),
            "ATF_SSRF_ALLOW_CIDRS": "10.232.0.0/16",
        }

    def test_wired(self, env: dict[str, str]) -> None:
        from atf_a2a_gateway.app import build_app

        c = TestClient(build_app(env))
        assert c.get("/ping").status_code == 200
        assert c.post(f"/agents/{B}/a2a", json=rpc()).status_code == 401
        assert c.get(f"/agents/{B}/.well-known/agent-card.json").status_code == 401
        bad = {"Authorization": "Bearer not-a-jwt"}
        assert c.get(f"/agents/{B}/.well-known/agent-card.json", headers=bad).status_code == 401
        r = c.post(f"/agents/{B}/a2a", json=rpc(), headers={**bad, "X-Subject-Token": "y"})
        assert r.status_code in (401, 503)  # no bundle yet, or token refused: never a send

    @pytest.mark.security
    def test_ssrf_allowlist_refused_outside_local(self, env: dict[str, str]) -> None:
        from atf_a2a_gateway.app import build_app

        from trustkit_http.ssrf import SsrfConfigError

        with pytest.raises(SsrfConfigError):
            build_app({**env, "ATF_ENV": "prod"})

    @pytest.mark.parametrize(
        "missing", ["ATF_A2A_PUBLIC_URL", "ATF_A2A_TARGET_SCOPES", "ATF_BUNDLE_ISSUER"]
    )
    def test_required_env(self, env: dict[str, str], missing: str) -> None:
        from atf_a2a_gateway.app import build_app

        with pytest.raises(KeyError):
            build_app({k: v for k, v in env.items() if k != missing})

    def test_app_from_env(self, env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
        from atf_a2a_gateway.app import app_from_env

        for k, v in env.items():
            monkeypatch.setenv(k, v)
        assert TestClient(app_from_env()).get("/ping").status_code == 200
