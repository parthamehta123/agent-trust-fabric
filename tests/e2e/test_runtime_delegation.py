"""Runtime-side validation of delegated tokens (ADR-0024 §5) and the tool-using agent."""

from __future__ import annotations

import json
from typing import Any

import pytest
from atf_agent_runtime.app import tool_agent

from tests.exchange.conftest import AGENT_BETA_CLIENT, AGENT_CLIENT, ALICE, BASE, World, mint_t2
from tests.exchange.test_chains import token_for_b
from trustkit.resource import AuthzFailure, Principal, ResourceAuthorizer, ResourceAuthzError

A, B = AGENT_CLIENT, AGENT_BETA_CLIENT


def beta_authz(world: World, accept: Any = None) -> ResourceAuthorizer:
    return ResourceAuthorizer(
        issuer=f"{BASE}/oauth2/agent-beta",
        audience="api://agent-beta",
        keys=world.jwks(f"{BASE}/oauth2/agent-beta/v1/keys"),
        now=world.clock,
        accept_actor=accept,
    )


@pytest.mark.security
class TestDelegatedTokens:
    def test_accepted_actor(self, world: World) -> None:
        p = beta_authz(world, accept=lambda a: a == A).authorize(
            f"Bearer {token_for_b(world)}", required_scope="agent.invoke"
        )
        assert (p.subject, p.actors) == (ALICE, (A,))

    def test_delegated_tokens_refused_by_default(self, world: World) -> None:
        """A runtime that hasn't opted in must not accept tokens naming any actor."""
        with pytest.raises(ResourceAuthzError) as e:
            beta_authz(world).authorize(
                f"Bearer {token_for_b(world)}", required_scope="agent.invoke"
            )
        assert e.value.failure is AuthzFailure.INVALID_TOKEN

    def test_actor_not_accepted_is_403(self, world: World) -> None:
        with pytest.raises(ResourceAuthzError) as e:
            beta_authz(world, accept=lambda a: False).authorize(
                f"Bearer {token_for_b(world)}", required_scope="agent.invoke"
            )
        assert (e.value.failure, e.value.status) == (AuthzFailure.ACTOR_NOT_ACCEPTED, 403)

    def test_two_prior_actors_refused(self, world: World) -> None:
        idp, now = world.idp, world.clock()
        deep = idp._sign(
            idp._server_keys["agent-beta"],
            "at+jwt",
            {
                "iss": idp.issuer("agent-beta"),
                "sub": ALICE,
                "aud": "api://agent-beta",
                "client_id": "0oa-tool-gateway",
                "scope": "agent.invoke",
                "jti": "j-deep-rt",
                "iat": now,
                "exp": now + 300,
                "act": {"sub": "0oa-x", "act": {"sub": A}},
            },
        )
        with pytest.raises(ResourceAuthzError) as e:
            beta_authz(world, accept=lambda a: True).authorize(
                f"Bearer {deep}", required_scope="agent.invoke"
            )
        assert e.value.failure is AuthzFailure.INVALID_TOKEN

    def test_plain_user_token_still_fine(self, world: World) -> None:
        """Alpha's runtime receiving a user's own T2 (no act) is unaffected."""
        authz = ResourceAuthorizer(
            issuer=f"{BASE}/oauth2/agent-alpha",
            audience="api://agent-alpha",
            keys=world.jwks(f"{BASE}/oauth2/agent-alpha/v1/keys"),
            now=world.clock,
        )
        assert (
            authz.authorize(f"Bearer {mint_t2(world)}", required_scope="agent.invoke").actors == ()
        )


class FakeMcp:
    def __init__(self, tools: list[str] | None = None, text: str = "ticket T-7 for alice") -> None:
        self.calls: list[tuple[str, dict[str, Any], dict[str, str]]] = []
        self.tools = tools if tools is not None else ["tickets-ab12__get_ticket"]
        self.text = text

    def __call__(self, url: str, payload: Any, headers: Any) -> tuple[int, Any]:
        self.calls.append((url, dict(payload), dict(headers)))
        if payload["method"] == "tools/list":
            return 200, {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"tools": [{"name": n} for n in self.tools]},
            }
        return 200, {
            "jsonrpc": "2.0",
            "id": payload["id"],
            "result": {"content": [{"type": "text", "text": self.text}]},
        }


PRINCIPAL = Principal(
    subject=ALICE,
    client_id="0oa-tool-gateway",
    scopes=frozenset({"agent.invoke"}),
    token_jti="j",
    actors=(A,),
)


class TestToolAgent:
    def agent(self, mcp: FakeMcp) -> Any:
        return tool_agent(
            mcp_url="https://mcp-gateway:8443/mcp", workload_token=lambda: "WL-B", post_json=mcp
        )

    def test_calls_tool_with_own_workload_and_inbound_subject(self) -> None:
        mcp = FakeMcp()
        out = self.agent(mcp)(PRINCIPAL, {"prompt": "please get ticket T-7"}, "T_B")
        assert out == {"output": "ticket T-7 for alice"}
        call = mcp.calls[-1]
        assert call[1]["params"] == {"name": "tickets-ab12__get_ticket", "arguments": {"id": "T-7"}}
        assert call[2] == {"Authorization": "Bearer WL-B", "X-Subject-Token": "T_B"}

    @pytest.mark.security
    def test_tokens_never_in_output(self) -> None:
        out = self.agent(FakeMcp())(PRINCIPAL, {"prompt": "get ticket T-1"}, "T_B-SECRET")
        assert "T_B-SECRET" not in json.dumps(out)
        assert "WL-B" not in json.dumps(out)

    @pytest.mark.parametrize("prompt", ["hello", "", "get ticket", "ticket TT-1", 7])
    def test_non_ticket_prompts_refused(self, prompt: Any) -> None:
        mcp = FakeMcp()
        out = self.agent(mcp)(PRINCIPAL, {"prompt": prompt}, "T_B")
        assert out == {"output": "I can only fetch tickets (e.g. 'get ticket T-7')."}
        assert mcp.calls == []

    def test_no_ticket_tool_available(self) -> None:
        out = self.agent(FakeMcp(tools=[]))(PRINCIPAL, {"prompt": "get ticket T-7"}, "T_B")
        assert out == {"output": "No ticket tool is available to me for you."}

    def test_tool_error_is_generic(self) -> None:
        def denied(url: str, payload: Any, headers: Any) -> tuple[int, Any]:
            if payload["method"] == "tools/list":
                return 200, {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"tools": [{"name": "t__get_ticket"}]},
                }
            return 200, {
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"code": -32602, "message": "unknown tool"},
            }

        out = tool_agent(mcp_url="https://m/mcp", workload_token=lambda: "w", post_json=denied)(
            PRINCIPAL, {"prompt": "get ticket T-7"}, "T_B"
        )
        assert out == {"output": "The ticket tool refused the request."}


@pytest.mark.security
class TestRuntimeWiring:
    def env(self, tmp_path: Any, **extra: str) -> dict[str, str]:
        from tests.inference.test_wiring import _ca_pem
        from tests.policy.test_bundle import SIGNER

        (tmp_path / "ca.pem").write_bytes(_ca_pem())
        (tmp_path / "k.jwk").write_text(json.dumps(SIGNER.public_jwk()))
        return {
            "ATF_RESOURCE_ISSUER": f"{BASE}/oauth2/agent-beta",
            "ATF_RESOURCE_AUDIENCE": "api://agent-beta",
            "ATF_RESOURCE_JWKS_URI": f"{BASE}/oauth2/agent-beta/v1/keys",
            "ATF_CA_BUNDLE": str(tmp_path / "ca.pem"),
            "ATF_AGENT_ID": B,
            "ATF_BUNDLE_ISSUER": "atf-bundle-publisher",
            "ATF_BUNDLE_PUBLIC_JWK_PATH": str(tmp_path / "k.jwk"),
            "ATF_BUNDLE_PATH": str(tmp_path / "bundle.jws"),
            **extra,
        }

    def publish(self, tmp_path: Any) -> None:
        import time

        from tests.exchange.conftest import alpha_grant, beta_grant
        from tests.policy.helpers import GUARDRAILS
        from tests.policy.test_bundle import SIGNER
        from trustkit_policy.bundle import Bundle, sign_bundle
        from trustkit_policy.grants import generate_permits

        gs = {
            A: alpha_grant(delegation={"may_delegate_to": [B]}),
            B: beta_grant(delegation={"accepts_delegation_from": [A]}),
        }
        now = int(time.time())
        b = Bundle(
            iss="atf-bundle-publisher",
            bundle_version=1,
            iat=now,
            exp=now + 600,
            agents=gs,
            policies=generate_permits(gs) + "\n" + GUARDRAILS,
        )
        (tmp_path / "bundle.jws").write_bytes(sign_bundle(b, SIGNER))

    def test_accepts_only_mutual_edge(self, tmp_path: Any) -> None:
        from atf_agent_runtime.app import build_runtime_from_env

        self.publish(tmp_path)
        rt = build_runtime_from_env(self.env(tmp_path))
        accept = rt.authorizer._accept_actor
        assert accept is not None
        assert accept(A)
        assert not accept("0oa-stranger")

    def test_no_bundle_refuses_every_actor(self, tmp_path: Any) -> None:
        from atf_agent_runtime.app import build_runtime_from_env

        rt = build_runtime_from_env(self.env(tmp_path))
        accept = rt.authorizer._accept_actor
        assert accept is not None
        assert not accept(A)

    def test_without_agent_id_delegation_is_off(self, tmp_path: Any) -> None:
        from atf_agent_runtime.app import build_runtime_from_env

        env = {
            k: v
            for k, v in self.env(tmp_path).items()
            if not k.startswith("ATF_BUNDLE_") and k != "ATF_AGENT_ID"
        }
        assert build_runtime_from_env(env).authorizer._accept_actor is None

    def test_tool_agent_selected_with_mcp_url(self, tmp_path: Any) -> None:
        from atf_agent_runtime.app import build_runtime_from_env, echo_agent
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        keys = tmp_path / "keys"
        keys.mkdir()
        (keys / "agent-beta.pem").write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        env = self.env(
            tmp_path,
            ATF_ENV="local",
            ATF_MCP_URL="https://mcp-gateway:8443/mcp",
            ATF_WORKLOAD_SIGNING_KEY="local:agent-beta",
            ATF_LOCAL_KEYS_DIR=str(keys),
            ATF_WORKLOAD_CLIENT_ID=B,
            ATF_WORKLOAD_TOKEN_ENDPOINT=f"{BASE}/oauth2/workload/v1/token",
        )
        assert build_runtime_from_env(env).agent is not echo_agent


@pytest.mark.security
def test_malformed_act_refused_even_when_opted_in(world: World) -> None:
    idp, now = world.idp, world.clock()
    bad = idp._sign(
        idp._server_keys["agent-beta"],
        "at+jwt",
        {
            "iss": idp.issuer("agent-beta"),
            "sub": ALICE,
            "aud": "api://agent-beta",
            "client_id": "0oa-tool-gateway",
            "scope": "agent.invoke",
            "jti": "j-bad-act",
            "iat": now,
            "exp": now + 300,
            "act": {"sub": A, "client_id": "smuggled"},
        },
    )
    with pytest.raises(ResourceAuthzError) as e:
        beta_authz(world, accept=lambda a: True).authorize(
            f"Bearer {bad}", required_scope="agent.invoke"
        )
    assert e.value.failure is AuthzFailure.INVALID_TOKEN
