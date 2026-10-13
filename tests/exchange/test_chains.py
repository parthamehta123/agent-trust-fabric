"""Agent -> agent delegation chains through the real IdP (ADR-0024 §1-§2)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.exchange.conftest import (
    AGENT_BETA_CLIENT,
    AGENT_CLIENT,
    ALICE,
    BASE,
    GATEWAY_CLIENT,
    World,
    mint_t2,
    mint_workload,
)
from tests.exchange.test_egress import BETA_POLICY, claims, egress_profile, validators
from trustkit.binding import (
    ActorBinding,
    ActorBindingError,
    ActorBindingReason,
    bind_actor,
    expected_act,
    parse_act_chain,
)

A, B = AGENT_CLIENT, AGENT_BETA_CLIENT
ALPHA_WIDE = {
    A: {
        "t2_issuer": f"{BASE}/oauth2/agent-alpha",
        "t2_audience": "api://agent-alpha",
        "t2_jwks_uri": f"{BASE}/oauth2/agent-alpha/v1/keys",
        "allowed_scopes": ["agent.invoke", "tickets.read"],
    }
}


def to_beta_profile() -> Any:
    """A -> B: the gateway exchanges at B's AS (subject = A's T2, actor = A)."""
    return egress_profile(
        idp={
            "issuer": BASE,
            "jwks_uri": f"{BASE}/oauth2/v1/keys",
            "token_endpoint": f"{BASE}/oauth2/v1/token",
            "resource_issuer": f"{BASE}/oauth2/agent-beta",
            "resource_token_endpoint": f"{BASE}/oauth2/agent-beta/v1/token",
            "resource_jwks_uri": f"{BASE}/oauth2/agent-beta/v1/keys",
        },
        target={"audience": "api://agent-beta", "scopes": ["agent.invoke", "tickets.read"]},
        server_id="agent-beta",
    )


def bind_a(world: World) -> ActorBinding:
    wv, agents = validators(world, egress_profile(), ALPHA_WIDE)
    return bind_actor(mint_workload(world, A), mint_t2(world), workload_validator=wv, agents=agents)


def token_for_b(world: World) -> str:
    return world.exchanger.exchange_delegated(bind_a(world), to_beta_profile()).token


def bind_b(world: World, t_b: str, max_prior: int = 1) -> ActorBinding:
    wv, agents = validators(world, egress_profile(), {B: BETA_POLICY})
    return bind_actor(
        mint_workload(world, B),
        t_b,
        workload_validator=wv,
        agents=agents,
        max_prior_actors=max_prior,
    )


class TestChain:
    def test_a_to_b_token_names_user_and_a(self, world: World) -> None:
        c = claims(token_for_b(world))
        assert (c["sub"], c["aud"], c["act"], c["client_id"]) == (
            ALICE,
            "api://agent-beta",
            {"sub": A},
            GATEWAY_CLIENT,
        )
        assert c["iss"] == f"{BASE}/oauth2/agent-beta"

    def test_b_binds_with_a_as_prior_actor(self, world: World) -> None:
        b = bind_b(world, token_for_b(world))
        assert (b.agent_client_id, b.subject, b.prior_actors) == (B, ALICE, (A,))

    @pytest.mark.security
    def test_chains_refused_unless_enabled(self, world: World) -> None:
        with pytest.raises(ActorBindingError) as e:
            bind_b(world, token_for_b(world), max_prior=0)
        assert e.value.reason is ActorBindingReason.DELEGATION_CHAIN

    def test_tool_token_carries_nested_act(self, world: World) -> None:
        b = bind_b(world, token_for_b(world))
        c = claims(world.exchanger.exchange_delegated(b, egress_profile()).token)
        assert c["act"] == {"sub": B, "act": {"sub": A}}
        assert c["sub"] == ALICE

    @pytest.mark.security
    def test_chain_loop_refused_even_if_misconfigured(self, world: World) -> None:
        """A presents the token minted for B. Even with A misconfigured to accept B-audience
        tokens, the chain would make A act "for" itself: refused as a loop."""
        wv, agents = validators(world, egress_profile(), {A: BETA_POLICY})
        with pytest.raises(ActorBindingError) as e:
            bind_actor(
                mint_workload(world, A),
                token_for_b(world),
                workload_validator=wv,
                agents=agents,
                max_prior_actors=1,
            )
        assert e.value.reason is ActorBindingReason.DELEGATION_CHAIN

    @pytest.mark.security
    def test_correctly_configured_a_cannot_spend_b_token(self, world: World) -> None:
        wv, agents = validators(world, egress_profile(), ALPHA_WIDE)
        with pytest.raises(ActorBindingError) as e:
            bind_actor(
                mint_workload(world, A),
                token_for_b(world),
                workload_validator=wv,
                agents=agents,
                max_prior_actors=1,
            )
        assert e.value.reason is ActorBindingReason.SUBJECT_INVALID  # wrong audience for A

    @pytest.mark.security
    def test_idp_accepts_one_prior_actor_refuses_two(self, world: World) -> None:
        """IdP-side cap (ADR-0024 §2): a subject naming one actor may be delegated again
        (nested act); one naming two may not, and the refusal is about chain length."""
        from tests.mock_idp.test_delegation import delegate

        b_actor = mint_workload(world, B)
        ok = delegate(world, subject=token_for_b(world), actor=b_actor)
        assert ok.status == 200, ok.body
        assert claims(str(ok.body["access_token"]))["act"] == {"sub": B, "act": {"sub": A}}

        idp, now = world.idp, world.clock()
        deep = idp._sign(
            idp._server_keys["agent-beta"],
            "at+jwt",
            {
                "iss": idp.issuer("agent-beta"),
                "sub": ALICE,
                "aud": "api://agent-beta",
                "client_id": GATEWAY_CLIENT,
                "scope": "tickets.read",
                "jti": "j-deep",
                "iat": now,
                "exp": now + 300,
                "act": {"sub": B, "act": {"sub": A}},  # already two actors
            },
        )
        r = delegate(world, subject=deep, actor=b_actor)
        assert (r.status, r.body.get("error")) == (400, "invalid_grant"), r.body
        assert "chain" in str(r.body.get("error_description"))


class TestActChainParsing:
    @pytest.mark.parametrize(
        ("act", "chain"),
        [
            (None, ()),
            ({"sub": "a"}, ("a",)),
            ({"sub": "b", "act": {"sub": "a"}}, ("a", "b")),
        ],
    )
    def test_valid(self, act: Any, chain: tuple[str, ...]) -> None:
        assert parse_act_chain(act) == chain

    @pytest.mark.security
    @pytest.mark.parametrize(
        "act",
        [
            {},
            {"sub": ""},
            {"sub": 1},
            {"sub": "a", "client_id": "x"},  # unknown member
            {"sub": "a", "act": "b"},
            {"sub": "a", "act": None},  # explicit null is ambiguous
            {"sub": "a", "act": {"sub": "b", "act": {}}},
            "a",
            ["a"],
        ],
    )
    def test_malformed(self, act: Any) -> None:
        with pytest.raises(ValueError):  # noqa: PT011
            parse_act_chain(act)

    @pytest.mark.security
    def test_depth_bounded(self) -> None:
        act: dict[str, Any] = {"sub": "a0"}
        for i in range(1, 50):
            act = {"sub": f"a{i}", "act": act}
        with pytest.raises(ValueError):  # noqa: PT011
            parse_act_chain(act)

    def test_expected_act_nests_newest_outermost(self, world: World) -> None:
        b = bind_b(world, token_for_b(world))
        assert expected_act(b) == {"sub": B, "act": {"sub": A}}
        assert expected_act(bind_a(world)) == {"sub": A}


@pytest.mark.security
class TestSignedButMalformed:
    """Genuine signatures, hostile contents: binding must still refuse."""

    def sign(self, world: World, as_id: str, claims: dict[str, Any]) -> str:
        idp, now = world.idp, world.clock()
        base = {"iat": now, "exp": now + 300, "jti": f"j-{as_id}-{len(claims)}"}
        return idp._sign(idp._server_keys[as_id], "at+jwt", {**base, **claims})

    def test_malformed_act_in_valid_t2(self, world: World) -> None:
        t2 = self.sign(
            world,
            "agent-alpha",
            {
                "iss": world.idp.issuer("agent-alpha"),
                "sub": ALICE,
                "aud": "api://agent-alpha",
                "client_id": "0oa-chat",
                "scope": "agent.invoke",
                "act": {"sub": "x", "client_id": "smuggled"},
            },
        )
        wv, agents = validators(world, egress_profile(), ALPHA_WIDE)
        with pytest.raises(ActorBindingError) as e:
            bind_actor(
                mint_workload(world, A),
                t2,
                workload_validator=wv,
                agents=agents,
                max_prior_actors=1,
            )
        assert e.value.reason is ActorBindingReason.DELEGATION_CHAIN

    def test_workload_sub_must_equal_client_id(self, world: World) -> None:
        wl = self.sign(
            world,
            "workload",
            {
                "iss": world.idp.issuer("workload"),
                "sub": B,  # claims to be beta...
                "client_id": A,  # ...but was issued to alpha
                "aud": "api://tool-gateway",
                "scope": "tools.invoke",
            },
        )
        wv, agents = validators(world, egress_profile(), ALPHA_WIDE)
        with pytest.raises(ActorBindingError) as e:
            bind_actor(wl, mint_t2(world), workload_validator=wv, agents=agents)
        assert e.value.reason is ActorBindingReason.WORKLOAD_INVALID
