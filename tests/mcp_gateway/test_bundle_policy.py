"""MCP gateway decisions over the signed bundle + Cedar (ADR-0022, ADR-0023)."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from atf_mcp_gateway.app import PolicyUnavailableError, bundle_authorizer, bundle_binder
from atf_mcp_gateway.servers import Delegation

from tests.exchange.conftest import (
    AGENT_BETA_CLIENT,
    AGENT_CLIENT,
    BASE,
    BOB,
    World,
    alpha_grant,
    beta_grant,
    egress_bundle,
    mint_t2,
    mint_workload,
)
from tests.mcp_gateway.test_proxy import BINDING, record
from tests.mcp_gateway.test_snapshot import TOOLS
from trustkit.binding import ActorBindingError, ActorBindingReason
from trustkit.jwt import TokenValidator, ValidationPolicy


def server(sid: str = "tickets", delegation: Delegation = Delegation.TOKEN) -> Any:
    """A server offering read and write; grants decide which the agent may request."""
    return dataclasses.replace(
        record(sid, TOOLS, delegation=delegation),
        scopes=frozenset({"tickets.read", "tickets.write"}),
    )


def workload_v(world: World) -> TokenValidator:
    return TokenValidator(
        ValidationPolicy(
            issuer=f"{BASE}/oauth2/workload",
            audiences=frozenset({"api://tool-gateway"}),
            expected_typ="at+jwt",
        ),
        world.jwks(f"{BASE}/oauth2/workload/v1/keys"),
        now=world.clock,
    )


def headers(world: World, agent: str = AGENT_CLIENT, t2: str | None = None) -> dict[str, str]:
    return {
        "authorization": f"Bearer {mint_workload(world, agent)}",
        "x-subject-token": t2 or mint_t2(world),
    }


class TestBinder:
    def test_binds_from_bundle(self, world: World) -> None:
        bind = bundle_binder(lambda: egress_bundle(), workload_v(world), world.jwks, world.clock)
        b = bind(headers(world))
        assert (b.agent_client_id, b.allowed_scopes) == (AGENT_CLIENT, frozenset({"tickets.read"}))

    @pytest.mark.security
    def test_no_bundle_is_policy_unavailable(self, world: World) -> None:
        bind = bundle_binder(lambda: None, workload_v(world), world.jwks, world.clock)
        with pytest.raises(PolicyUnavailableError):
            bind(headers(world))

    @pytest.mark.security
    def test_agent_not_in_bundle(self, world: World) -> None:
        bind = bundle_binder(
            lambda: egress_bundle(beta_grant()), workload_v(world), world.jwks, world.clock
        )
        with pytest.raises(ActorBindingError) as e:
            bind(headers(world))
        assert e.value.reason is ActorBindingReason.AGENT_NOT_ALLOWED

    @pytest.mark.security
    def test_confused_deputy_still_refused(self, world: World) -> None:
        both = egress_bundle(alpha_grant(), beta_grant())
        bind = bundle_binder(lambda: both, workload_v(world), world.jwks, world.clock)
        with pytest.raises(ActorBindingError) as e:
            bind(headers(world, AGENT_BETA_CLIENT))  # beta spending alpha's T2
        assert e.value.reason is ActorBindingReason.SUBJECT_INVALID

    @pytest.mark.parametrize(
        "h", [{}, {"authorization": "Bearer x"}, {"x-subject-token": "y"}, {"authorization": "x"}]
    )
    def test_missing_credentials(self, world: World, h: dict[str, str]) -> None:
        bind = bundle_binder(lambda: egress_bundle(), workload_v(world), world.jwks, world.clock)
        with pytest.raises(ValueError, match="credentials"):
            bind(h)


class TestAuthorizer:
    def binding(self, world: World, user: str | None = None) -> Any:
        bind = bundle_binder(lambda: egress_bundle(), workload_v(world), world.jwks, world.clock)
        return bind(headers(world, t2=mint_t2(world, user) if user else None))

    def test_allowed_returns_intersection(self, world: World) -> None:
        authorize = bundle_authorizer(lambda: egress_bundle(), world.clock)
        assert authorize(self.binding(world), server()) == frozenset({"tickets.read"})

    @pytest.mark.security
    def test_user_not_entitled(self, world: World) -> None:
        authorize = bundle_authorizer(lambda: egress_bundle(), world.clock)
        assert authorize(self.binding(world, BOB), server()) is None

    @pytest.mark.security
    def test_server_not_granted(self, world: World) -> None:
        authorize = bundle_authorizer(lambda: egress_bundle(), world.clock)
        assert authorize(self.binding(world), server("weather")) is None

    @pytest.mark.security
    def test_privileged_never_shared_credentials(self, world: World) -> None:
        priv = egress_bundle(alpha_grant(tier="privileged"))
        authorize = bundle_authorizer(lambda: priv, world.clock)
        b = self.binding(world)
        assert authorize(b, server()) is not None
        assert authorize(b, server(delegation=Delegation.NONE)) is None

    @pytest.mark.security
    def test_bundle_gone_mid_session_is_deny(self, world: World) -> None:
        state: dict[str, Any] = {"b": egress_bundle()}
        authorize = bundle_authorizer(lambda: state["b"], world.clock)
        b = self.binding(world)
        state["b"] = None
        assert authorize(b, server()) is None

    @pytest.mark.security
    def test_revoked_between_bind_and_call(self, world: World) -> None:
        """The agent was bound under bundle N; bundle N+1 removed it: the call is denied."""
        state: dict[str, Any] = {"b": egress_bundle()}
        authorize = bundle_authorizer(lambda: state["b"], world.clock)
        b = self.binding(world)
        state["b"] = egress_bundle(beta_grant())
        assert authorize(b, server()) is None

    def test_fake_binding_without_scope_claim(self, world: World) -> None:
        authorize = bundle_authorizer(lambda: egress_bundle(), world.clock)
        assert authorize(BINDING, server()) is None


@pytest.mark.security
class TestChains:
    """ADR-0024: B calling a tool on behalf of A, for the user."""

    def chain_bundle(self, **a_over: Any) -> Any:
        a = alpha_grant(**{"delegation": {"may_delegate_to": [AGENT_BETA_CLIENT]}, **a_over})
        b = beta_grant(delegation={"accepts_delegation_from": [AGENT_CLIENT]})
        return egress_bundle(a, b)

    def bind_b(self, world: World, bundle: Any) -> Any:
        from tests.exchange.test_chains import token_for_b

        bind = bundle_binder(lambda: bundle, workload_v(world), world.jwks, world.clock)
        return bind(headers(world, AGENT_BETA_CLIENT, t2=token_for_b(world)))

    def test_b_binds_with_prior_actor(self, world: World) -> None:
        b = self.bind_b(world, self.chain_bundle())
        assert (b.agent_client_id, b.prior_actors) == (AGENT_BETA_CLIENT, (AGENT_CLIENT,))

    def test_chain_allowed_when_every_actor_holds_the_grant(self, world: World) -> None:
        bundle = self.chain_bundle()
        authorize = bundle_authorizer(lambda: bundle, world.clock)
        assert authorize(self.bind_b(world, bundle), server()) == frozenset({"tickets.read"})

    def test_laundering_denied(self, world: World) -> None:
        bundle = self.chain_bundle(tools={})  # A has no ticket rights of its own
        authorize = bundle_authorizer(lambda: bundle, world.clock)
        assert authorize(self.bind_b(world, bundle), server()) is None

    def test_edge_removed_after_minting(self, world: World) -> None:
        state: dict[str, Any] = {"b": self.chain_bundle()}
        authorize = bundle_authorizer(lambda: state["b"], world.clock)
        b = self.bind_b(world, state["b"])
        state["b"] = self.chain_bundle(delegation={})
        assert authorize(b, server()) is None
