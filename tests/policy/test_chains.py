"""Delegation chains in Cedar: both-sides edges, no amplification, cards (ADR-0024 §3-§6)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.policy.helpers import loaded_bundle, make_grant
from trustkit_policy.grants import generate_permits
from trustkit_policy.runtime import delegate_decision, tool_decision, visible_card

A, B, C = "0oa-agent-alpha", "0oa-agent-beta", "0oa-agent-gamma"
T = 1_800_000_000
CARD = {
    "name": "Beta",
    "description": "Summarises tickets",
    "endpoint": "https://agent-beta.internal:8443/a2a",
    "skills": [{"id": "summarise", "name": "Summarise"}],
}


def a(**over: Any) -> Any:
    doc: dict[str, Any] = {"delegation": {"may_delegate_to": [B]}}
    doc.update(over)
    return make_grant(A, **doc)


def b(**over: Any) -> Any:
    doc: dict[str, Any] = {"delegation": {"accepts_delegation_from": [A]}, "card": CARD}
    doc.update(over)
    return make_grant(B, **doc)


def tool(loaded: Any, **over: Any) -> Any:
    args: dict[str, Any] = {
        "agent_id": B,
        "user": "alice",
        "user_scopes": frozenset({"tickets.read"}),
        "server_id": "tickets",
        "delegation": "token",
        "requested": frozenset({"tickets.read"}),
        "chain": (A,),
    }
    args.update(over)
    return tool_decision(loaded, **args)


def delegate(loaded: Any, frm: str = A, to: str = B) -> Any:
    return delegate_decision(
        loaded, from_agent=frm, to_agent=to, user="alice", user_scopes=frozenset({"tickets.read"})
    )


class TestEdges:
    def test_permit_only_when_both_sides_agree(self) -> None:
        text = generate_permits({A: a(), B: b()})
        assert f'@id("delegate:{A}->{B}")' in text
        assert delegate(loaded_bundle(a(), b())).allowed

    @pytest.mark.security
    @pytest.mark.parametrize(
        "grants",
        [
            pytest.param(lambda: (a(), b(delegation={})), id="b-does-not-accept"),
            pytest.param(lambda: (a(delegation={}), b()), id="a-does-not-offer"),
            pytest.param(lambda: (a(),), id="b-absent"),
        ],
    )
    def test_one_sided_edge_is_no_edge(self, grants: Any) -> None:
        loaded = loaded_bundle(*grants())
        assert "delegate:" not in loaded.bundle.policies
        assert not delegate(loaded).allowed

    def test_edges_are_directional(self) -> None:
        assert not delegate(loaded_bundle(a(), b()), frm=B, to=A).allowed


class TestNoAmplification:
    def test_allowed_when_both_actors_hold_the_grant(self) -> None:
        d = tool(loaded_bundle(a(), b()))
        assert d.allowed
        assert set(d.policy_ids) >= {
            f"grant:{B}:tool:tickets",
            f"grant:{A}:tool:tickets",
            f"delegate:{A}->{B}",
        }

    @pytest.mark.security
    def test_a_cannot_launder_access_through_b(self) -> None:
        """A has no ticket rights; B does. A asking B to read tickets for the user is denied."""
        assert not tool(loaded_bundle(a(tools={}), b())).allowed

    @pytest.mark.security
    def test_b_needs_its_own_grant_too(self) -> None:
        assert not tool(loaded_bundle(a(), b(tools={}))).allowed

    @pytest.mark.security
    def test_revoked_upstream_actor_kills_the_chain(self) -> None:
        """A revoked after minting B's token: the next hop re-checks and denies."""
        assert not tool(loaded_bundle(b())).allowed

    @pytest.mark.security
    def test_removed_edge_kills_the_chain(self) -> None:
        assert not tool(loaded_bundle(a(delegation={}), b())).allowed

    @pytest.mark.security
    def test_user_guardrail_still_applies(self) -> None:
        assert not tool(loaded_bundle(a(), b()), user_scopes=frozenset()).allowed

    @pytest.mark.security
    def test_two_prior_actors_refused(self) -> None:
        c = make_grant(C, delegation={"may_delegate_to": [A]})
        loaded = loaded_bundle(
            c, a(delegation={"may_delegate_to": [B], "accepts_delegation_from": [C]}), b()
        )
        assert not tool(loaded, chain=(C, A)).allowed


class TestCards:
    def test_visible_to_permitted_delegator_with_gateway_url(self) -> None:
        card = visible_card(
            loaded_bundle(a(), b()),
            viewer=A,
            agent_id=B,
            gateway_url="https://a2a-gateway:8443/agents/0oa-agent-beta",
            now=T,
        )
        assert card is not None
        assert card["name"] == "Beta"
        assert card["url"] == "https://a2a-gateway:8443/agents/0oa-agent-beta"
        assert "agent-beta.internal" not in str(card)  # runtime endpoint never disclosed
        assert [s["id"] for s in card["skills"]] == ["summarise"]  # type: ignore[index]

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("viewer", "grants"),
        [
            pytest.param(C, lambda: (a(), b(), make_grant(C)), id="unrelated-agent"),
            pytest.param(A, lambda: (a(), b(delegation={})), id="edge-not-mutual"),
            pytest.param(A, lambda: (a(), b(card=None)), id="no-card"),
            pytest.param(A, lambda: (a(),), id="target-revoked"),
        ],
    )
    def test_hidden(self, viewer: str, grants: Any) -> None:
        assert (
            visible_card(
                loaded_bundle(*grants()),
                viewer=viewer,
                agent_id=B,
                gateway_url="https://gw/agents/x",
                now=T,
            )
            is None
        )
