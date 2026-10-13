"""Knowledge authorization in Cedar and the server-side filter (ADR-0025 §2-§3)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.policy.helpers import loaded_bundle, make_grant
from trustkit_policy.grants import classification_rank, generate_permits
from trustkit_policy.runtime import (
    RetrievalFilter,
    document_decision,
    knowledge_filter,
    user_collections,
)

A, B = "0oa-agent-alpha", "0oa-agent-beta"
T = 1_800_000_000


def kb(*collections: str, ceiling: str = "confidential") -> dict[str, Any]:
    return {"collections": list(collections), "max_classification": ceiling}


def a(**over: Any) -> Any:
    doc: dict[str, Any] = {"knowledge": kb("eng", "hr"), "delegation": {"may_delegate_to": [B]}}
    doc.update(over)
    return make_grant(A, **doc)


def b(**over: Any) -> Any:
    doc: dict[str, Any] = {
        "knowledge": kb("eng", "hr", "finance", ceiling="restricted"),
        "delegation": {"accepts_delegation_from": [A]},
    }
    doc.update(over)
    return make_grant(B, **doc)


def decide(loaded: Any, **over: Any) -> Any:
    args: dict[str, Any] = {
        "agent_id": A,
        "chain": (),
        "user": "alice",
        "user_collections": frozenset({"eng", "hr"}),
        "collection": "eng",
        "classification": "internal",
    }
    args.update(over)
    return document_decision(loaded, **args)


class TestUserCollections:
    @pytest.mark.parametrize(
        ("scopes", "want"),
        [
            ({"kb.eng.read", "kb.hr.read", "agent.invoke"}, {"eng", "hr"}),
            ({"kb.eng.write", "kb..read", "kb.Eng.read", "kb.eng.read.x"}, set()),
            (set(), set()),
        ],
    )
    def test_parse(self, scopes: set[str], want: set[str]) -> None:
        assert user_collections(frozenset(scopes)) == frozenset(want)


class TestRank:
    def test_order(self) -> None:
        assert [
            classification_rank(c) for c in ("public", "internal", "confidential", "restricted")
        ] == [0, 1, 2, 3]

    def test_unknown_is_error_not_default(self) -> None:
        with pytest.raises(ValueError):  # noqa: PT011
            classification_rank("secret")


class TestFilter:
    def test_user_intersect_agent(self) -> None:
        f = knowledge_filter(
            loaded_bundle(a()),
            agent_id=A,
            chain=(),
            user_collections=frozenset({"eng", "finance"}),
            now=T,
        )
        assert f == RetrievalFilter(collections=frozenset({"eng"}), max_rank=2)

    @pytest.mark.security
    def test_chain_intersects_every_actor_and_takes_lowest_ceiling(self) -> None:
        """B (restricted, has finance) acting for A (confidential, no finance)."""
        f = knowledge_filter(
            loaded_bundle(a(), b()),
            agent_id=B,
            chain=(A,),
            user_collections=frozenset({"eng", "hr", "finance"}),
            now=T,
        )
        assert f == RetrievalFilter(collections=frozenset({"eng", "hr"}), max_rank=2)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "case",
        ["user-has-nothing", "agent-no-knowledge", "agent-absent", "expired", "chain-actor-absent"],
    )
    def test_nothing_retrievable_is_none(self, case: str) -> None:
        loaded, agent, chain, users = loaded_bundle(a()), A, (), frozenset({"eng"})
        if case == "user-has-nothing":
            users = frozenset()
        elif case == "agent-no-knowledge":
            loaded = loaded_bundle(a(knowledge=None))
        elif case == "agent-absent":
            agent = "0oa-nobody"
        elif case == "expired":
            loaded = loaded_bundle(a(expires_at=T))
        elif case == "chain-actor-absent":
            loaded, agent, chain = loaded_bundle(b()), B, (A,)
        assert (
            knowledge_filter(loaded, agent_id=agent, chain=chain, user_collections=users, now=T)
            is None
        )


class TestDocumentDecision:
    def test_permits_generated(self) -> None:
        text = generate_permits({A: a()})
        assert f'@id("grant:{A}:knowledge")' in text

    def test_allowed(self) -> None:
        d = decide(loaded_bundle(a()))
        assert d.allowed
        assert d.policy_ids == (f"grant:{A}:knowledge",)

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("over", "reason"),
        [
            ({"collection": "finance"}, "collection-not-granted"),
            ({"classification": "restricted"}, "above-ceiling"),
            ({"user_collections": frozenset({"hr"})}, "user-lacks-collection"),
            ({"classification": "top-secret"}, "unknown-label"),
        ],
    )
    def test_denied(self, over: dict[str, Any], reason: str) -> None:
        assert not decide(loaded_bundle(a()), **over).allowed, reason

    @pytest.mark.security
    def test_user_guardrail_named(self) -> None:
        d = decide(loaded_bundle(a()), user_collections=frozenset({"hr"}))
        assert "guardrail:user-collections" in d.policy_ids

    @pytest.mark.security
    def test_chain_no_amplification(self) -> None:
        """B can read finance; A can't: B reading finance *for A* is denied."""
        loaded = loaded_bundle(a(), b())
        args = {"agent_id": B, "chain": (A,), "user_collections": frozenset({"finance", "eng"})}
        assert decide(loaded, **args, collection="eng").allowed
        assert not decide(loaded, **args, collection="finance").allowed

    @pytest.mark.security
    def test_chain_needs_live_edge(self) -> None:
        loaded = loaded_bundle(a(delegation={}), b())
        assert not decide(loaded, agent_id=B, chain=(A,), collection="eng").allowed


@pytest.mark.security
@pytest.mark.parametrize("chain", [(A, B), (B,)], ids=["too-long", "loop"])
def test_chain_shape_refused(chain: tuple[str, ...]) -> None:
    loaded = loaded_bundle(a(), b())
    assert (
        knowledge_filter(
            loaded, agent_id=B, chain=chain, user_collections=frozenset({"eng"}), now=T
        )
        is None
    )
    assert not decide(loaded, agent_id=B, chain=chain).allowed
