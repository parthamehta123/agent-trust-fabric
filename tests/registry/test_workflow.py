"""Registry workflow (ADR-0021): roles, tiered approval, versions, revocation, audit, races."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from atf_agent_registry.records import (
    AgentSpec,
    AgentVersion,
    ApprovalRole,
    InMemoryRegistryStore,
    State,
    StoreConflictError,
)
from atf_agent_registry.workflow import (
    APPROVERS_GROUP,
    SECURITY_GROUP,
    Failure,
    Principal,
    RegistryError,
    RegistryService,
    authorize,
    eligible_roles,
)
from joserfc.jwk import RSAKey

from tests.conftest import NOW, Mint, StaticKeys, good_claims
from trustkit.audit import AuditEvent, Decision
from trustkit.jwt import TokenValidator, ValidationPolicy

AGENT = "0oa-agent-alpha"
T0 = dt.datetime(2026, 10, 13, 12, 0, tzinfo=dt.UTC)

DAVE = Principal("dave", frozenset({"team-alpha"}))  # author
ALICE = Principal("alice", frozenset({"team-alpha", APPROVERS_GROUP}))  # owner-eligible
BOB = Principal("bob", frozenset({APPROVERS_GROUP}))  # approver, not on the team
CAROL = Principal("carol", frozenset({SECURITY_GROUP}))
EVE = Principal("eve", frozenset({"team-beta"}))
FRANK = Principal("frank", frozenset({"team-alpha", "team-beta"}))
MALLORY = Principal("mallory", frozenset({"team-alpha", APPROVERS_GROUP, SECURITY_GROUP}))


def spec(**over: Any) -> AgentSpec:
    doc: dict[str, Any] = {
        "display_name": "Alpha",
        "owner_team": "alpha",
        "tier": "standard",
        "tools": {"tickets": ["tickets.read"]},
        "models": {"claude-sonnet": {"daily_token_budget": 1000, "max_output_tokens": 256}},
    }
    doc.update(over)
    return AgentSpec.model_validate_json(json.dumps(doc))


class Sink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.fail = False

    def emit(self, event: AuditEvent) -> None:
        if self.fail:
            raise OSError("audit sink down")
        self.events.append(event)


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> dt.datetime:
        return self.t


class Env:
    def __init__(self) -> None:
        self.store, self.audit, self.clock = InMemoryRegistryStore(), Sink(), Clock()
        self.svc = RegistryService(self.store, self.audit, now=self.clock)

    def approved(self, s: AgentSpec | None = None, author: Principal = DAVE) -> AgentVersion:
        v = self.svc.create_draft(author, AGENT, s or spec())
        self.svc.submit(author, AGENT, v.version)
        if v.spec.tier == "standard":
            out = self.svc.approve(BOB, AGENT, v.version, ApprovalRole.APPROVER)
            if out.state is State.IN_REVIEW:  # an added delegation edge needs security too
                out = self.svc.approve(CAROL, AGENT, v.version, ApprovalRole.SECURITY)
            return out
        self.svc.approve(ALICE, AGENT, v.version, ApprovalRole.OWNER)
        return self.svc.approve(CAROL, AGENT, v.version, ApprovalRole.SECURITY)


def fails(failure: Failure, fn: Any, *args: Any) -> None:
    with pytest.raises(RegistryError) as e:
        fn(*args)
    assert e.value.failure is failure, e.value


@pytest.fixture
def env() -> Env:
    return Env()


# ----------------------------------------------------------------------------- identity


class TestAuthorize:
    @pytest.fixture
    def validator(self, rsa_key: RSAKey) -> TokenValidator:
        from tests.conftest import AUDIENCE, ISSUER

        return TokenValidator(
            ValidationPolicy(issuer=ISSUER, audiences=frozenset({AUDIENCE}), expected_typ="at+jwt"),
            StaticKeys(rsa_key),
            now=lambda: NOW,
        )

    def bearer(self, mint: Mint, **over: Any) -> str:
        claims = good_claims(sub="alice", scope="registry.admin", groups=["team-alpha"])
        claims.update(over)
        claims = {k: v for k, v in claims.items() if v is not None}
        return f"Bearer {mint(claims, header={'typ': 'at+jwt'})}"

    def test_groups_become_principal(self, validator: TokenValidator, mint: Mint) -> None:
        p = authorize(self.bearer(mint), validator)
        assert p == Principal("alice", frozenset({"team-alpha"}))

    @pytest.mark.security
    @pytest.mark.parametrize("groups", ["team-alpha", [1, "x"], {"a": 1}, None])
    def test_malformed_groups_mean_no_roles(
        self, validator: TokenValidator, mint: Mint, groups: Any
    ) -> None:
        assert authorize(self.bearer(mint, groups=groups), validator).groups == frozenset()

    @pytest.mark.security
    def test_scope_required(self, validator: TokenValidator, mint: Mint) -> None:
        fails(Failure.FORBIDDEN, authorize, self.bearer(mint, scope="mcp.admin"), validator)

    @pytest.mark.security
    @pytest.mark.parametrize("header", [None, "", "Basic x", "Bearer not.a.jwt"])
    def test_bad_credentials(self, validator: TokenValidator, header: str | None) -> None:
        fails(Failure.UNAUTHORIZED, authorize, header, validator)

    @pytest.mark.security
    def test_wrong_audience(self, validator: TokenValidator, mint: Mint) -> None:
        fails(Failure.UNAUTHORIZED, authorize, self.bearer(mint, aud="api://mcp-admin"), validator)


class TestEligibleRoles:
    @pytest.mark.parametrize(
        ("who", "team", "roles"),
        [
            (ALICE, "alpha", {ApprovalRole.APPROVER, ApprovalRole.OWNER}),
            (ALICE, "beta", {ApprovalRole.APPROVER}),
            (BOB, "alpha", {ApprovalRole.APPROVER}),
            (CAROL, "alpha", {ApprovalRole.SECURITY}),
            (DAVE, "alpha", set()),  # team membership alone approves nothing
            (MALLORY, "alpha", set(ApprovalRole)),
        ],
    )
    def test_roles(self, who: Principal, team: str, roles: set[ApprovalRole]) -> None:
        assert eligible_roles(who, team) == frozenset(roles)


# ----------------------------------------------------------------------------- drafts


class TestDrafts:
    def test_team_member_creates_draft(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec())
        assert (v.version, v.state, v.author, v.rev) == (1, State.DRAFT, "dave", 0)
        assert env.audit.events[-1].event_type == "registry.create"
        assert env.audit.events[-1].decision is Decision.ALLOW

    @pytest.mark.security
    def test_outsider_cannot_create(self, env: Env) -> None:
        fails(Failure.FORBIDDEN, env.svc.create_draft, EVE, AGENT, spec())
        assert env.store.versions(AGENT) == []
        assert env.audit.events[-1].decision is Decision.DENY

    @pytest.mark.security
    @pytest.mark.parametrize("tier", ["elevated", "privileged"])
    def test_fail_open_forbidden_above_standard(self, env: Env, tier: str) -> None:
        """ADR-0004: elevated tiers can't set scanner fail-open."""
        fails(
            Failure.INVALID,
            env.svc.create_draft,
            DAVE,
            AGENT,
            spec(tier=tier, scanner_failure_mode="open"),
        )

    def test_fail_open_allowed_for_standard(self, env: Env) -> None:
        env.svc.create_draft(DAVE, AGENT, spec(scanner_failure_mode="open"))

    @pytest.mark.security
    @pytest.mark.parametrize("field", ["may_delegate_to", "accepts_delegation_from"])
    def test_self_delegation_invalid(self, env: Env, field: str) -> None:
        fails(Failure.INVALID, env.svc.create_draft, DAVE, AGENT, spec(delegation={field: [AGENT]}))

    @pytest.mark.parametrize("agent_id", ["", "bad id", "x" * 200, "-lead"])
    def test_bad_agent_id(self, env: Env, agent_id: str) -> None:
        fails(Failure.INVALID, env.svc.create_draft, DAVE, agent_id, spec())

    def test_one_open_version_per_agent(self, env: Env) -> None:
        env.svc.create_draft(DAVE, AGENT, spec())
        fails(Failure.CONFLICT, env.svc.create_draft, DAVE, AGENT, spec())

    def test_new_version_after_approval(self, env: Env) -> None:
        env.approved()
        assert env.svc.create_draft(DAVE, AGENT, spec(display_name="Alpha 2")).version == 2

    @pytest.mark.security
    def test_ownership_transfer_needs_both_teams(self, env: Env) -> None:
        env.approved()
        fails(Failure.FORBIDDEN, env.svc.create_draft, EVE, AGENT, spec(owner_team="beta"))
        assert env.svc.create_draft(FRANK, AGENT, spec(owner_team="beta")).version == 2

    @pytest.mark.security
    def test_new_version_needs_current_team(self, env: Env) -> None:
        """A member of another team can't open a new version claiming to be the owner team."""
        env.approved()
        outsider = Principal("oscar", frozenset({"team-beta"}))
        fails(Failure.FORBIDDEN, env.svc.create_draft, outsider, AGENT, spec(owner_team="beta"))

    def test_author_edits_draft(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec())
        v2 = env.svc.update_draft(DAVE, AGENT, v.version, spec(display_name="Renamed"))
        assert (v2.spec.display_name, v2.rev) == ("Renamed", 1)

    @pytest.mark.security
    def test_only_author_edits(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec())
        fails(Failure.FORBIDDEN, env.svc.update_draft, ALICE, AGENT, v.version, spec())

    @pytest.mark.security
    def test_edit_cannot_move_team(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec())
        fails(
            Failure.FORBIDDEN,
            env.svc.update_draft,
            DAVE,
            AGENT,
            v.version,
            spec(owner_team="beta"),
        )

    @pytest.mark.security
    def test_in_review_is_frozen(self, env: Env) -> None:
        """What approvers review is what gets approved."""
        v = env.svc.create_draft(DAVE, AGENT, spec())
        env.svc.submit(DAVE, AGENT, v.version)
        fails(Failure.CONFLICT, env.svc.update_draft, DAVE, AGENT, v.version, spec())

    def test_submit(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec())
        assert env.svc.submit(DAVE, AGENT, v.version).state is State.IN_REVIEW
        fails(Failure.CONFLICT, env.svc.submit, DAVE, AGENT, v.version)

    def test_only_author_submits(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec())
        fails(Failure.FORBIDDEN, env.svc.submit, ALICE, AGENT, v.version)

    def test_unknown_version(self, env: Env) -> None:
        fails(Failure.NOT_FOUND, env.svc.submit, DAVE, AGENT, 7)


# ----------------------------------------------------------------------------- approval


def in_review(env: Env, s: AgentSpec | None = None, author: Principal = DAVE) -> int:
    v = env.svc.create_draft(author, AGENT, s or spec())
    env.svc.submit(author, AGENT, v.version)
    return v.version


class TestApproval:
    def test_standard_one_approver(self, env: Env) -> None:
        n = in_review(env)
        v = env.svc.approve(BOB, AGENT, n, ApprovalRole.APPROVER)
        assert (v.state, v.approved_at, v.expires_at) == (State.APPROVED, T0, None)
        assert [(a.subject, a.role) for a in v.approvals] == [("bob", ApprovalRole.APPROVER)]
        assert env.svc.effective(AGENT) == v

    def test_not_before_submit(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec())
        fails(Failure.CONFLICT, env.svc.approve, BOB, AGENT, v.version, ApprovalRole.APPROVER)

    @pytest.mark.security
    def test_author_never_approves(self, env: Env) -> None:
        n = in_review(env, author=MALLORY)
        for role in ApprovalRole:
            fails(Failure.SAME_PERSON, env.svc.approve, MALLORY, AGENT, n, role)

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("who", "role"),
        [(BOB, ApprovalRole.OWNER), (FRANK, ApprovalRole.OWNER), (ALICE, ApprovalRole.SECURITY)],
    )
    def test_must_be_eligible_for_role(self, env: Env, who: Principal, role: ApprovalRole) -> None:
        n = in_review(env, spec(tier="elevated"))
        fails(Failure.FORBIDDEN, env.svc.approve, who, AGENT, n, role)

    def test_role_must_be_required(self, env: Env) -> None:
        n = in_review(env)
        fails(Failure.INVALID, env.svc.approve, CAROL, AGENT, n, ApprovalRole.SECURITY)

    def test_elevated_needs_owner_and_security(self, env: Env) -> None:
        n = in_review(env, spec(tier="elevated"))
        v = env.svc.approve(ALICE, AGENT, n, ApprovalRole.OWNER)
        assert v.state is State.IN_REVIEW
        assert env.svc.effective(AGENT) is None
        v = env.svc.approve(CAROL, AGENT, n, ApprovalRole.SECURITY)
        assert v.state is State.APPROVED

    @pytest.mark.security
    def test_one_person_counts_once(self, env: Env) -> None:
        n = in_review(env, spec(tier="elevated"))
        env.svc.approve(MALLORY, AGENT, n, ApprovalRole.OWNER)
        fails(Failure.SAME_PERSON, env.svc.approve, MALLORY, AGENT, n, ApprovalRole.SECURITY)

    def test_satisfied_role_not_repeated(self, env: Env) -> None:
        n = in_review(env, spec(tier="elevated"))
        env.svc.approve(ALICE, AGENT, n, ApprovalRole.OWNER)
        fails(Failure.CONFLICT, env.svc.approve, MALLORY, AGENT, n, ApprovalRole.OWNER)

    def test_privileged_expires_after_90_days(self, env: Env) -> None:
        v = env.approved(spec(tier="privileged"))
        assert v.expires_at == T0 + dt.timedelta(days=90)
        env.clock.t = T0 + dt.timedelta(days=89)
        assert env.svc.effective(AGENT) == v
        env.clock.t = T0 + dt.timedelta(days=90)
        assert env.svc.effective(AGENT) is None

    def test_new_version_supersedes_atomically(self, env: Env) -> None:
        v1 = env.approved()
        n = in_review(env, spec(display_name="Alpha 2"))
        assert env.svc.effective(AGENT) == v1  # old version serves during review
        v2 = env.svc.approve(BOB, AGENT, n, ApprovalRole.APPROVER)
        assert env.svc.effective(AGENT) == v2
        old = env.store.get(AGENT, v1.version)
        assert old is not None
        assert old.state is State.SUPERSEDED

    def test_reject(self, env: Env) -> None:
        n = in_review(env)
        v = env.svc.reject(BOB, AGENT, n)
        assert (v.state, v.decided_by) == (State.REJECTED, "bob")
        assert env.svc.create_draft(DAVE, AGENT, spec()).version == 2

    @pytest.mark.security
    def test_reject_rules(self, env: Env) -> None:
        n = in_review(env, author=MALLORY)
        fails(Failure.SAME_PERSON, env.svc.reject, MALLORY, AGENT, n)
        fails(Failure.FORBIDDEN, env.svc.reject, DAVE, AGENT, n)


class TestRevoke:
    def test_security_revokes_immediately(self, env: Env) -> None:
        env.approved()
        v = env.svc.revoke(CAROL, AGENT)
        assert (v.state, v.decided_by) == (State.REVOKED, "carol")
        assert env.svc.effective(AGENT) is None

    @pytest.mark.security
    @pytest.mark.parametrize("who", [BOB, ALICE, DAVE])
    def test_only_security_revokes(self, env: Env, who: Principal) -> None:
        env.approved()
        fails(Failure.FORBIDDEN, env.svc.revoke, who, AGENT)

    def test_nothing_to_revoke(self, env: Env) -> None:
        fails(Failure.NOT_FOUND, env.svc.revoke, CAROL, AGENT)


class TestRead:
    @pytest.mark.parametrize("who", [DAVE, BOB, CAROL])
    def test_readers(self, env: Env, who: Principal) -> None:
        env.approved()
        assert [v.version for v in env.svc.history(who, AGENT)] == [1]
        assert env.svc.get(who, AGENT, 1).state is State.APPROVED

    @pytest.mark.security
    def test_outsider_cannot_tell_existing_from_missing(self, env: Env) -> None:
        """No enumeration oracle: both answers are not_found."""
        env.approved()
        fails(Failure.NOT_FOUND, env.svc.history, EVE, AGENT)
        fails(Failure.NOT_FOUND, env.svc.history, EVE, "0oa-nonexistent")
        fails(Failure.NOT_FOUND, env.svc.get, EVE, AGENT, 1)


# ----------------------------------------------------------------------------- audit + races


@pytest.mark.security
class TestAuditAndRaces:
    def test_audit_failure_means_nothing_written(self, env: Env) -> None:
        env.audit.fail = True
        fails(Failure.UNAVAILABLE, env.svc.create_draft, DAVE, AGENT, spec())
        assert env.store.versions(AGENT) == []

    def test_audit_failure_blocks_approval(self, env: Env) -> None:
        n = in_review(env)
        env.audit.fail = True
        fails(Failure.UNAVAILABLE, env.svc.approve, BOB, AGENT, n, ApprovalRole.APPROVER)
        env.audit.fail = False
        assert env.svc.effective(AGENT) is None

    def test_events_carry_who_what_version(self, env: Env) -> None:
        n = in_review(env)
        env.svc.approve(BOB, AGENT, n, ApprovalRole.APPROVER)
        e = env.audit.events[-1]
        assert (e.event_type, e.subject, e.client_id, e.record_version) == (
            "registry.approve",
            "bob",
            AGENT,
            n,
        )

    def test_concurrent_approvals_never_lose_one(self, env: Env) -> None:
        """A sneaks in an approval between B's read and B's write: B gets 409, A's survives."""
        n = in_review(env, spec(tier="elevated"))
        real_replace = env.store.replace
        raced = {"done": False}

        def racing_replace(v: AgentVersion, *, expected: AgentVersion) -> None:
            if not raced["done"]:
                raced["done"] = True
                env.svc.approve(ALICE, AGENT, n, ApprovalRole.OWNER)  # the competitor
            real_replace(v, expected=expected)

        env.store.replace = racing_replace  # type: ignore[method-assign]
        fails(Failure.CONFLICT, env.svc.approve, CAROL, AGENT, n, ApprovalRole.SECURITY)
        env.store.replace = real_replace  # type: ignore[method-assign]
        current = env.store.get(AGENT, n)
        assert current is not None
        assert [a.subject for a in current.approvals] == ["alice"]
        assert env.svc.approve(CAROL, AGENT, n, ApprovalRole.SECURITY).state is State.APPROVED

    def test_store_conflict_maps_to_conflict(self, env: Env) -> None:
        class Racy(InMemoryRegistryStore):
            def put_new(self, v: AgentVersion) -> None:
                raise StoreConflictError

        env.svc = RegistryService(Racy(), env.audit, now=env.clock)
        fails(Failure.CONFLICT, env.svc.create_draft, DAVE, AGENT, spec())


@pytest.mark.security
class TestStoreOutage:
    class Down(InMemoryRegistryStore):
        reads_fail = False
        writes_fail = False

        def versions(self, agent_id: str) -> Any:
            from atf_agent_registry.records import StoreUnavailableError

            if self.reads_fail:
                raise StoreUnavailableError
            return super().versions(agent_id)

        def put_new(self, v: AgentVersion) -> None:
            from atf_agent_registry.records import StoreUnavailableError

            if self.writes_fail:
                raise StoreUnavailableError
            super().put_new(v)

    def test_read_outage_is_unavailable(self, env: Env) -> None:
        store = self.Down()
        store.reads_fail = True
        svc = RegistryService(store, env.audit, now=env.clock)
        fails(Failure.UNAVAILABLE, svc.history, BOB, AGENT)
        fails(Failure.UNAVAILABLE, svc.create_draft, DAVE, AGENT, spec())

    def test_write_outage_is_unavailable(self, env: Env) -> None:
        store = self.Down()
        store.writes_fail = True
        svc = RegistryService(store, env.audit, now=env.clock)
        fails(Failure.UNAVAILABLE, svc.create_draft, DAVE, AGENT, spec())


class TestMoreRules:
    @pytest.mark.security
    def test_edit_rechecks_tier_rules(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec(tier="elevated"))
        fails(
            Failure.INVALID,
            env.svc.update_draft,
            DAVE,
            AGENT,
            v.version,
            spec(tier="elevated", scanner_failure_mode="open"),
        )

    def test_reject_only_in_review(self, env: Env) -> None:
        v = env.svc.create_draft(DAVE, AGENT, spec())
        fails(Failure.CONFLICT, env.svc.reject, BOB, AGENT, v.version)


# ----------------------------------------------------------------------------- delegation edges


class TestDelegationEdges:
    """ADR-0024 §4: adding a delegation edge always needs a security approval."""

    def test_required_roles(self) -> None:
        from atf_agent_registry.records import required_roles

        plain, edged = spec(), spec(delegation={"may_delegate_to": ["0oa-agent-beta"]})
        assert required_roles(plain, None) == frozenset({ApprovalRole.APPROVER})
        assert required_roles(edged, None) == frozenset(
            {ApprovalRole.APPROVER, ApprovalRole.SECURITY}
        )
        assert required_roles(edged, edged) == frozenset({ApprovalRole.APPROVER})  # unchanged
        assert required_roles(plain, edged) == frozenset({ApprovalRole.APPROVER})  # removal
        accepts = spec(delegation={"accepts_delegation_from": ["0oa-agent-beta"]})
        assert ApprovalRole.SECURITY in required_roles(accepts, None)
        elevated = spec(tier="elevated", delegation={"may_delegate_to": ["0oa-agent-beta"]})
        assert required_roles(elevated, None) == frozenset(
            {ApprovalRole.OWNER, ApprovalRole.SECURITY}
        )

    @pytest.mark.security
    def test_standard_agent_adding_edge_needs_security(self, env: Env) -> None:
        n = in_review(env, spec(delegation={"may_delegate_to": ["0oa-agent-beta"]}))
        v = env.svc.approve(BOB, AGENT, n, ApprovalRole.APPROVER)
        assert v.state is State.IN_REVIEW  # approver alone isn't enough
        v = env.svc.approve(CAROL, AGENT, n, ApprovalRole.SECURITY)
        assert v.state is State.APPROVED

    def test_security_can_reject_edge_version(self, env: Env) -> None:
        n = in_review(env, spec(delegation={"may_delegate_to": ["0oa-agent-beta"]}))
        assert env.svc.reject(CAROL, AGENT, n).state is State.REJECTED

    def test_removing_edge_needs_only_tier_roles(self, env: Env) -> None:
        env.approved(spec(delegation={"may_delegate_to": ["0oa-agent-beta"]}))
        n = in_review(env, spec())
        assert env.svc.approve(BOB, AGENT, n, ApprovalRole.APPROVER).state is State.APPROVED


class TestCardSpec:
    @pytest.mark.security
    @pytest.mark.parametrize(
        "card",
        [
            {"endpoint": "http://agent.internal/a2a"},
            {"endpoint": "https://a/b", "skills": [{"id": "Bad Id", "name": "x"}]},
            {"endpoint": "https://a/b", "extra": 1},
        ],
    )
    def test_invalid_card_rejected(self, card: dict[str, Any]) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            spec(card=card)
