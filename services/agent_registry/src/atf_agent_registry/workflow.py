"""Registry workflow: who may do what, and the state machine (ADR-0021 §2, §4-§6).

Pure domain logic over a ``RegistryStore``; no HTTP. Every decision (allowed or denied) is
audited; allowed changes are audited *before* the write, and an audit failure aborts the write.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import re
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NoReturn

from atf_agent_registry.records import (
    OPEN_STATES,
    PRIVILEGED_APPROVAL_TTL,
    AgentSpec,
    AgentVersion,
    Approval,
    ApprovalRole,
    RegistryStore,
    State,
    StoreConflictError,
    StoreUnavailableError,
    Tier,
    required_roles,
)
from trustkit.audit import AuditEvent, AuditSink, Decision
from trustkit.jwt import TokenValidationError, TokenValidator
from trustkit.profiles import ScannerFailureMode

REGISTRY_SCOPE: Final = "registry.admin"
APPROVERS_GROUP: Final = "atf-registry-approvers"
SECURITY_GROUP: Final = "atf-security-approvers"
TEAM_PREFIX: Final = "team-"
_BEARER: Final = re.compile(r"^[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9._~+/=-]+)$")
_AGENT_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class Failure(StrEnum):
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    INVALID = "invalid"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    SAME_PERSON = "same_person"
    UNAVAILABLE = "unavailable"
    """Audit sink or store unreachable: nothing was written."""


class RegistryError(Exception):
    def __init__(self, failure: Failure, detail: str = "") -> None:
        self.failure, self.detail = failure, detail
        super().__init__(f"{failure.value}: {detail}" if detail else failure.value)


@dataclass(frozen=True)
class Principal:
    subject: str
    groups: frozenset[str]

    def in_team(self, team: str) -> bool:
        return f"{TEAM_PREFIX}{team}" in self.groups


def authorize(authorization_header: str | None, validator: TokenValidator) -> Principal:
    """Valid ``at+jwt`` with ``registry.admin`` scope. ``groups`` must be a list of strings,
    else the principal has no groups (never an error that reveals token details)."""
    m = _BEARER.fullmatch(authorization_header or "")
    if m is None:
        raise RegistryError(Failure.UNAUTHORIZED)
    try:
        token = validator.validate(m.group(1))
    except TokenValidationError:
        raise RegistryError(Failure.UNAUTHORIZED) from None
    scope = token.claims.get("scope")
    if not isinstance(scope, str) or REGISTRY_SCOPE not in scope.split():
        raise RegistryError(Failure.FORBIDDEN)
    raw = token.claims.get("groups")
    groups = (
        frozenset(raw)
        if isinstance(raw, list) and all(isinstance(g, str) for g in raw)
        else frozenset()
    )
    return Principal(token.subject, groups)


def eligible_roles(who: Principal, owner_team: str) -> frozenset[ApprovalRole]:
    """``approver``: approvers group. ``owner``: approvers group + the owner team.
    ``security``: security group."""
    roles: set[ApprovalRole] = set()
    if APPROVERS_GROUP in who.groups:
        roles.add(ApprovalRole.APPROVER)
        if who.in_team(owner_team):
            roles.add(ApprovalRole.OWNER)
    if SECURITY_GROUP in who.groups:
        roles.add(ApprovalRole.SECURITY)
    return frozenset(roles)


def _check_spec(agent_id: str, spec: AgentSpec) -> str | None:
    """Tier and self-reference rules the schema alone can't express. Returns a reason or None."""
    if spec.tier is not Tier.STANDARD and spec.scanner_failure_mode is ScannerFailureMode.OPEN:
        return "fail-open not allowed above standard tier"
    d = spec.delegation
    if agent_id in d.may_delegate_to or agent_id in d.accepts_delegation_from:
        return "an agent cannot delegate to itself"
    return None


class RegistryService:
    def __init__(
        self,
        store: RegistryStore,
        audit: AuditSink,
        *,
        now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
    ) -> None:
        self._store, self._audit, self._now = store, audit, now

    # ------------------------------------------------------------------ commands

    def create_draft(self, who: Principal, agent_id: str, spec: AgentSpec) -> AgentVersion:
        ev = "registry.create"
        if not _AGENT_ID.fullmatch(agent_id):
            self._deny(ev, who, agent_id, None, Failure.INVALID, "agent_id")
        if not who.in_team(spec.owner_team):
            self._deny(ev, who, agent_id, None, Failure.FORBIDDEN, "not in owner team")
        if (reason := _check_spec(agent_id, spec)) is not None:
            self._deny(ev, who, agent_id, None, Failure.INVALID, reason)
        versions = self._versions(agent_id)
        current_team = self._current_team(versions)
        if current_team is not None and not who.in_team(current_team):
            self._deny(ev, who, agent_id, None, Failure.FORBIDDEN, "not in current owner team")
        if versions and versions[-1].state in OPEN_STATES:
            self._deny(ev, who, agent_id, None, Failure.CONFLICT, "open version exists")
        now = self._now()
        v = AgentVersion(
            agent_id=agent_id,
            version=versions[-1].version + 1 if versions else 1,
            spec=spec,
            state=State.DRAFT,
            author=who.subject,
            created_at=now,
            updated_at=now,
        )
        self._commit(ev, who, v, lambda: self._store.put_new(v))
        return v

    def update_draft(
        self, who: Principal, agent_id: str, version: int, spec: AgentSpec
    ) -> AgentVersion:
        ev = "registry.update"
        v = self._load(ev, who, agent_id, version)
        if v.author != who.subject:
            self._deny(ev, who, agent_id, version, Failure.FORBIDDEN, "not the author")
        if v.state is not State.DRAFT:
            self._deny(ev, who, agent_id, version, Failure.CONFLICT, "not a draft")
        if spec.owner_team != v.spec.owner_team:
            self._deny(ev, who, agent_id, version, Failure.FORBIDDEN, "owner team change")
        if (reason := _check_spec(agent_id, spec)) is not None:
            self._deny(ev, who, agent_id, version, Failure.INVALID, reason)
        new = self._next(v, spec=spec)
        self._commit(ev, who, new, lambda: self._store.replace(new, expected=v))
        return new

    def submit(self, who: Principal, agent_id: str, version: int) -> AgentVersion:
        ev = "registry.submit"
        v = self._load(ev, who, agent_id, version)
        if v.author != who.subject:
            self._deny(ev, who, agent_id, version, Failure.FORBIDDEN, "not the author")
        if v.state is not State.DRAFT:
            self._deny(ev, who, agent_id, version, Failure.CONFLICT, "not a draft")
        new = self._next(v, state=State.IN_REVIEW)
        self._commit(ev, who, new, lambda: self._store.replace(new, expected=v))
        return new

    def approve(
        self, who: Principal, agent_id: str, version: int, role: ApprovalRole
    ) -> AgentVersion:
        ev = "registry.approve"
        v = self._load(ev, who, agent_id, version)
        if v.state is not State.IN_REVIEW:
            self._deny(ev, who, agent_id, version, Failure.CONFLICT, "not in review")
        if who.subject == v.author or any(a.subject == who.subject for a in v.approvals):
            self._deny(ev, who, agent_id, version, Failure.SAME_PERSON, role.value)
        versions = self._versions(agent_id)
        prev = self._approved(versions)
        required = required_roles(v.spec, prev.spec if prev is not None else None)
        if role not in required:
            self._deny(ev, who, agent_id, version, Failure.INVALID, f"{role.value} not required")
        if role not in eligible_roles(who, v.spec.owner_team):
            self._deny(ev, who, agent_id, version, Failure.FORBIDDEN, f"not eligible: {role}")
        if any(a.role is role for a in v.approvals):
            self._deny(ev, who, agent_id, version, Failure.CONFLICT, f"{role.value} satisfied")
        now = self._now()
        approvals = (*v.approvals, Approval(who.subject, role, now))
        if not required <= {a.role for a in approvals}:
            new = self._next(v, approvals=approvals)
            self._commit(ev, who, new, lambda: self._store.replace(new, expected=v), role)
            return new
        new = self._next(
            v,
            approvals=approvals,
            state=State.APPROVED,
            approved_at=now,
            expires_at=now + PRIVILEGED_APPROVAL_TTL if v.spec.tier is Tier.PRIVILEGED else None,
        )
        if prev is None:
            self._commit(ev, who, new, lambda: self._store.replace(new, expected=v), role)
        else:
            old = self._next(prev, state=State.SUPERSEDED)
            self._commit(
                ev,
                who,
                new,
                lambda: self._store.replace_pair(new, expected=v, other=old, other_expected=prev),
                role,
            )
        return new

    def reject(self, who: Principal, agent_id: str, version: int) -> AgentVersion:
        ev = "registry.reject"
        v = self._load(ev, who, agent_id, version)
        if v.state is not State.IN_REVIEW:
            self._deny(ev, who, agent_id, version, Failure.CONFLICT, "not in review")
        if who.subject == v.author:
            self._deny(ev, who, agent_id, version, Failure.SAME_PERSON, "author")
        prev = self._approved(self._versions(agent_id))
        required = required_roles(v.spec, prev.spec if prev is not None else None)
        if not eligible_roles(who, v.spec.owner_team) & required:
            self._deny(ev, who, agent_id, version, Failure.FORBIDDEN, "not an approver")
        new = self._next(v, state=State.REJECTED, decided_by=who.subject)
        self._commit(ev, who, new, lambda: self._store.replace(new, expected=v))
        return new

    def revoke(self, who: Principal, agent_id: str) -> AgentVersion:
        ev = "registry.revoke"
        versions = self._versions(agent_id)
        v = self._approved(versions)
        if v is None or not self._readable(who, versions):
            self._deny(ev, who, agent_id, None, Failure.NOT_FOUND, "no approved version")
        if ApprovalRole.SECURITY not in eligible_roles(who, v.spec.owner_team):
            self._deny(ev, who, agent_id, v.version, Failure.FORBIDDEN, "not security")
        new = self._next(v, state=State.REVOKED, decided_by=who.subject)
        self._commit(ev, who, new, lambda: self._store.replace(new, expected=v))
        return new

    # ------------------------------------------------------------------ queries

    def history(self, who: Principal, agent_id: str) -> Sequence[AgentVersion]:
        """Readable by the owner team, approvers and security."""
        versions = self._versions(agent_id)
        if not versions or not self._readable(who, versions):
            raise RegistryError(Failure.NOT_FOUND)
        return versions

    def get(self, who: Principal, agent_id: str, version: int) -> AgentVersion:
        versions = self._versions(agent_id)
        found = next((v for v in versions if v.version == version), None)
        if found is None or not self._readable(who, versions):
            raise RegistryError(Failure.NOT_FOUND)
        return found

    def effective(self, agent_id: str) -> AgentVersion | None:
        """The approved, unexpired version, if any. Unauthenticated: for the bundle builder."""
        v = self._approved(self._versions(agent_id))
        if v is None or (v.expires_at is not None and self._now() >= v.expires_at):
            return None
        return v

    # ------------------------------------------------------------------ helpers

    def _versions(self, agent_id: str) -> Sequence[AgentVersion]:
        try:
            return self._store.versions(agent_id)
        except StoreUnavailableError:
            raise RegistryError(Failure.UNAVAILABLE) from None

    @staticmethod
    def _approved(versions: Sequence[AgentVersion]) -> AgentVersion | None:
        return next((v for v in reversed(versions) if v.state is State.APPROVED), None)

    def _current_team(self, versions: Sequence[AgentVersion]) -> str | None:
        anchor = self._approved(versions) or (versions[-1] if versions else None)
        return None if anchor is None else anchor.spec.owner_team

    def _readable(self, who: Principal, versions: Sequence[AgentVersion]) -> bool:
        if who.groups & {APPROVERS_GROUP, SECURITY_GROUP}:
            return True
        teams = {self._current_team(versions), versions[-1].spec.owner_team}
        return any(t is not None and who.in_team(t) for t in teams)

    def _load(self, ev: str, who: Principal, agent_id: str, version: int) -> AgentVersion:
        """The version, or ``not_found`` for missing *and* unreadable (no enumeration oracle)."""
        versions = self._versions(agent_id)
        found = next((v for v in versions if v.version == version), None)
        if found is None or not self._readable(who, versions):
            self._deny(ev, who, agent_id, version, Failure.NOT_FOUND, "")
        return found

    def _next(self, v: AgentVersion, **changes: object) -> AgentVersion:
        return dataclasses.replace(
            v,
            rev=v.rev + 1,
            updated_at=self._now(),
            **changes,  # type: ignore[arg-type]
        )

    def _event(
        self,
        ev: str,
        who: Principal,
        agent_id: str,
        version: int | None,
        decision: Decision,
        reason: str,
    ) -> AuditEvent:
        return AuditEvent(
            event_type=ev,
            request_id=str(uuid.uuid4()),
            decision=decision,
            reason=reason,
            subject=who.subject,
            client_id=agent_id,
            record_version=version,
        )

    def _deny(
        self,
        ev: str,
        who: Principal,
        agent_id: str,
        version: int | None,
        failure: Failure,
        detail: str,
    ) -> NoReturn:
        # A denial is a denial even if audit is down: nothing is written either way.
        with contextlib.suppress(Exception):
            self._audit.emit(self._event(ev, who, agent_id, version, Decision.DENY, failure.value))
        raise RegistryError(failure, detail)

    def _commit(
        self,
        ev: str,
        who: Principal,
        v: AgentVersion,
        write: Callable[[], None],
        role: ApprovalRole | None = None,
    ) -> None:
        """Audit first; if audit fails, nothing is written (ADR-0021 §6)."""
        reason = f"{v.state.value}:{role.value}" if role is not None else v.state.value
        try:
            self._audit.emit(self._event(ev, who, v.agent_id, v.version, Decision.ALLOW, reason))
        except Exception:  # noqa: BLE001 - any sink failure aborts the change
            raise RegistryError(Failure.UNAVAILABLE, "audit") from None
        try:
            write()
        except StoreConflictError:
            self._deny(ev, who, v.agent_id, v.version, Failure.CONFLICT, "lost race")
        except StoreUnavailableError:
            raise RegistryError(Failure.UNAVAILABLE, "store") from None
