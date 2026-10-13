"""Agent records: spec schema, versions, lifecycle states, store protocol (ADR-0021 §3-§5)."""

from __future__ import annotations

import datetime as dt
import json
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from trustkit.profiles import HttpsUrl, ScannerFailureMode, Scope

AgentId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
"""The agent's OAuth ``client_id``."""
TeamSlug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
ServerId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
ModelName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:/-]{1,200}$")]

PRIVILEGED_APPROVAL_TTL: Final = dt.timedelta(days=90)


class Tier(StrEnum):
    STANDARD = "standard"
    ELEVATED = "elevated"
    PRIVILEGED = "privileged"


class State(StrEnum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


OPEN_STATES: Final = frozenset({State.DRAFT, State.IN_REVIEW})


class ApprovalRole(StrEnum):
    APPROVER = "approver"
    OWNER = "owner"
    SECURITY = "security"


REQUIRED_APPROVALS: Final[dict[Tier, frozenset[ApprovalRole]]] = {
    Tier.STANDARD: frozenset({ApprovalRole.APPROVER}),
    Tier.ELEVATED: frozenset({ApprovalRole.OWNER, ApprovalRole.SECURITY}),
    Tier.PRIVILEGED: frozenset({ApprovalRole.OWNER, ApprovalRole.SECURITY}),
}


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class IngressBinding(_Strict):
    """How gateways validate this agent's T2 (replaces the interim egress ``agents`` map)."""

    t2_issuer: HttpsUrl
    t2_audience: Annotated[str, StringConstraints(pattern=r"^\S{1,512}$")]
    t2_jwks_uri: HttpsUrl


class ModelGrant(_Strict):
    daily_token_budget: Annotated[int, Field(gt=0, le=1_000_000_000)]
    max_output_tokens: Annotated[int, Field(gt=0, le=32_768)]


class DelegationRights(_Strict):
    """Both-sides allowlists for agent-to-agent chains (enforced in 4c)."""

    may_delegate_to: Annotated[frozenset[AgentId], Field(max_length=64)] = frozenset()
    accepts_delegation_from: Annotated[frozenset[AgentId], Field(max_length=64)] = frozenset()


class KnowledgeSpec(_Strict):
    """Knowledge grant (ADR-0025 §2): collections and a classification ceiling."""

    collections: Annotated[
        frozenset[Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]],
        Field(min_length=1, max_length=64),
    ]
    max_classification: Literal["public", "internal", "confidential", "restricted"]


class SkillSpec(_Strict):
    id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    description: Annotated[str, StringConstraints(max_length=1_000)] = ""


class CardSpec(_Strict):
    """A2A Agent Card material (ADR-0024 §6). ``endpoint`` is the internal runtime URL; agents
    only ever see the gateway's URL."""

    endpoint: HttpsUrl
    skills: Annotated[tuple[SkillSpec, ...], Field(max_length=32)] = ()


class AgentSpec(_Strict):
    """The editable part of a record. Tier rules are checked here; self-references in the
    workflow (the spec doesn't know its own ``agent_id``)."""

    display_name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    description: Annotated[str, StringConstraints(max_length=2_000)] = ""
    owner_team: TeamSlug
    tier: Tier
    ingress: IngressBinding | None = None
    tools: Annotated[
        dict[ServerId, Annotated[frozenset[Scope], Field(min_length=1)]], Field(max_length=256)
    ] = Field(default_factory=dict)
    models: Annotated[dict[ModelName, ModelGrant], Field(max_length=64)] = Field(
        default_factory=dict
    )
    delegation: DelegationRights = DelegationRights()
    scanner_failure_mode: ScannerFailureMode = ScannerFailureMode.CLOSED
    card: CardSpec | None = None
    knowledge: KnowledgeSpec | None = None


def adds_delegation_edges(new: AgentSpec, previous: AgentSpec | None) -> bool:
    """True if ``new`` names any delegation partner ``previous`` (the approved version) didn't."""
    before = previous.delegation if previous is not None else DelegationRights()
    return bool(
        new.delegation.may_delegate_to - before.may_delegate_to
        or new.delegation.accepts_delegation_from - before.accepts_delegation_from
    )


def required_roles(new: AgentSpec, previous: AgentSpec | None) -> frozenset[ApprovalRole]:
    """Tier roles, plus ``security`` when the version adds a delegation edge (ADR-0024 §4)."""
    roles = REQUIRED_APPROVALS[new.tier]
    if adds_delegation_edges(new, previous):
        roles = roles | {ApprovalRole.SECURITY}
    return roles


@dataclass(frozen=True)
class Approval:
    subject: str
    role: ApprovalRole
    at: dt.datetime


@dataclass(frozen=True)
class AgentVersion:
    agent_id: str
    version: int
    spec: AgentSpec
    state: State
    author: str
    created_at: dt.datetime
    updated_at: dt.datetime
    rev: int = 0
    """Optimistic-lock counter; every write is conditional on the stored value."""
    approvals: tuple[Approval, ...] = ()
    approved_at: dt.datetime | None = None
    expires_at: dt.datetime | None = None
    decided_by: str | None = None
    """Who rejected or revoked it."""


def canonical_spec_json(spec: AgentSpec) -> str:
    """Deterministic JSON: sorted keys, sorted sets, no whitespace (stable digests for 4b)."""

    def norm(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: norm(v) for k, v in x.items()}
        if isinstance(x, list):
            items = [norm(v) for v in x]
            return sorted(items) if all(isinstance(i, str) for i in items) else items
        return x

    return json.dumps(norm(spec.model_dump(mode="json")), sort_keys=True, separators=(",", ":"))


class StoreConflictError(Exception):
    """A conditional write lost a race (or the version already exists)."""


class StoreUnavailableError(Exception):
    """The store could not be reached, or returned data that fails validation."""


class RegistryStore(Protocol):
    def put_new(self, v: AgentVersion) -> None:
        """Create; ``StoreConflictError`` if ``(agent_id, version)`` exists."""

    def replace(self, v: AgentVersion, *, expected: AgentVersion) -> None:
        """Write ``v`` (whose ``rev`` = ``expected.rev + 1``) only if the stored item still has
        ``expected.state`` and ``expected.rev``; else ``StoreConflictError``."""

    def replace_pair(
        self,
        v: AgentVersion,
        *,
        expected: AgentVersion,
        other: AgentVersion,
        other_expected: AgentVersion,
    ) -> None:
        """Both conditional replacements atomically (approve + supersede)."""

    def get(self, agent_id: str, version: int) -> AgentVersion | None: ...

    def versions(self, agent_id: str) -> Sequence[AgentVersion]:
        """All versions, ascending."""

    def agent_ids(self) -> Sequence[str]:
        """Valid agent ids only (never the reserved bundle-counter item)."""

    def next_bundle_version(self) -> int:
        """Strictly increasing across calls, restarts and processes (ADR-0022 §7)."""


class InMemoryRegistryStore:
    def __init__(self) -> None:
        self._items: dict[tuple[str, int], AgentVersion] = {}
        self._lock = threading.Lock()
        self._bundle_version = 0

    def put_new(self, v: AgentVersion) -> None:
        with self._lock:
            if (v.agent_id, v.version) in self._items:
                raise StoreConflictError
            self._items[(v.agent_id, v.version)] = v

    def _check(self, expected: AgentVersion) -> None:
        stored = self._items.get((expected.agent_id, expected.version))
        if stored is None or (stored.state, stored.rev) != (expected.state, expected.rev):
            raise StoreConflictError

    def replace(self, v: AgentVersion, *, expected: AgentVersion) -> None:
        with self._lock:
            self._check(expected)
            self._items[(v.agent_id, v.version)] = v

    def replace_pair(
        self,
        v: AgentVersion,
        *,
        expected: AgentVersion,
        other: AgentVersion,
        other_expected: AgentVersion,
    ) -> None:
        with self._lock:
            self._check(expected)
            self._check(other_expected)
            self._items[(v.agent_id, v.version)] = v
            self._items[(other.agent_id, other.version)] = other

    def get(self, agent_id: str, version: int) -> AgentVersion | None:
        return self._items.get((agent_id, version))

    def versions(self, agent_id: str) -> Sequence[AgentVersion]:
        with self._lock:
            found = [v for (a, _), v in self._items.items() if a == agent_id]
        return sorted(found, key=lambda v: v.version)

    def agent_ids(self) -> Sequence[str]:
        with self._lock:
            return sorted({a for a, _ in self._items})

    def next_bundle_version(self) -> int:
        with self._lock:
            self._bundle_version += 1
            return self._bundle_version
