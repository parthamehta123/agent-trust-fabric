"""What an approved agent may do, as carried in a bundle, and permit generation (ADR-0022 §3)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from trustkit.profiles import HttpsUrl, ScannerFailureMode, Scope

AgentId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
TeamSlug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
ServerId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
ModelName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:/-]{1,200}$")]

SAFE_ID: Final = r"^[A-Za-z0-9._:/-]{1,200}$"
"""Everything interpolated into generated Cedar text must match this (re-checked)."""
_SAFE: Final = re.compile(SAFE_ID)


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class T2Binding(_Strict):
    t2_issuer: HttpsUrl
    t2_audience: Annotated[str, StringConstraints(pattern=r"^\S{1,512}$")]
    t2_jwks_uri: HttpsUrl


class ModelGrant(_Strict):
    daily_token_budget: Annotated[int, Field(gt=0, le=1_000_000_000)]
    max_output_tokens: Annotated[int, Field(gt=0, le=32_768)]


class DelegationGrant(_Strict):
    may_delegate_to: frozenset[AgentId] = frozenset()
    accepts_delegation_from: frozenset[AgentId] = frozenset()


CLASSIFICATIONS: Final = ("public", "internal", "confidential", "restricted")
"""Ordered: a document's rank is its index (ADR-0025 §1)."""
Classification = Literal["public", "internal", "confidential", "restricted"]
CollectionSlug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]


def classification_rank(c: str) -> int:
    """Rank of a classification label; ``ValueError`` for anything unknown (never a default)."""
    return CLASSIFICATIONS.index(c)


class KnowledgeGrant(_Strict):
    """What an agent may retrieve (ADR-0025 §2): collections and a classification ceiling."""

    collections: Annotated[frozenset[CollectionSlug], Field(min_length=1, max_length=64)]
    max_classification: Classification


class Skill(_Strict):
    id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    description: Annotated[str, StringConstraints(max_length=1_000)] = ""


class CardGrant(_Strict):
    """A2A Agent Card material (ADR-0024 §6). ``endpoint`` is the *internal* runtime URL: the
    gateway serves cards with its own URL and never discloses this one."""

    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    description: Annotated[str, StringConstraints(max_length=2_000)] = ""
    endpoint: HttpsUrl
    skills: Annotated[tuple[Skill, ...], Field(max_length=32)] = ()


class AgentGrant(_Strict):
    agent_id: AgentId
    record_version: Annotated[int, Field(gt=0)]
    tier: Literal["standard", "elevated", "privileged"]
    owner_team: TeamSlug
    ingress: T2Binding | None = None
    tools: dict[ServerId, frozenset[Scope]] = Field(default_factory=dict)
    models: dict[ModelName, ModelGrant] = Field(default_factory=dict)
    delegation: DelegationGrant = DelegationGrant()
    scanner_failure_mode: ScannerFailureMode = ScannerFailureMode.CLOSED
    expires_at: Annotated[int, Field(gt=0)] | None = None
    """Epoch seconds; the grant is void after this even inside a fresh bundle."""
    card: CardGrant | None = None
    knowledge: KnowledgeGrant | None = None


def generate_permits(grants: Mapping[str, AgentGrant]) -> str:
    """Deterministic Cedar text: one permit per (agent, server) and per (agent, model).

    Raises ``ValueError`` if any interpolated value fails ``SAFE_ID`` (defence in depth; the
    schema patterns already exclude quotes and backslashes)."""

    def q(value: str) -> str:
        if not _SAFE.fullmatch(value):
            raise ValueError("unsafe identifier in generated policy")
        return f'"{value}"'

    def cedar_set(values: Iterable[str]) -> str:
        return "[" + ", ".join(q(v) for v in sorted(values)) + "]"

    out: list[str] = []
    for agent_id in sorted(grants):
        g = grants[agent_id]
        a = q(g.agent_id)
        for server in sorted(g.tools):
            out.append(
                f'@id("grant:{g.agent_id}:tool:{server}")\n'
                f"permit (principal == Atf::Agent::{a}, "
                f'action == Atf::Action::"invoke_tool", '
                f"resource == Atf::McpServer::{q(server)})\n"
                f"when {{ {cedar_set(g.tools[server])}.containsAll(context.scopes) }};"
            )
        for model in sorted(g.models):
            out.append(
                f'@id("grant:{g.agent_id}:model:{model}")\n'
                f"permit (principal == Atf::Agent::{a}, "
                f'action == Atf::Action::"call_model", '
                f"resource == Atf::Model::{q(model)});"
            )
    # Knowledge (ADR-0025 §2): granted collections up to the agent's classification ceiling.
    for agent_id in sorted(grants):
        g = grants[agent_id]
        if g.knowledge is None:
            continue
        out.append(
            f'@id("grant:{g.agent_id}:knowledge")\n'
            f"permit (principal == Atf::Agent::{q(g.agent_id)}, "
            f'action == Atf::Action::"read_document", resource)\n'
            f"when {{ {cedar_set(g.knowledge.collections)}.contains(resource.collection) && "
            f"resource.classification_rank <= "
            f"{classification_rank(g.knowledge.max_classification)} }};"
        )

    # Delegation edges (ADR-0024 §4): only when *both* records name each other.
    for frm in sorted(grants):
        for to in sorted(grants[frm].delegation.may_delegate_to):
            target = grants.get(to)
            if target is None or frm not in target.delegation.accepts_delegation_from:
                continue
            out.append(
                f'@id("delegate:{frm}->{to}")\n'
                f"permit (principal == Atf::Agent::{q(frm)}, "
                f'action == Atf::Action::"delegate", '
                f"resource == Atf::Agent::{q(to)});"
            )
    return "\n\n".join(out) + ("\n" if out else "")
