"""Policy decision point (ADR-0022 §4). Any error, schema mismatch or NoDecision is deny."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import cedarpy

from trustkit_policy.grants import AgentGrant
from trustkit_policy.schema import CEDAR_SCHEMA, NAMESPACE, Action, ResourceType


class PolicyConfigError(Exception):
    """Policies don't parse or don't validate against the schema. Message is log-safe."""


@dataclass(frozen=True)
class Resource:
    type: ResourceType
    id: str
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DecisionRequest:
    agent_id: str
    action: Action
    resource: Resource
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    policy_ids: tuple[str, ...] = ()
    """``@id`` annotations of the determining policies (for audit)."""
    errored: bool = False


class PolicyDecisionPoint(Protocol):
    def decide(self, request: DecisionRequest) -> PolicyDecision: ...


class CedarPdp:
    """In-process Cedar. Agents (with team parents and ``tier``) come from the grants; the
    resource entity and its attributes come from the caller per request."""

    def __init__(self, policies: str, grants: Mapping[str, AgentGrant]) -> None:
        try:
            result = cedarpy.validate_policies(policies, CEDAR_SCHEMA)
        except Exception:  # noqa: BLE001 - the native parser may raise on malformed text
            raise PolicyConfigError("policies do not parse") from None
        if not result.validation_passed:
            raise PolicyConfigError("policies do not validate against the schema")
        try:
            self._schema = cedarpy.Schema.from_str(CEDAR_SCHEMA)
            self._policies = cedarpy.PolicySet.from_str(policies)
            teams = sorted({g.owner_team for g in grants.values()})
            entities: list[dict[str, Any]] = [
                {"uid": _uid("Team", t), "attrs": {}, "parents": []} for t in teams
            ]
            entities += [
                {
                    "uid": _uid("Agent", g.agent_id),
                    "attrs": {"tier": g.tier},
                    "parents": [_uid("Team", g.owner_team)],
                }
                for g in grants.values()
            ]
            self._entities = cedarpy.Entities.from_json_str(json.dumps(entities), self._schema)
        except Exception:  # noqa: BLE001
            raise PolicyConfigError("policy set or entities invalid") from None

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        try:
            resource = {
                "uid": _uid(request.resource.type.value, request.resource.id),
                "attrs": dict(request.resource.attrs),
                "parents": [],
            }
            entities = self._entities.with_added_json_str(json.dumps([resource]), self._schema)
            result = cedarpy.is_authorized(
                {
                    "principal": _uid("Agent", request.agent_id),
                    "action": _uid("Action", request.action.value),
                    "resource": resource["uid"],
                    "context": dict(request.context),
                },
                self._policies,
                entities,
                schema=self._schema,
            )
            diagnostics = result.diagnostics
            errors = list(diagnostics.errors)
            ids = _annotated_ids(diagnostics)
        except Exception:  # noqa: BLE001 - any failure to evaluate is a deny
            return PolicyDecision(allowed=False, errored=True)
        if errors or result.decision is not cedarpy.Decision.Allow:
            return PolicyDecision(allowed=False, policy_ids=ids, errored=bool(errors))
        return PolicyDecision(allowed=True, policy_ids=ids)


def _uid(kind: str, ident: str) -> dict[str, str]:
    return {"type": f"{NAMESPACE}::{kind}", "id": ident}


def _annotated_ids(diagnostics: Any) -> tuple[str, ...]:
    """Map Cedar's internal policy ids to our ``@id`` annotations (sorted, for audit)."""
    by_reason = diagnostics.id_annotations_by_reason or {}
    return tuple(sorted(str(by_reason.get(r, r)) for r in diagnostics.reasons))
