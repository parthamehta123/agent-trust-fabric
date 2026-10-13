"""Cedar decision point + permit generation + repo guardrails (ADR-0022 §2-§4)."""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from trustkit_policy.grants import AgentGrant, generate_permits
from trustkit_policy.pdp import (
    CedarPdp,
    DecisionRequest,
    PolicyConfigError,
    PolicyDecision,
    Resource,
)
from trustkit_policy.schema import Action, ResourceType

ROOT = pathlib.Path(__file__).parents[2]
GUARDRAILS = (ROOT / "policies" / "guardrails.cedar").read_text()
AGENT, OTHER = "0oa-agent-alpha", "0oa-agent-beta"


def grant(agent_id: str = AGENT, **over: Any) -> AgentGrant:
    doc: dict[str, Any] = {
        "agent_id": agent_id,
        "record_version": 1,
        "tier": "standard",
        "owner_team": "alpha",
        "tools": {"tickets": ["tickets.read"]},
        "models": {"claude-sonnet": {"daily_token_budget": 1000, "max_output_tokens": 256}},
    }
    doc.update(over)
    return AgentGrant.model_validate_json(json.dumps(doc))


def pdp(*grants: AgentGrant, extra: str = "") -> CedarPdp:
    gs = {g.agent_id: g for g in (grants or (grant(),))}
    return CedarPdp(generate_permits(gs) + "\n" + GUARDRAILS + extra, gs)


def tool(
    p: CedarPdp,
    *,
    agent: str = AGENT,
    server: str = "tickets",
    scopes: list[str] | None = None,
    user_scopes: list[str] | None = None,
    delegation: str = "token",
) -> PolicyDecision:
    return p.decide(
        DecisionRequest(
            agent_id=agent,
            action=Action.INVOKE_TOOL,
            resource=Resource(ResourceType.MCP_SERVER, server, {"delegation": delegation}),
            context={
                "user": "alice",
                "scopes": ["tickets.read"] if scopes is None else scopes,
                "user_scopes": ["tickets.read"] if user_scopes is None else user_scopes,
            },
        )
    )


def model(p: CedarPdp, name: str = "claude-sonnet", agent: str = AGENT) -> PolicyDecision:
    return p.decide(
        DecisionRequest(
            agent_id=agent, action=Action.CALL_MODEL, resource=Resource(ResourceType.MODEL, name)
        )
    )


class TestGenerate:
    def test_deterministic(self) -> None:
        g = {AGENT: grant(tools={"tickets": ["b.read", "a.read"], "wiki": ["w.read"]})}
        assert generate_permits(g) == generate_permits(dict(reversed(list(g.items()))))
        text = generate_permits(g)
        assert text.index('"a.read"') < text.index('"b.read"')
        assert '@id("grant:0oa-agent-alpha:tool:tickets")' in text
        assert '@id("grant:0oa-agent-alpha:model:claude-sonnet")' in text

    def test_no_grants_no_permits(self) -> None:
        assert "permit" not in generate_permits({})

    @pytest.mark.security
    @pytest.mark.parametrize(
        "bad",
        ['x"); permit(principal, action, resource); //', "a\\b", "new\nline", ""],
    )
    def test_injection_refused_even_if_schema_bypassed(self, bad: str) -> None:
        """model_construct skips validation; the generator must still refuse unsafe ids."""
        g = AgentGrant.model_construct(**{**grant().__dict__, "agent_id": bad})
        with pytest.raises(ValueError, match="unsafe"):
            generate_permits({bad: g})


class TestDecisions:
    def test_granted_scopes_allowed_with_policy_id(self) -> None:
        d = tool(pdp())
        assert d.allowed
        assert d.policy_ids == ("grant:0oa-agent-alpha:tool:tickets",)

    @pytest.mark.parametrize(
        "kw",
        [
            pytest.param(
                {"scopes": ["tickets.write"], "user_scopes": ["tickets.write"]}, id="ungranted"
            ),
            pytest.param(
                {
                    "scopes": ["tickets.read", "tickets.write"],
                    "user_scopes": ["tickets.read", "tickets.write"],
                },
                id="superset",
            ),
            pytest.param({"server": "wiki"}, id="other-server"),
            pytest.param({"agent": OTHER}, id="unknown-agent"),
        ],
    )
    def test_denied(self, kw: dict[str, Any]) -> None:
        assert not tool(pdp(), **kw).allowed

    @pytest.mark.security
    def test_user_scope_guardrail_beats_permit(self) -> None:
        """TM-TOOL-01: the agent's grant can't exceed what the user holds."""
        d = tool(pdp(), user_scopes=[])
        assert not d.allowed
        assert d.policy_ids == ("guardrail:user-scopes",)

    @pytest.mark.security
    def test_privileged_never_uses_shared_credentials(self) -> None:
        p = pdp(grant(tier="privileged"))
        assert tool(p, delegation="token").allowed
        d = tool(p, delegation="none")
        assert not d.allowed
        assert d.policy_ids == ("guardrail:privileged-no-shared-credentials",)

    def test_standard_may_use_shared_credentials(self) -> None:
        assert tool(pdp(), delegation="none").allowed

    @pytest.mark.security
    def test_no_permit_can_override_a_guardrail(self) -> None:
        """Even a hand-written blanket permit loses to a forbid."""
        blanket = '\n@id("evil") permit (principal, action, resource);'
        assert not tool(pdp(extra=blanket), user_scopes=[]).allowed

    def test_models(self) -> None:
        p = pdp()
        assert model(p).allowed
        assert not model(p, "claude-opus").allowed
        assert not model(p, agent=OTHER).allowed

    def test_agents_isolated(self) -> None:
        p = pdp(grant(), grant(OTHER, tools={"wiki": ["w.read"]}))
        assert not tool(p, agent=OTHER).allowed
        assert tool(
            p, agent=OTHER, server="wiki", scopes=["w.read"], user_scopes=["w.read"]
        ).allowed


@pytest.mark.security
class TestFailClosed:
    def test_missing_context_is_deny_not_crash(self) -> None:
        d = pdp().decide(
            DecisionRequest(
                agent_id=AGENT,
                action=Action.INVOKE_TOOL,
                resource=Resource(ResourceType.MCP_SERVER, "tickets", {"delegation": "token"}),
                context={"user": "alice"},
            )
        )
        assert (d.allowed, d.errored) == (False, True)

    def test_missing_resource_attribute_is_deny(self) -> None:
        d = pdp().decide(
            DecisionRequest(
                agent_id=AGENT,
                action=Action.INVOKE_TOOL,
                resource=Resource(ResourceType.MCP_SERVER, "tickets"),
                context={"user": "a", "scopes": [], "user_scopes": []},
            )
        )
        assert not d.allowed

    def test_weird_ids_are_data_not_syntax(self) -> None:
        """Structured {type, id} requests: a quote in an id can't change the policy."""
        assert not tool(pdp(), agent='0oa-agent-alpha" || true').allowed

    @pytest.mark.parametrize(
        "policies",
        [
            pytest.param("permit(", id="syntax"),
            pytest.param(
                'permit(principal == Atf::Robot::"x", action, resource);', id="unknown-type"
            ),
            pytest.param(
                'permit(principal, action == Atf::Action::"invoke_tool", resource) '
                "when { context.nope };",
                id="unknown-attr",
            ),
        ],
    )
    def test_invalid_policies_refused_at_load(self, policies: str) -> None:
        with pytest.raises(PolicyConfigError):
            CedarPdp(policies, {})

    def test_guardrails_file_validates(self) -> None:
        CedarPdp(GUARDRAILS, {})

    def test_empty_policy_set_denies_everything(self) -> None:
        p = CedarPdp(GUARDRAILS, {AGENT: grant()})
        assert not tool(p).allowed
        assert not model(p).allowed
