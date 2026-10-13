"""Build verified-shape policy bundles for gateway tests (real Cedar, real guardrails)."""

from __future__ import annotations

import json
import pathlib
from typing import Any

from trustkit_policy.bundle import Bundle, LoadedBundle
from trustkit_policy.grants import AgentGrant, generate_permits
from trustkit_policy.pdp import CedarPdp

GUARDRAILS = (pathlib.Path(__file__).parents[2] / "policies" / "guardrails.cedar").read_text()


def make_grant(agent_id: str, **over: Any) -> AgentGrant:
    doc: dict[str, Any] = {
        "agent_id": agent_id,
        "record_version": 1,
        "tier": "standard",
        "owner_team": "alpha",
        "tools": {"tickets": ["tickets.read"]},
        "models": {},
    }
    doc.update(over)
    return AgentGrant.model_validate_json(json.dumps(doc))


def t2_binding(base: str, agent_as: str, audience: str) -> dict[str, str]:
    return {
        "t2_issuer": f"{base}/oauth2/{agent_as}",
        "t2_audience": audience,
        "t2_jwks_uri": f"{base}/oauth2/{agent_as}/v1/keys",
    }


def loaded_bundle(*grants: AgentGrant, version: int = 1, iat: int = 1_800_000_000) -> LoadedBundle:
    gs = {g.agent_id: g for g in grants}
    policies = generate_permits(gs) + "\n" + GUARDRAILS
    bundle = Bundle(
        iss="atf-bundle-publisher",
        bundle_version=version,
        iat=iat,
        exp=iat + 600,
        agents=gs,
        policies=policies,
    )
    return LoadedBundle(bundle, raw=b"", pdp=CedarPdp(policies, gs))
