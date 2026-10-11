# ADR-0008: Delegated per-target tool tokens with an `act` claim

- **Status:** accepted
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Resolves:** OQ-3
- **Threat-model refs:** TM-TOOL-01, TM-TOOL-02, TM-TOOL-07

## Context

When an agent calls a tool on behalf of a user, the tool must be able to answer "who is the user,
and which agent is acting for them?" The MCP authorization spec prohibits passing a client's
token through to downstream services.

## Decision

- The tool gateway's interceptor (same deployment, **egress** profile, consistent with ADR-0002)
  performs an [RFC 8693] exchange for every tool target:
  - `subject_token` = the T2 the agent received (it represents the user).
  - `actor_token` = the agent's workload token (client credentials of the agent's own client,
    ADR-0007).
  - `audience` / `resource` = that tool target only.
- The resulting token has `sub = user`, `aud = tool`, and `act = { "sub": <agent client_id> }`.
  Scopes are the intersection of (agent record allowed actions) ∩ (tool profile scopes).
- **Delegation depth:** at most one `act` level by default. Agent-to-agent chains (nested `act`)
  are denied unless both agent records explicitly allow delegation (Phase 4).
- Tools that cannot accept delegated tokens get a per-target credential instead, with a
  `delegation = none` flag in their profile. That flag is visible in review and in audit.
  It is never passthrough.

## Consequences

- Full attribution at the tool: user, agent, scope.
- Requires the tool's authorization server to support token exchange. Our resource AS and the
  mock IdP do. Third-party SaaS will often fall into the `delegation = none` path.
- A cached delegated token follows ADR-0003 rules, with the key extended by tool audience and
  actor.

[RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693
