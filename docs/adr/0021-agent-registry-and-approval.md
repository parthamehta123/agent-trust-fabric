# ADR-0021: Agent registry and approval workflow (Phase 4a)

- **Status:** accepted
- **Date:** 2026-10-13
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-CP-01, TM-TOOL-01, TM-TOOL-07, TM-INF-01, AS-8

## Context

Phase 3 authorized agents from interim `agents` maps inside gateway profiles (ADR-0016 §7,
ADR-0019 §4). Phase 4 makes the registry the source of truth. Decisions taken for the whole phase:

- **Cedar** is evaluated in-process (`cedarpy`, the official Rust engine) behind a
  `PolicyDecisionPoint` interface; an Amazon Verified Permissions adapter can follow in Phase 6
  (4b, ADR-0022).
- **Distribution** to gateways is by **signed policy bundles**: versioned, KMS-signed, rollback
  protected, deny when stale. Gateways never call the registry on the request path (4b).
- **Delegation chains**: at most two actors (user → A → B), both-sides allowlists, scopes narrowed
  at every hop (4c, ADR-0023). A2A Agent Cards are published in 4c.

## Decisions

1. **Service.** `services/agent_registry`: FastAPI admin API + DynamoDB. Admin-only: its port
   is never on an agent-facing network.

2. **Identity of admins.**
   - Bearer tokens from a dedicated `registry` AS: `aud = api://agent-registry`, scope
     `registry.admin`, `typ = at+jwt`. `sub` identifies the human.
   - Roles come from the token's `groups` claim (an Okta custom-AS groups claim in production):
     - `team-<owner_team>`: may create and edit drafts for that team's agents, and gives
       owner-team approval if also in `atf-registry-approvers`;
     - `atf-registry-approvers`: may approve `standard` agents;
     - `atf-security-approvers`: security approval, and revocation.
   - A missing or malformed `groups` claim means no roles.

3. **Record.** One immutable item per version: `agent_id` (= the agent's OAuth `client_id`;
   the registry never creates IdP clients), `version`, a strict `spec` (display name,
   description, owner team, tier, ingress T2 binding, tools → scopes, models → budget,
   delegation allowlists, scanner failure mode), `state`, `author`, `approvals`, timestamps,
   `expires_at`, and a revision counter `rev`.

4. **Workflow.** `draft → in_review → approved | rejected`; `approved → superseded | revoked`.
   - Only the author edits and submits a draft. One open (draft or in-review) version per agent.
   - Approval requirements by tier:

     | Tier | Required approvals | Extra rules |
     |---|---|---|
     | `standard` | 1 × `approver` | — |
     | `elevated` | `owner` + `security` | scanner fail-open rejected |
     | `privileged` | `owner` + `security` | scanner fail-open rejected; expires 90 days after approval; no `delegation = none` tools (checked at bundle build, 4b) |

   - Each approval names its role. The approver must be eligible for it, the role must be
     required and not yet satisfied, and **no person counts twice; the author never counts**.
   - When the requirements are met, the version becomes `approved` and the previous approved
     version becomes `superseded`, atomically (DynamoDB transaction). The old version keeps
     serving until then.
   - **Revocation** takes one security approver and is immediate: stopping access is easy,
     granting it is hard.
   - **Ownership transfer:** a new version must be created by a member of both the current
     approved owner team and the new one.

5. **Concurrency.** Every write is conditional: new versions on `attribute_not_exists`,
   transitions on the expected `state` **and** `rev`. Two approvers acting at once can't
   overwrite each other's approval. A losing writer gets `409` and retries on fresh state.

6. **Audit.** Every decision (allowed or denied) emits an audit event with the principal, agent,
   version and transition. Allowed changes are audited **before** the write; if the audit sink
   fails, nothing is written. The version items themselves are the history of record.

7. **API** (errors are `{"error": <code>}`, authentication checked before anything else):

   | Method and path | Action |
   |---|---|
   | `POST /registry/agents/{id}/versions` | create a draft (201) |
   | `PUT /registry/agents/{id}/versions/{v}` | edit a draft |
   | `POST /registry/agents/{id}/versions/{v}/submit` | draft → in_review |
   | `POST /registry/agents/{id}/versions/{v}/approve` | body `{"role": "approver" \| "owner" \| "security"}` |
   | `POST /registry/agents/{id}/versions/{v}/reject` | in_review → rejected |
   | `POST /registry/agents/{id}/revoke` | approved → revoked |
   | `GET /registry/agents/{id}/versions[/{v}]` | history / one version |

## Consequences

- TM-CP-01 is enforced server-side; the interim `agents` maps are retired in 4b.
- The registry depends on the IdP emitting a trustworthy `groups` claim. Group membership
  management becomes a governed process (Phase 6: Okta group rules, access reviews).
