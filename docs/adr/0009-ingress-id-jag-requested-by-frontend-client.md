# ADR-0009: On ingress, the front-end client requests the ID-JAG

- **Status:** accepted
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Amends:** ADR-0007 (which client requests the ID-JAG on **ingress**; egress is unchanged);
  ADR-0006 (the freshness bound uses `auth_time`, not `iat`)
- **Resolves:** assumption A-4
- **Threat-model refs:** TM-EXC-01, TM-EXC-06, TM-ING-08

## Context

ADR-0006 makes the user's OIDC ID token the `subject_token` of the ID-JAG exchange. That ID
token is issued to the **front-end client** the user signed in to (`IDT.aud`). Under the strict
reading of the ID-JAG draft, the IdP only lets the client the subject token was issued to
exchange it. ADR-0007 assumed the *agent's* client would request the ID-JAG, which the strict
reading forbids.

## Decision

- **Ingress:** the interceptor requests the ID-JAG **as the front-end client** identified by
  the access-token ↔ ID-token binding (ADR-0006). It authenticates with that client's
  KMS-signed `private_key_jwt`. The resulting T2 is:
  - `sub` = user
  - `client_id` = front-end client
  - `aud` = the target agent (it comes from the profile, never from the request)

  The agent's identity is the **audience**. It is not an actor, so no `act` claim is involved on
  ingress.
- **Egress is unchanged:** per-agent clients (ADR-0007) authenticate the agent's own workload
  token, which is the `actor_token` in ADR-0008. `act` appears only where the agent acts on
  behalf of the user.
- **Profile schema change:** ingress profiles carry `ingress_clients: {client_id: signing_key}`
  (non-empty) and **no** `client`. The binding step picks the entry, and an unlisted client is
  denied. Egress profiles require `client` (the agent) and forbid `ingress_clients`.
- **Login freshness (amends ADR-0006):** binding requires the ID token's `auth_time` and enforces
  `now − auth_time ≤ max_auth_age_s`. Okta silently re-issues ID tokens on session refresh, so
  `iat` measures token issuance, not authentication. A fresh `iat` on a 30-day-old login must not
  pass. `iat` is still validated by the generic checks (not in the future, bounded by `exp`).

## Consequences

- Strict-spec safe: no reliance on vendor-specific trust relaxations.
- **Blast radius:** the interceptor role can `kms:Sign` with front-end client keys as well as agent
  keys. Mitigations:
  - The IAM policy is generated from profiles, naming exact key ARNs (TM-EXC-06).
  - Each front-end client's grant at the IdP is restricted to the resource ASes of the agents
    it fronts, so a misused front-end key can only mint T2s for those agents.
- The mock IdP enforces the strict rule (`IDT.aud ∋ requesting client_id`), so a regression to
  the old design fails the tests.
