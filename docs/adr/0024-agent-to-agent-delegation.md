# ADR-0024: Agent-to-agent delegation and Agent Cards (Phase 4c)

- **Status:** accepted
- **Date:** 2026-10-13
- **Deciders:** Partha Mehta
- **Amends:** ADR-0008 and ADR-0016 (delegation depth 1 → at most two actors), ADR-0021 §4
  (edge approval), ADR-0022 §2 (`delegate` action)
- **Threat-model refs:** TM-TOOL-07, TM-TOOL-01, TM-CP-01, TM-A2A-01..04

## Flow

```
user ──T2_A──▶ agent A ──(workload_A + T2_A)──▶ a2a-gateway ──exchange @ B's AS──▶ T_B
                                                     │   sub = user, aud = B, act = {sub: A}
                                                     └──▶ B's runtime (validates T_B itself)
agent B ──(workload_B + T_B)──▶ tool gateway ──exchange @ tool AS──▶ tool token
                                     sub = user, act = {sub: B, act: {sub: A}}   (RFC 8693 §4.1)
```

## Decisions

1. **A dedicated `a2a-gateway`** brokers every agent → agent call. It speaks the A2A JSON-RPC
   subset `message/send`.
   - It binds A (workload token + T2_A) and runs Cedar `delegate` A → B.
   - It exchanges at B's AS using its own client: subject = T2_A, actor = workload_A.
   - It forwards to B's runtime and scans both directions.
   - Agents never hold exchange credentials.

2. **Chains are capped at two actors.**
   - `bind_actor(..., max_prior_actors=1)` parses the subject's `act` chain strictly. Each
     level is exactly `{sub}` or `{sub, act}`; anything else, or deeper, is `DELEGATION_CHAIN`.
   - `exchange_delegated` validates that the issued token's `act` equals the expected nested
     chain *exactly*.
   - The IdP enforces the same cap.

3. **No amplification: everything is decided in Cedar.** A call by B on behalf of A is allowed
   only if all three hold:
   - `invoke_tool` for **B**;
   - `invoke_tool` for **A**, for the same server and scopes;
   - `delegate` **A → B**.

   All are evaluated against the *current* bundle on every hop, so revoking A, B or the edge
   ends in-flight chains at their next hop. The user-scope guardrail applies to every
   evaluation.

4. **Edges need both sides.**
   - A `delegate` permit is generated only when A's record lists B in `may_delegate_to` **and**
     B's lists A in `accepts_delegation_from`.
   - Any record version that *adds* an edge needs a **security approval** on top of its tier's
     approvals. Removing an edge needs nothing extra.

5. **B validates its inbound token itself** (as ADR-0014): `iss` = B's AS, `aud` = B,
   `act.sub` in B's `accepts_delegation_from` (from the bundle), depth ≤ 2, no unknown `act`
   members.

6. **Agent Cards.**
   - Approved records may carry a card (description, skills, and the *internal* runtime
     endpoint). The publisher puts cards in the signed bundle.
   - The A2A gateway serves `GET /agents/{id}/.well-known/agent-card.json` only to an
     authenticated agent that may delegate to `{id}` (least disclosure).
   - The served card's `url` is the gateway's endpoint, never the runtime's.
   - Revoking an agent removes its card at the next refresh.

7. **Audit:** decisions carry `actor_chain`, the prior actors oldest-first, alongside
   `client_id` (the current actor) and the `policy_ids`.

## Implementation notes (4c-ii)

- The A2A gateway reuses the MCP gateway's SSRF pinning, now shared as `trustkit_http.ssrf`.
- Runtimes refuse any `act` by default (`ResourceAuthorizer(accept_actor=None)`). Before this,
  `act` was silently ignored (TM-A2A-05).
- The broker audits an allowed delegation **before** minting B's token; if the audit write
  fails, nothing is minted or forwarded (503).
- Agents receive the inbound bearer token as an explicit third argument, so they can act on the
  user's behalf downstream. It is never placed in `Principal`, logged or echoed.

## Consequences

- TM-TOOL-07 changes from "chains denied" to "chains bounded, both-sides, non-amplifying".
- Each hop costs one more exchange and three Cedar evaluations; all are in-process except the
  exchange.
