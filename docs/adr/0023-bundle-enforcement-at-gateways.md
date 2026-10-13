# ADR-0023: Bundle enforcement at the gateways (Phase 4b-ii)

- **Status:** accepted
- **Date:** 2026-10-13
- **Deciders:** Partha Mehta
- **Amends:** ADR-0016 §7 (egress `agents` map removed), ADR-0019 §4 and ADR-0020 §2 (inference
  `agents` map and routes coverage check removed)
- **Threat-model refs:** TM-TOOL-01, TM-TOOL-08, TM-INF-01, TM-INF-02, TM-CP-07

## Decisions

1. **User entitlements travel in T2's `scope`.**
   - The ingress exchange requests the downstream scopes an agent may use on the user's behalf
     (e.g. `agent.invoke tickets.read`).
   - The IdP grants only those the user is entitled to (in Okta: custom-AS access policies per
     group). It *downscopes* rather than refusing (RFC 6749 §3.3), and errors only if nothing
     requested is grantable.
   - Gateways pass T2's `scope` to Cedar as `context.user_scopes`, so `guardrail:user-scopes`
     enforces user ∩ agent at every gateway. The tool AS re-checks at exchange.
   - The mock IdP models this with per-AS `restricted_scopes: {scope: [subjects]}`.

2. **One wiring for every gateway.**
   - `trustkit_policy.runtime.policy_from_env` builds settings, source, holder and guard.
   - Source: `ATF_BUNDLE_PATH` (a read-only mount) **or** `ATF_BUNDLE_S3_BUCKET` +
     `ATF_BUNDLE_S3_KEY`. Both, or neither, is a cold-start failure.
   - `ATF_BUNDLE_MAX_AGE_S` has a ceiling of 600 s and must exceed `ATF_BUNDLE_REFRESH_S`.
   - The pinned key must be a public JWK.
   - Every refresh outcome except `unchanged` is audited as `bundle.refresh`.

3. **Lazy single-flight refresh.**
   - On a request, if the last refresh is due, one caller refreshes without blocking; the others
     use the current bundle.
   - This works unchanged in Lambda and in long-running services.
   - Staleness is judged on the bundle's own `iat`, so an idle gateway can't serve an old bundle.

4. **Interceptor (egress).**
   - Egress profiles name their registry `server_id`; a legacy `agents` map is rejected by the
     schema.
   - Order: no fresh bundle → **503 `policy_unavailable`**; bind the actor from bundle grants
     (`scopes_for` = grant.tools[server_id] ∩ target scopes); Cedar `invoke_tool` must allow,
     else **403 `policy_denied`**, with policy ids audited; then the delegated exchange.
   - An ingress-only deployment configures no bundle, so every egress request is denied.

5. **MCP gateway.**
   - The binder takes agents from the bundle; with no bundle it answers 503.
   - The proxy calls an `authorize(binding, record)` hook on **every** list and call:
     - requested = grant.tools[server] ∩ record.scopes;
     - Cedar sees the record's delegation mode and the user's scopes;
     - the hook re-reads the bundle on each call, so a revocation after binding takes effect
       immediately.
   - A denied server is hidden from listings, and its tools return the same error as a missing
     tool (no policy oracle).
   - The delegated exchange uses exactly the requested scopes.

6. **Inference gateway.**
   - The profile keeps gateway settings only.
   - Per request: the grant (absent or expired → 403 `agent_not_allowed`), then the model (not
     granted, or not routable at this gateway → 403 `model_not_allowed` before any spend), then
     Cedar `call_model`.
   - Max tokens come from the grant.
   - Budgets are counted per **agent + model**, because the registry grants budgets per model.

7. **Scanner fail mode:** the most restrictive setting wins. Open only if the gateway profile
   **and** the agent's grant both say open.

8. **Delegated-token cache key includes the requested scopes (TM-TOOL-08).** A bundle that
   narrows an agent's grant can never be answered with a token minted under the broader grant.

## Consequences

- No interim authorization maps remain. What an agent may do is decided only by approved
  registry records, the guardrails and the user's entitlements, through one signed artefact.
- A gateway with no fresh bundle refuses everything it would otherwise authorize. This is
  deliberate: availability depends on the publisher heartbeat (ADR-0022 §7).
