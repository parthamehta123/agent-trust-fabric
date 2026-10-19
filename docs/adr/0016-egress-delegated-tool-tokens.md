# ADR-0016: Egress delegated tool tokens (actor token + gateway client); OQ-4 closed

- **Status:** accepted
- **Date:** 2026-10-12
- **Deciders:** Partha Mehta
- **Implements:** ADR-0008. **Amends:** ADR-0007 (meaning of the egress profile's `client`).
- **Resolves:** OQ-4
- **Threat-model refs:** TM-TOOL-01, TM-TOOL-02, TM-TOOL-07, TM-EXC-02, TM-EXC-03

## Decisions

1. **OQ-4 is closed: no separate ingress proxy.** The AgentCore Gateway JWT authorizer, the
   interceptor and (Phase 6) AWS WAF cover the edge. A proxy would hold caller tokens without
   adding a control.

2. **Agent workload token (the actor).**
   - The agent runtime runs OAuth `client_credentials` with **its own client** at a dedicated
     *workload* AS, authenticating with `private_key_jwt` signed through `kms:Sign` (ADR-0007/0010).
     The key never leaves the agent's KMS key.
   - The token is RFC 9068 `at+jwt` with `sub = client_id = agent` and `aud = tool gateway`, and a
     lifetime of at most 300 s. The runtime caches it until `exp − 30 s` (`trustkit.workload`).

3. **What the agent sends to the tool gateway:**
   - `Authorization: Bearer <workload token>`, validated by the gateway's inbound JWT authorizer
     and again by the interceptor;
   - `X-Subject-Token: <T2>`, the user-delegated token the agent received on ingress
     (`aud = this agent`).

4. **Egress binding (the confused-deputy guard, TM-TOOL-01).** All of these must hold, or the
   request is denied:
   - the workload token is valid under `profile.egress_inbound`, and its `client_id` is in
     `profile.agents`;
   - T2 is valid under that agent's own entry (`t2_issuer`, `t2_audience`, `t2_jwks_uri`). That
     means **agent A cannot spend a T2 that was issued to agent B**;
   - T2 carries **no `act`**: delegation depth is at most 1, and chains are denied until the
     Phase 4 registry can authorize them (TM-TOOL-07);
   - the subject's `sub` is kept, and the actor is the workload `client_id`.

5. **Exchange (RFC 8693) at the tool's AS** (`profile.idp.resource_token_endpoint`).
   - Request: `subject_token` = T2 and `actor_token` = the workload token (both of type
     `access_token`), `audience` = the tool AS issuer, `resource` = `target.audience`, and `scope`
     = `target.scopes ∩ agents[agent].allowed_scopes`.
   - Client authentication is the **tool gateway's own client** (`profile.client`, KMS
     `private_key_jwt`). The interceptor never holds agent keys.
   - The tool AS must also verify that the actor is the agent the subject token was issued to.
     The mock tool AS enforces this, so the guard exists at both layers.

6. **Post-mint validation.** The delegated token must satisfy all of the following, or it is not
   forwarded (TM-EXC-02):
   - `typ = at+jwt`, `iss` = tool AS, `aud` = `target.audience`;
   - `sub = T2.sub`, `act.sub` = agent, no nested `act`, `client_id` = gateway client;
   - `scope` ⊆ requested.

   It is cached under `SHA-256(T2.jti ‖ workload.jti ‖ sub ‖ tool aud ‖ profile)`, with the same
   rules as ADR-0011.

7. **Interim configuration.** Egress profiles carry:
   - `egress_inbound`: `{issuer, audiences, jwks_uri}` for workload tokens;
   - `agents`: `{client_id: {t2_issuer, t2_audience, t2_jwks_uri, allowed_scopes}}`;
   - `client`: the **tool gateway's** client. This amends ADR-0007, where the egress `client`
     meant the agent.

   Phase 4 replaces the `agents` map with registry lookups behind the same interface.

## Consequences

- The agent key stays with the agent, and the interceptor holds only gateway keys.
- Each tool sees user, agent and scopes: full attribution.
- Third-party tools that cannot accept delegated tokens use the per-target credential path
  (`delegation = none`) in slice 3b.

## RFC self-review of the token exchange (2026-10-19)

`trustkit.exchange` (ingress ID-JAG and T2, egress delegation), the client assertions and the
mock IdP, reviewed against RFC 8693, RFC 7523, the ID-JAG draft and Okta's documentation. As
configured, nothing let a forged or over-scoped token through. Each code finding has a
regression test (`tests/exchange/test_token_exchange_review.py`, `TestOktaProfile`).

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | **High (interop: blocks the sandbox; fails closed)** | Every access-token validator required `typ: at+jwt`, a `scope` string and `client_id` (RFC 9068). Okta custom authorization servers send **no `typ`**, **`scp`** (array) and **`cid`**, and a user's `sub` is their login with the id in `uid`. Every real workload, T2, tool and admin token would have been refused; the mock issued the RFC 9068 shape, so no test could see it. | `AccessTokenProfile` per deployment (`ATF_ACCESS_TOKEN_PROFILE`; IaC `okta`). The `okta` profile accepts a *missing* `typ` where `at+jwt` is expected (any other `typ` is still refused, RFC 8725 §2.8) and normalises `scp`→`scope`, `cid`→`client_id` and `uid`→`sub`; conflicting pairs are `malformed`. The mock IdP issues Okta-shaped tokens in compose, so CI runs the real shape. **A-15.** |
| 2 | Medium (unrecorded assumptions) | Delegated tool tokens depend on Okta accepting `actor_token` and emitting `act` exactly; undocumented by Okta and unrecorded here. | **A-16**, with a sandbox verification row. **Fallback if it fails:** the gateway's own client gets the tool token by token exchange with the subject token alone, and the actor travels in a signed header the tool verifies against the gateway's key. That needs its own ADR before any code. |
| 3 | Low | The ingress T2 cache key omitted the requested scopes and the client (the delegated key already had them): narrowing a profile's scopes left a broader cached T2 in use for up to 5 min. | Client and sorted scopes are in the key. |
| 4 | Low (availability) | After a timeout the JWT-bearer step was retried with the **same** ID-JAG; if the first request had reached the IdP, its single-use `jti` was spent and the retry could only fail. | `TransportError.maybe_sent`: only a connect failure is "never sent". Steps with single-use input retry only then; the other steps still retry after a timeout. |

**Verified correct (no change):**
- **Client assertions (RFC 7523 §3):** ES256, `iss`/`sub` = client, `aud` = token endpoint, a lifetime of 60 s or less, a 256-bit `jti`, and a fresh assertion for every attempt.
- **Audience injection:** the 2025 issue that led rfc7523bis to prefer `aud` = issuer doesn't apply. Endpoints come from config or trusted IdP origins (ADR-0027 review #1), never from discovered metadata, and Okta requires the token endpoint as `aud`.
- **RFC 8693 responses:** `issued_token_type` and `token_type` are checked (`N_A` for the ID-JAG, `Bearer` for access tokens).
- **Every minted token is validated before use or caching:**
  - `iss`, `aud`, `typ` and the signature are checked;
  - the ID-JAG and T2 must name the same user and client (mix-up defence);
  - the delegated token must carry exactly the expected `act` chain and the gateway's client;
  - scopes can only narrow.
- **IdP errors:** only RFC 6749 codes are surfaced, and descriptions are dropped.
- **Cache:** keys are per user and length-prefixed, with no fallback key. Only 5xx and 429 responses count as IdP failures.
- **Mock IdP:**
  - client authentication is `private_key_jwt` only, with `aud`, lifetime and `jti` replay checks;
  - ID-JAGs are single use;
  - delegation requires the actor to be the agent the subject token was issued to, caps chains and checks the target.

