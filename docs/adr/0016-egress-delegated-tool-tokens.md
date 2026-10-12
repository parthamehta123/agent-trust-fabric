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
