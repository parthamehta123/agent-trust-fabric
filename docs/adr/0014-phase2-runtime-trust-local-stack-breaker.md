# ADR-0014: Runtime trust, local stack shape, and IdP circuit breaker

- **Status:** accepted
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Resolves:** OQ-5
- **Threat-model refs:** TM-RT-01, TM-RT-02, TM-EXC-07, RR-3

## Decisions

1. **Proof of transit (OQ-5): T2 validation in the runtime, plus network isolation.**
   - Every agent runtime validates T2 itself with `trustkit.resource.ResourceAuthorizer`:
     - signature against the resource AS JWKS;
     - `typ = at+jwt`, and `iss` = its resource AS;
     - `aud` = its own audience, and it is unexpired;
     - it carries the scope the operation requires.
   - In AWS, the AgentCore Runtime inbound JWT authorizer is configured with the same issuer and
     audience as a second, independent check (assumption **A-7**, to verify). The runtime is
     reachable only through the gateway.
   - `x-atf-*` headers never carry authorization meaning in the runtime (TM-RT-02).
   - Rejected for now: a gateway-signed attestation header. It proves transit through *our*
     interceptor, beyond possession of a valid T2, but adds a key and its rotation. Revisit if a
     stolen-T2 replay becomes a credible threat beyond T2's 300 s life and audience binding.
2. **Local TLS uses an ephemeral CA.**
   - A script generates a throwaway CA and service certificates at stack start-up. They are
     gitignored and never committed.
   - Containers trust only that CA.
   - No code path anywhere permits plain HTTP, so production and local code paths stay identical.
3. **The gateway emulator** (`packages/gateway_emulator`) is TEST INFRASTRUCTURE ONLY, built the
   same way as the mock IdP: a pure-Python core for in-process tests plus a thin FastAPI shell for
   compose. It reproduces the documented AgentCore Gateway behaviour around interceptors (ADR-0012
   sources):
   - the inbound JWT check;
   - the `http` event shape and the Lambda client context;
   - short-circuit on a REQUEST deny;
   - header propagation (`Authorization` from the interceptor; other headers only if allowlisted;
     the interceptor wins conflicts; **client-sent allowlisted headers pass through when the
     interceptor omits them**, the pessimistic reading of A-5);
   - buffered RESPONSE interception.

   Where real behaviour is unknown (A-6: interceptor error or malformed output), the emulator fails
   closed and the gap is logged in `emulator-divergences.md`.
4. **IdP circuit breaker (TM-EXC-07).**
   - Scoped per Lambda execution environment, per token endpoint.
   - **Open** after 5 consecutive failures. Only transport errors, 5xx and 429 count; 4xx policy
     answers prove the IdP is healthy.
   - **Half-open** after a 30 s cooldown, allowing exactly one probe. Success closes the breaker;
     failure re-opens it.
   - While open, the exchanger denies instantly with `CIRCUIT_OPEN` (503) and makes no IdP call.
   - State transitions are audited.
5. **Header-allowlist policy.** `trustkit.policy.check_target_allowlist` is used by the emulator
   now and by Terraform validation tests in Phase 6. It:
   - rejects credential-bearing headers (`authorization`, `x-subject-token`, `cookie`,
     `proxy-authorization`, `x-api-key`);
   - **requires** every reserved `x-atf-*` header, so the interceptor's overwrites (ADR-0012 §4)
     actually reach the runtime;
   - leaves other non-credential headers (e.g. correlation IDs) to per-target review.
