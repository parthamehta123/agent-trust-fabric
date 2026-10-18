# ADR-0027: IdP signing-key rotation and revocation at token validators

- **Status:** accepted
- **Date:** 2026-10-18
- **Deciders:** Partha Mehta
- **Amends:** the JWKS refresh rules in `trustkit.jwt.JwksKeyResolver` (Phase 1, TM-ING-03)
- **Threat-model refs:** TM-ING-03, TM-RT-01, TM-CP-07

## Context

Every service that validates an IdP token resolves the signing key through
`JwksKeyResolver`. Today it does three things:

| Situation | Behaviour | Bound |
|---|---|---|
| Key set older than `max_key_age_s` | proactive refetch on the next validation | **1 h** |
| Token carries an **unknown** `kid` | one refetch, rate-limited | at most one per **60 s** |
| Fetch fails | keep the last good set | at most **24 h** since the last success, then nothing resolves |
| Token carries a **known** `kid` but its signature doesn't verify | `BAD_SIGNATURE`, **no refetch** | until the next proactive refresh (≤ 1 h) |

**What surfaced it (PR #8).** On GitHub's runners a test restart recreated the mock IdP. The
mock generates **fresh keys on every start but reuses fixed `kid`s** (`org-k1`, `<as>-k1`), so
after the recreate every token carried a `kid` the gateways already knew, with different key
material. Every token failed with `BAD_SIGNATURE`. None triggered the unknown-`kid` refetch, so
the gateways stayed broken for the full proactive interval: 401s that no wait could fix.

Reusing a `kid` for new key material violates the spirit of RFC 7517 §4.5. Real Okta rotates
with a new `kid` and publishes the next key before signing with it, so production would recover
through the unknown-`kid` path. The incident nonetheless exposes two properties worth deciding
deliberately:

1. **Availability under abrupt rotation.** A validator can't tell "the IdP rotated and reused a
   `kid`" from "this token is forged". Today it assumes forged, for up to an hour.
2. **Revocation latency (the security-relevant one).** If an IdP signing key is
   **compromised** and the IdP removes it from its JWKS, our validators keep accepting tokens
   signed with it until their cached set is older than `max_key_age_s`. That is **up to 1 hour
   of trusting a key the IdP has already revoked.** Nothing in the request path shortens it: the
   attacker's tokens carry a *known* `kid`, so they never trigger a refetch.

## Options considered

**A. Keep the current rules and document them.** No code change. Abrupt rotation can cost up to
1 h of availability, and the revocation window stays 1 h.

**B. Treat a signature failure on a known `kid` like an unknown `kid`.** Allow one
rate-limited refetch, then retry verification once against the new set.
- *Pro:* recovers from `kid` reuse within 60 s.
- *Amplification:* none new. A forger can already force one refetch per 60 s with a random
  `kid`; this shares the same budget.
- *Con:* does **nothing** for revocation, because the compromised key still verifies.

**C. Shorten `max_key_age_s` from 1 h to 5 min.**
- *Pro:* bounds the revocation window at 5 min and also covers `kid` reuse.
- *Con:* about 12 JWKS fetches per hour per validator per issuer, which is negligible against
  Okta's rate limits for our handful of services.

**D. An operator "revoke now" path.** A documented step that forces every validator to
refetch immediately: a rolling restart in AWS (new tasks start with an empty cache), or `make up`
locally. It's a runbook item rather than code, and it closes the window to deployment time when
the operator acts.

**E. Make the mock IdP realistic.** RFC 7638 thumbprint `kid`s, which it already uses for our
own ES256 client keys, so new key material always means a new `kid`. This fixes test fidelity
independently of A–D.

## Decision

Adopted **B + C + D + E** (accepted 2026-10-18):

1. **B:** a `BAD_SIGNATURE` on a known `kid` performs one refetch through the shared
   unknown-`kid` rate limit (≤ 1 per 60 s) and re-verifies **once**. Never more than one retry
   per token, and never a refetch outside the shared budget. Tests: `kid` reuse recovers in one
   refetch, and a forged-signature flood causes at most one fetch per 60 s.
2. **C:** `max_key_age_s` defaults to **300 s**. The revocation window for a compromised IdP key
   is ≤ 5 min plus one request. The 24 h failure staleness bound is unchanged.
3. **D:** the sandbox runbook gains "IdP key compromise". Revoke the key in the IdP, then force a
   rolling restart of every validator: the ECS services, the interceptor (publish a new Lambda
   version or update its configuration), and the agent runtimes. Record the time in the audit
   trail.
4. **E:** the mock IdP derives each `kid` from the key's RFC 7638 thumbprint. Bundle and client
   keys already do.

## Consequences

- **Positive:**
  - An abrupt rotation recovers in about a minute.
  - A revoked IdP key stops being trusted within about 5 minutes without operator action, and
    immediately with D.
  - The test IdP behaves like a real one.
- **Negative / accepted:**
  - About 12 extra JWKS fetches per hour per validator per issuer.
  - B adds one extra signature verification on the failure path only.
  - The revocation window is reduced, not eliminated. **RR-9** records it: ≤ 5 min plus
    operator time, and immediate with D.
- **Not changed:** the 60 s unknown-`kid` rate limit, the 24 h failure staleness, and the
  rejection of `jku`/`x5u`/`jwk`/`x5c` headers (TM-ING-03). The JWKS URL remains pinned per
  issuer.
- **Follow-ups:** implement B, C and E in one PR with tests; D in the runbook; TM-ING-03 and
  RR-9 in the threat model; then verify on the sandbox apply that Okta key rotation (with a new
  `kid`) is picked up without errors.
