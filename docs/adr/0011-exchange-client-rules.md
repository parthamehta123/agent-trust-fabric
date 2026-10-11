# ADR-0011: Exchange client rules (validation, retries, cache key)

- **Status:** accepted
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Amends:** ADR-0003 (cache key)
- **Threat-model refs:** TM-EXC-02, TM-EXC-03, TM-EXC-07, TM-EXC-08

## Decisions

1. **Validate the ID-JAG on receipt**, even though the interceptor only forwards it. Checks:
   - signature against the org AS JWKS;
   - `typ = oauth-id-jag+jwt`;
   - `iss` = org AS and `aud` = the profile's resource AS;
   - `client_id` = the bound front-end client, and `sub` = the bound user.

   This catches IdP mix-ups and misconfiguration at the source, instead of as an opaque
   `invalid_grant` one hop later.
2. **Validate T2 after it is minted (TM-EXC-02).** Checks:
   - signature against the resource AS JWKS, with `typ = at+jwt`;
   - `iss` = resource AS and `aud` = `profile.target.audience`;
   - `sub` and `client_id` match the binding;
   - `scope` ⊆ `profile.target.scopes`.

   Any failure is a deny. A T2 that is broader than requested is never forwarded.
3. **Retries.**
   - The HTTP adapter never retries.
   - The exchanger retries a call **once**, and only when no HTTP response was received
     (connect error or timeout). The retry uses a **freshly built client assertion**, because
     the IdP may already have consumed the first one's `jti`.
   - 4xx, 5xx and 429 responses are never retried and lead to a fast deny. A circuit breaker
     comes later (TM-EXC-07).
4. **Cache key (amends ADR-0003):**
   `SHA-256(AT.jti ‖ IDT.jti ‖ sub ‖ target_audience ‖ profile_id)`.
   - A new access token or a new ID token is always a cache miss.
   - If either token lacks a `jti`, the request is **not cached**. It never falls back to a
     weaker key.
   - TTL and bounds are unchanged: `min(T2.exp − 30 s, 300 s)`, LRU-bounded, process-local.
5. **HTTP adapter (`trustkit-http`, httpx):**
   - HTTPS URLs only, and TLS verification cannot be disabled through the API;
   - redirects are **never** followed;
   - connect and total timeouts;
   - response body capped at 64 KiB;
   - JSON accepted only with `application/json`;
   - IdP `error_description` is never propagated, only `error` codes from the RFC 6749/8693 set.

## Consequences

- Each cache miss costs two extra local signature verifications (negligible).
- The profile gains `idp.resource_jwks_uri` so the T2 issuer's keys can be resolved.
