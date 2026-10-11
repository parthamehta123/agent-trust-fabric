# ADR-0006: Ingress credentials (access token for the gateway, ID token as exchange subject)

- **Status:** accepted
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Resolves:** OQ-1
- **Threat-model refs:** TM-ING-01, TM-ING-02, TM-ING-06, TM-ING-08

## Context

The ID-JAG draft defines `subject_token` for the token-exchange step as an OIDC **ID token**
(alternatively a refresh token or SAML assertion), not an access token. However, OIDC guidance
says ID tokens should not be used as bearer credentials for APIs, and the managed gateway's
inbound authorizer expects an access token.

## Options considered

1. **Access token for the gateway, plus the ID token as the exchange subject.**
   Standards-conformant. Two credentials to bind.
2. **ID token only.** Misuses the ID token as an API credential.
3. **Access token as `subject_token`.** Non-standard and dependent on the vendor.

## Decision

Option 1. The caller sends:

| Header | Content | Validated by |
|---|---|---|
| `Authorization: Bearer <AT>` | Access token (T1) from the IdP's custom AS for the ingress audience | Proxy, gateway inbound authorizer, interceptor |
| `X-Subject-Token: <ID token>` | OIDC ID token from the same login | Interceptor only |

The interceptor **binds** the two before any exchange. All of these must hold, or the request is denied:

- Both have valid signatures from the expected issuer(s), and neither is expired.
- `AT.sub == IDT.sub`.
- `IDT.aud` contains a client ID registered as an allowed ingress client, and that client
  matches the AT's client claim (`cid` / `client_id`).
- `IDT.iat` is within the profile's `max_id_token_age` (default 3600 s). This limits how long a
  stale login can mint delegated tokens.

Both headers are **removed** before the request is forwarded. Only T2 continues.

## Consequences

- Clients must keep and send their ID token. This is a documented API contract.
- Header name `X-Subject-Token` is deliberately outside the reserved `x-atf-*` namespace,
  which inbound stripping covers (TM-RT-02).
- Depends on assumption A-1: the interceptor must be able to see both headers.
