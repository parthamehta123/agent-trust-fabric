# ADR-0007: Per-agent OAuth clients authenticated with KMS-signed `private_key_jwt`

- **Status:** accepted; ingress client selection amended by [ADR-0009](0009-ingress-id-jag-requested-by-frontend-client.md)
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Resolves:** OQ-2
- **Threat-model refs:** TM-EXC-01, TM-EXC-06, TM-EXC-08

## Context

Someone must authenticate to the IdP to request the ID-JAG, and that client's identity ends up in
`ID-JAG.client_id` and `T2.client_id`. With one shared client, T2 cannot tell agents apart and a
single key compromise affects everything.

## Decision

- **Identity:** each agent has its own OAuth client at the IdP. Its `client_id` is recorded in
  the agent's registry record (Phase 4). The interceptor requests the ID-JAG *as the target
  agent's client*, so `T2.client_id` identifies the agent.
- **Client authentication:** `private_key_jwt` ([RFC 7523 §2.2] / OIDC Core §9). The interceptor
  builds the client assertion and signs it with **`kms:Sign`**, so the private key never leaves
  KMS:
  - Claims `iss = sub = client_id`, `aud = token endpoint`, `jti` random, `exp ≤ now + 60 s`.
  - Header `kid` = a stable identifier derived from the KMS key.
  - Algorithm: `RS256` (KMS `RSASSA_PKCS1_V1_5_SHA_256`) or `ES256` (KMS `ECDSA_SHA_256`).
- **Least privilege:** the interceptor role may `kms:Sign` only on the keys referenced by declared
  profiles. The key policy pins `kms:SigningAlgorithm` and denies `kms:GetPublicKey` to everyone
  except the registration pipeline.
- **Rotation:** new KMS key → its public JWK is added to the client's JWKS at the IdP → profiles
  are switched → after a grace period the old JWK is removed and the old key disabled. The client
  keeps two active keys during the overlap.
- **Locally**, `trustkit` defines a `KeySigner` protocol. Tests use an in-memory signer, and
  `moto` KMS is used for adapter tests.

## Constraint to verify (A-4)

The ID-JAG draft has the IdP check that the requesting client is entitled to exchange the
subject token. Typically the ID token must have been **issued to that same client**
(`IDT.aud ∋ client_id`). If our IdP enforces this, the caller's ID token from a front-end client
cannot be exchanged by the *agent's* client. Possible resolutions, to be settled once verified:

1. The front-end client requests the ID-JAG (it holds the subject token's audience). The
   agent's identity then goes into T2 via the resource AS policy or an `act` claim.
2. The user signs in to each agent's client directly (works for agent-specific UIs, poor for
   shared chat front ends).
3. The IdP is configured to allow trusted clients to exchange tokens issued to a peer client,
   if the vendor supports it.

Phase 1 implements the mock IdP with this check **on**, so our tests reflect the strict reading.

## Consequences

- Strong attribution: agents can be revoked and rate-limited individually at the IdP.
- One KMS key and one IdP client per agent adds operational load, so provisioning must be
  automated (Phase 4/6).
- The KMS signing call adds a few ms per cache miss (already amortized by ADR-0003).

[RFC 7523 §2.2]: https://www.rfc-editor.org/rfc/rfc7523#section-2.2
