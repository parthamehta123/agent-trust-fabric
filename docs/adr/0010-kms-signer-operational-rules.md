# ADR-0010: KMS signer operational rules

- **Status:** accepted
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Amends:** ADR-0007 (key policy no longer denies `kms:GetPublicKey` to the interceptor)
- **Threat-model refs:** TM-EXC-01, TM-EXC-06, RR-3

## Context

Implementing the KMS-backed `private_key_jwt` signer raised three operational questions that
ADR-0007 either did not cover or got wrong.

## Decisions

1. **Key spec: `ECC_NIST_P256` with ES256 only.** KMS returns DER-encoded ECDSA signatures.
   JOSE requires fixed-width `r || s` (RFC 7518 §3.4). `trustkit.signing.der_to_jose_es256`
   is the single conversion point. It range-checks `r` and `s` against the curve order and
   rejects trailing bytes.
2. **The interceptor may call `kms:GetPublicKey`.** ADR-0007 denied it, but a public key is not
   secret, so the deny added no protection. It also blocked three controls:
   - fail-closed cold-start checks of KeySpec, KeyUsage and allowed signing algorithms;
   - deriving `kid` as the RFC 7638 thumbprint;
   - verifying every signature locally.

   `kms:Sign` stays restricted to exact key ARNs, with the condition
   `kms:SigningAlgorithm = ECDSA_SHA_256`.
3. **`MessageType=RAW`.** In testing, moto double-hashes `DIGEST` messages, whereas real KMS
   signs the digest as given. Using RAW keeps the emulated and real code paths identical. The
   cost is that KMS sees the client assertion's signing input: about 400 bytes containing a
   client ID, a token endpoint and a random `jti`. None of it is secret, and RAW mode's 4 KiB
   limit is enforced before the call.
4. **Self-verify every signature** against the cached public key before returning it. A wrong
   signature (bad key, corruption, encoding bug, emulator drift) becomes a deny at the source,
   not an opaque `invalid_client` from the IdP. Cost is about 0.1 ms per token-cache miss.

## Consequences

- Misconfigured keys fail at cold start, not on the first user request.
- moto divergences found while building this (ED-1..ED-4) are tracked in
  [`docs/emulator-divergences.md`](../emulator-divergences.md) and must be verified against real
  KMS before Phase 6.
