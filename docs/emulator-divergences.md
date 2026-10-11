# Emulator divergences

Every place where a local emulator (moto, LocalStack, the mock IdP) behaves differently from the
real service. Each entry states how the codebase stays correct against the **real** behaviour,
and each must be re-verified against the real service before Phase 6 (ADR-0005, RR-3).

| ID | Emulator | Behaviour in emulator | Real behaviour | How we stay correct | Verified against real |
|---|---|---|---|---|---|
| ED-1 | moto 5.x KMS | `Sign` with `MessageType=DIGEST` hashes the digest again (double hash) | Signs the supplied digest as-is | Use `MessageType=RAW` (ADR-0010); self-verify every signature | ☐ |
| ED-2 | moto 5.x KMS | `Sign` succeeds on a key in `Disabled` state | `DisabledException` | Any `ClientError` from `Sign` is a `SigningError`. The test injects the real error code. | ☐ |
| ED-3 | moto 5.x KMS | `DisableKey` with a full key ARN raises an internal `KeyError` | Accepts key ID or ARN | Tests pass the bare key ID | ☐ |
| ED-4 | moto 5.x KMS | `GetPublicKey` omits `KeySpec` (returns only the deprecated `CustomerMasterKeySpec`) | Returns both | Read `KeySpec`, fall back to `CustomerMasterKeySpec` | ☐ |
