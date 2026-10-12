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
| ED-5 | gateway-emulator | Client-sent allowlisted headers pass through when the interceptor omits them | Unknown whether interceptors can remove client headers (A-5) | Pessimistic on purpose: the interceptor always overwrites reserved headers | ☐ |
| ED-6 | gateway-emulator | Interceptor exception or malformed output gives 502, target not called | Undocumented (A-6) | Our handler never raises. If real AWS fails open, ADR-0012 §3 still holds. | ☐ |
| ED-7 | gateway-emulator | Inbound JWT check: signature, `iss`, `aud`, `exp` only | Real authorizer also supports `allowedClients`, scopes, discovery-URL caching | Interceptor re-validates the access token with the full trustkit validator (defence in depth) | ☐ |
| ED-8 | Lambda RIE (`public.ecr.aws/lambda/python:3.12`) | Invoked over plain HTTP on the internal compose network. Client context via `X-Amz-Client-Context` (verified by probe 2026-10-12) | Lambda service invokes the function over its own internal channel | Hop confined to the `core` network. All other hops use TLS with a single trusted CA (ADR-0015) | ☐ |
| ED-9 | DynamoDB Local (`amazon/dynamodb-local`, pinned) | Accepts any alphanumeric access key; no IAM; plain HTTP on the internal `ddb-*` networks | IAM-authenticated, TLS endpoint, KMS-encrypted table | Local stack only uses dummy alphanumeric keys; table IAM/KMS/PITR come with Terraform (Phase 6). Conditional-write semantics are exercised for real. Its `/tmp` is mounted `exec` (native SQLite library); all other hardening is kept. | ☐ |
| ED-10 | botocore `Stubber` (moto has no `ApplyGuardrail`) | Returns exactly the canned response; validates request and response shapes against the botocore model only | Real guardrail evaluation, latency, throttling, and fields newer than the pinned botocore model | Adapter judges each finding by its own `action`, ignores bookkeeping keys (`invocationMetrics`), and treats unknown policy shapes as BLOCK (fail closed). Scanner errors map to `ScannerUnavailableError` → profile fail mode. | ☐ |
| ED-11 | `mock-llm` (test infrastructure) | OpenAI-compatible API through LiteLLM's `openai/` provider; deterministic replies; usage roughly chars/4 | Bedrock through LiteLLM's `bedrock/` provider (SigV4, Converse API), real tokenization, throttling and provider errors | Budgets settle on the provider's reported usage, whichever provider it is. Provider errors map to a generic 502 and release the reservation (unit-tested). The Bedrock provider path is verified in Phase 6. | ☐ |
