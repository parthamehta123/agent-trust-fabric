# ADR-0022: Cedar decision point and signed policy bundles (Phase 4b)

- **Status:** accepted
- **Date:** 2026-10-13
- **Deciders:** Partha Mehta
- **Supersedes:** the interim `agents` maps of ADR-0016 §7 and ADR-0019 §4
- **Threat-model refs:** TM-TOOL-01, TM-INF-01, TM-CP-01, TM-CP-03, RR-5

## Decisions

1. **Engine.**
   - Cedar runs in-process through `cedarpy` 4.12.1, which wraps the official `cedar-policy`
     4.12.0 Rust crate. It sits in a new `trustkit-policy` package, so services that don't
     evaluate policy never load the native library.
   - Vetted 2026-10-13: wheel hashes match PyPI and every file matches RECORD; the licence is
     Apache-2.0; the embedded SBOM lists 133 crates, all permissively licensed; no runtime Python
     dependencies; `pip-audit` clean.
   - **No PyPI provenance attestation is published** (RR-5).

2. **Cedar model** (namespace `Atf`, schema in `trustkit_policy.schema`):

   | Element | Definition |
   |---|---|
   | Principals | `Agent` (attribute `tier`), a member of `Team` |
   | Resources | `McpServer` (attribute `delegation`, supplied by the gateway per request), `Model` |
   | Actions | `invoke_tool` (context `user`, `user_scopes`, `scopes`), `call_model`; `delegate` comes in 4c |

   - Identifiers enter requests in Cedar's structured `{type, id}` form, never through the text
     parser. In generated policy text they are restricted to `[A-Za-z0-9._:/-]` and re-checked
     by the generator.

3. **Who writes policy.**
   - `permit` policies are **generated** from approved registry records: one per (agent, server)
     with the granted scopes, and one per (agent, model).
   - Platform-wide `forbid` **guardrails** live in `policies/*.cedar` under CODEOWNERS.
   - Cedar's forbid-overrides-permit semantics mean no generated permit can override a guardrail.
   - The first guardrails:
     - the requested scopes must be among the *user's* scopes (TM-TOOL-01);
     - privileged agents never use `delegation = none` servers (ADR-0021 §4).

4. **Decision point (PEP contract).**
   - Policies are validated against the schema when a bundle loads; an invalid bundle is refused.
   - Any evaluation error, schema mismatch or `NoDecision` is **deny**.
   - The determining policy ids are returned for audit.

5. **Bundle.**
   - A compact JWS: `alg = ES256`, `typ = atf-bundle+jwt`, `kid` = key thumbprint, and no other
     header fields (`jku`, `x5u` and the like are refused).
   - Payload: `iss`, `bundle_version`, `iat`, `exp`, `agents` (one grant per effective agent:
     T2 binding, tools, models with budgets, delegation rights, tier, scanner mode, the grant's
     own `expires_at`), and the full `policies` text that was evaluated.
   - Maximum size 4 MiB. `exp − iat` may not exceed the 10-minute maximum age.

6. **Verification at gateways.**
   - The verification key is **pinned in gateway config**, never fetched.
   - Refresh every 60 s. Accept only a strictly higher `bundle_version`:
     - lower → *rollback*, rejected;
     - same version with different bytes → *equivocation*, rejected and alerted.
   - A rejected or unavailable refresh keeps the current bundle **until it is 10 minutes old,
     then everything is denied**.
   - A grant past its own `expires_at` (privileged, 90 days) is treated as absent even inside a
     fresh bundle.

7. **Publisher.**
   - A separate `bundle-publisher` process holds the only signing permission (`kms:Sign` on the
     bundle key). The human-facing registry API cannot sign.
   - It reads approved, unexpired records, generates permits, appends the guardrails, and
     **refuses to publish** anything that fails schema validation.
   - It signs, then writes through a `BundleSink`:
     - **S3** in AWS: versioned bucket; only the publisher writes, gateways read;
     - **a directory** locally: atomic rename, mounted read-only into gateways.
   - It publishes on change (DynamoDB stream in AWS; polling locally) and at least every
     5 minutes as a heartbeat.
   - `bundle_version` is a DynamoDB atomic counter on a reserved item (`#bundle`, never a valid
     agent id), strictly increasing across restarts and clock skew.

8. **Rollout.** The interceptor, MCP gateway and inference gateway all take agent bindings from
   the verified bundle and run Cedar before acting (4b-ii). The interim `agents` maps are then
   removed.

## Consequences

- Revocation reaches every gateway within about 60 s. A dead publisher fails every gateway closed
  after 10 minutes.
- Compromising the registry API or its table can't mint a bundle: that needs the signing key.
- RR-5: `cedarpy` wheels carry no provenance attestation. Mitigations: hash-pinned lock, the
  embedded SBOM, pip-audit, and decision tests that exercise the engine on every shipped policy.
  Revisit when attestations appear, or build from source in Phase 6.
