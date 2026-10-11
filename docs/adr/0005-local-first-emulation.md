# ADR-0005: Local-first development with emulated IdP and AWS

- **Status:** accepted
- **Date:** 2026-10-10
- **Deciders:** Partha Mehta
- **Threat-model refs:** RR-3

## Context

No AWS account or Okta tenant is assumed for development. The security properties we care about
(audience checks, replay protection, fail-closed parsing, header stripping) must still be
proven by automated tests, not by manual testing against cloud services.

## Decision

- **IdP:** `mocks/idp` is a small standards-conformant authorization server. It supports RFC 8693
  token exchange to the ID-JAG token type and the RFC 7523 JWT-bearer grant, uses RS256 with a
  JWKS endpoint, and enforces `jti` single use. It is test infrastructure, not a production
  component, and is never deployed.
- **AWS:** `moto` for unit and contract tests; LocalStack for the docker-compose e2e stack.
- **Managed gateway:** a local harness invokes the interceptor handler with an event shape
  matching AgentCore's interceptor contract. The event shape is captured in fixtures so it can
  be checked against real events later.
- **Adapters:** `trustkit` defines protocols (`TokenExchanger`, `ContentScanner`,
  `ProfileSource`, `KeySigner`). Okta, AWS and Bedrock implementations are adapters, so tests
  swap them without monkeypatching.
- Before Phase 6 (real deploy), assumptions A-1..A-3 in `architecture.md` must each be verified
  against current vendor docs or a real tenant, and recorded here.

## Consequences

- Fast, deterministic, offline CI.
- Risk that the emulation diverges from reality (RR-3). Mitigated by contract fixtures and the
  pre-deploy verification gate.
