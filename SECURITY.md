# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report privately via
GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab).
Expect an acknowledgement within 3 business days.

## Scope

In scope: everything under `packages/`, `services/`, `infra/`, and the token flows in
[`docs/architecture.md`](docs/architecture.md).

## Engineering rules this repo enforces

- **Fail closed.** Any unparseable config, unknown gateway profile, failed token
  validation, or IdP error results in a deny. Fail-open is allowed only where an ADR
  permits it, and every fail-open decision emits an audit event.
- **No token passthrough.** A token issued for one audience is never forwarded to another.
  Every hop that crosses an audience boundary performs an exchange.
- **No secrets in logs.** Tokens are never logged. Audit records carry `jti` hashes, not
  token bodies.
- **Threat-model traceability.** Every mitigation in `docs/threat-model.md` has an ID
  (`TM-*`). The tests that verify it carry `@pytest.mark.security` and cite the ID.
- **Secrets never in git.** Secrets are blocked by pre-commit (`gitleaks`, `detect-private-key`)
  and by the CI secret scan.
