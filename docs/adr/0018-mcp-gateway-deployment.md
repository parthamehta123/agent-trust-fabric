# ADR-0018: MCP gateway deployment details (local SSRF exception, admin plane, storage)

- **Status:** accepted
- **Date:** 2026-10-12
- **Deciders:** Partha Mehta
- **Amends:** ADR-0017 §4 (SSRF) and §8 (storage)
- **Threat-model refs:** TM-TOOL-05, TM-TOOL-06, TM-CP-01, RR-3

## Decisions

1. **Local-only SSRF CIDR allowlist.**
   - `ATF_SSRF_ALLOW_CIDRS` (comma-separated) lets addresses in those networks pass the guard.
     It exists only so the compose `tools` network works.
   - It is honoured **only when `ATF_ENV=local`**. In any other environment, setting it causes a
     cold-start failure (deny-all), the same pattern as `local:` keys (ADR-0015 §5).
   - Even locally, every CIDR must sit inside RFC 1918 or ULA space, have a prefix of at least /16
     (IPv4) or /48 (IPv6), and never overlap link-local (`169.254.0.0/16`, `fe80::/10`). It can
     open one test subnet, never the metadata service or the world.

2. **Admin plane separated from data plane.**
   - The MCP gateway runs two listeners: data (`/mcp`, for agents) and admin (`/admin/...`, for
     enrol, refresh, approve, disable and list).
   - The admin port is attached only to an internal `admin` network and is never published.
   - In AWS it becomes a separate listener or target group, restricted to the admin VPC and SSO
     (Phase 6).
   - The admin API never returns secret values, only ARNs.

3. **DynamoDB storage.**
   - One item per server: `PK = server_id`.
   - Every write is conditional: `attribute_not_exists(server_id)` on create, `#status = :expected`
     on transitions. Concurrent approvals or refreshes cannot overwrite each other.
   - The snapshot is stored inline as canonical JSON. A refresh whose snapshot exceeds **300 KB** is
     rejected (the DynamoDB item limit is 400 KB).
   - The table is KMS-encrypted with point-in-time recovery (Terraform, Phase 6).

4. **Credentials adapter.**
   - `delegation = none`: Secrets Manager `GetSecretValue` by ARN, cached in-process for up to
     300 s. The value never enters records, logs, errors or responses.
   - `delegation = token`: `exchange_delegated` (ADR-0016), using a per-server egress profile built
     from gateway configuration plus the record's audience and scopes. The profile is validated by
     the same strict schema as every other profile.
