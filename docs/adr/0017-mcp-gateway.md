# ADR-0017: Self-hosted MCP gateway (non-AgentCore agents)

- **Status:** accepted
- **Date:** 2026-10-12
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-TOOL-01, TM-TOOL-02, TM-TOOL-03, TM-TOOL-04, TM-TOOL-05, TM-TOOL-06, TM-CP-01

## Context

Agents that do not run on AgentCore still need the egress guarantees of ADR-0016. They reach MCP
servers (tools) through our own gateway, `services/mcp_gateway`, which must also handle risks
specific to MCP:

- servers changing tool descriptions after approval (rug-pull or tool poisoning);
- enrolled URLs pointing inward (SSRF);
- tools that cannot accept delegated tokens.

## Decisions

1. **Same caller credentials as ADR-0016.** The caller sends the workload token plus T2, bound with
   `bind_actor`. The gateway uses the same `trustkit` code as the interceptor; there is no second
   implementation.

2. **Server lifecycle: `draft → approved ⇄ pending_review → disabled`.**
   - Admin endpoints require an IdP token carrying the `mcp.admin` scope.
   - Enrolment creates a `draft`.
   - **Approval requires a different subject from the enroller** (two-person rule, previewing
     TM-CP-01). Approval also requires a fresh discovery snapshot whose tool descriptions scan
     clean (TM-TOOL-04).
   - Phase 4 moves this workflow into the registry.

3. **Tool pinning (TM-TOOL-03).**
   - Approval stores the SHA-256 of the canonical `tools/list`: tools sorted by name, each with
     name, description and input schema, serialised as canonical JSON.
   - Every refresh re-hashes. **Any drift moves the server to `pending_review`.** Its tools then
     disappear from `tools/list`, and `tools/call` is denied until someone re-approves.
   - The hash is re-checked on every call, so there is no window between a refresh and an
     enforcement step.

4. **SSRF (TM-TOOL-06).**
   - Enrolled URLs must be `https`, with no userinfo, fragment or IP literal.
   - DNS is resolved **at enrolment and on every call**. Any address that is private, loopback,
     link-local (including `169.254.169.254`), CGNAT, multicast, reserved, unspecified, or an
     IPv4-mapped/NAT64 form of these is rejected.
   - The connection goes to the **vetted IP**, with SNI and the `Host` header set to the hostname
     and the certificate verified against the hostname. A DNS rebind between the check and the
     connect cannot redirect it.
   - Redirects are never followed.

5. **Credentials per server.**
   - `delegation = token` (default): RFC 8693 exchange to a server-specific audience via
     `exchange_delegated` (ADR-0016). The tool sees the user and the agent through `act`.
   - `delegation = none`: the gateway injects a per-server secret, referenced by a Secrets Manager
     ARN in the record. The value never appears in the store, logs or the agent's view. Because
     the tool cannot check the user, user entitlement must be enforced upstream: the agent's
     allowed scopes and, in Phase 4, Cedar. The flag is explicit, audited and shown in review.

6. **Namespacing.** Tools are exposed as `<server_id>__<tool>`. An unknown or unapproved prefix
   is denied, so one server cannot shadow another server's tool names.

7. **Limits.** Responses from servers are size-capped. Tool results are scanned before they reach
   the agent (TM-TOOL-04), with the same `scan_with_policy` and fail mode as everywhere else.

8. **Storage.** A `ServerStore` protocol, implemented in memory for this slice. The DynamoDB adapter
   (moto-tested, with conditional writes for state transitions) follows in the 3b HTTP/compose
   step, together with the FastAPI shell.
