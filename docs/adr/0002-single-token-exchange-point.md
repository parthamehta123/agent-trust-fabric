# ADR-0002: Single token-exchange point at the interceptor

- **Status:** accepted
- **Date:** 2026-10-10
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-ING-04, TM-ING-06, TM-EXC-01, TM-EXC-02

## Context

The reference design performs the T1 → ID-JAG → T2 exchange in two places: an application
"framework" hop for tool calls and a gateway interceptor for runtime invocations. Each copy
must get these right independently:

- audience and scope selection;
- client authentication;
- caching;
- error handling;
- header stripping.

Every one of them is a place where privilege escalation can creep in.

## Options considered

1. **Mirror the reference design** (two hops exchange, sharing a library). Familiar, but two
   deployment units hold exchange credentials, which doubles the key material blast radius and
   needs two audit points.
2. **Single exchange point at the interceptor.** The ingress proxy only validates T1 and
   forwards it. The interceptor is the only component with IdP client credentials.
3. **Exchange at the ingress proxy.** Possible, but it moves privilege to the internet-facing
   component and loses the per-gateway profile model.

## Decision

Option 2.

- The interceptor is the only component permitted to call the IdP token endpoint or hold
  client key material for ID-JAG requests.
- The exchange logic lives in `trustkit.exchange`. The interceptor is its only production caller.
- The ingress proxy validates T1 but **never** forwards T1 past the gateway. The interceptor
  replaces it with T2.

## Consequences

- One IAM principal has access to exchange key material. That principal is audited and its
  key is rotated.
- The interceptor is on the hot path for every request, so its latency budget is critical.
  Mitigated by ADR-0003.
- Open: whether the ingress proxy is needed at all (OQ-4).
