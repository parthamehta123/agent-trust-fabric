# ADR-0004: Content scanner failure mode

- **Status:** accepted
- **Date:** 2026-10-10
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-TOOL-04, TM-INF-03, RR-2

## Context

The interceptor calls a content scanner on requests and responses. The scanner can be a guardrail
service, a third-party product or a local rules engine. When the scanner errors or times out, the
interceptor must decide between denying the request and letting it through unscanned.

## Options considered

1. **Always fail closed.** Strongest, but a scanner outage takes every agent down.
2. **Always fail open with an alert.** Available, but an attacker who can degrade the scanner
   gets a bypass.
3. **Fail closed by default, with an explicit per-profile opt-in to fail open.**

## Decision

Option 3.

- Profile field `scanner_failure_mode` takes `closed` (default) or `open`. If the field is
  absent, the profile is treated as `closed`.
- A scanner call has a hard timeout taken from the profile, with a platform maximum.
- Every fail-open pass-through emits a `scanner.fail_open` audit event at WARN with the
  correlation ID and profile ID, and increments a metric that alerts.
- Profiles for agents in elevated trust tiers cannot set `open`. Profile validation rejects
  that combination (enforced once the registry exists, Phase 4).

## Consequences

- A scanner outage only affects fail-closed profiles (RR-2).
- The fail-open allowance is visible in config review and in audit.
