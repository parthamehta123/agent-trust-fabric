# ADR-0013: The response path can only tighten a decision

- **Status:** accepted
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Amends:** ADR-0012 §5 (replaces the "unforgeable deny marker")
- **Threat-model refs:** TM-INT-02, TM-TOOL-04

## Context

For MCP targets the RESPONSE interceptor still runs after a REQUEST interceptor short-circuit.
ADR-0012 proposed marking our own denies so the response handler could recognise them. But any
marker that makes the response handler **skip work** is something a malicious target can forge
to bypass response scanning. Making the marker unforgeable would need a signing secret, plus its
rotation and its own threat model.

## Decision

- No deny marker.
- The RESPONSE handler **always** runs its full pipeline: profile resolution, then scanning per
  the profile.
- The response handler can only **pass through unchanged, redact, or replace with a deny**. It
  never constructs a success out of an error, never restores content, and never relaxes a
  status code.
- When it scans one of our own deny bodies, that body contains no user content, so it passes
  through unchanged.

## Consequences

- No new secret. Nothing for a target to forge.
- On MCP targets, a request-time deny costs one extra (cheap) scan.
- Tests assert this as a property: for every response-handler input, the output status is never
  "more successful" than the input.
