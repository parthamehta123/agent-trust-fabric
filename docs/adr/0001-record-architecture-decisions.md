# ADR-0001: Record architecture decisions

- **Status:** accepted
- **Date:** 2026-10-10
- **Deciders:** Partha Mehta

## Context

This is an authorization and identity system. Most of its risk lives in *why* a boundary sits
where it does, not in code. Those reasons must be reviewable and must outlive any single
contributor.

## Decision

- Every non-trivial design decision gets an ADR in `docs/adr/`, using `0000-template.md`.
- ADRs are immutable once accepted. A change of mind is a new ADR that supersedes the old one.
- Every ADR that affects a threat lists its `TM-*` IDs. The threat model links back to it.
- No code for a phase is written until the ADRs for that phase are `accepted`.

## Consequences

- Slower start, much cheaper security review.
- `docs/adr/` and `docs/threat-model.md` are covered by CODEOWNERS.
