# ADR-0003: T2 cache policy

- **Status:** accepted; cache key amended by [ADR-0011](0011-exchange-client-rules.md)
- **Date:** 2026-10-10
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-EXC-03, TM-EXC-04, TM-EXC-07, RR-1

## Context

Each exchange is two IdP round-trips (token exchange, then JWT-bearer). Doing this on every
request adds latency and consumes IdP rate limit. Caching trades that cost against
revocation lag and against the risk of serving a token to the wrong principal.

## Options considered

1. **No cache.** Instant revocation, but the highest latency and IdP load.
2. **In-memory, short TTL, keyed per subject and target.**
3. **Distributed cache (ElastiCache/DynamoDB).** Higher hit rate across Lambda environments,
   but it adds an encrypted token store (a new high-value asset) and new infrastructure.

## Decision

Option 2.

- **Key:** `SHA-256(T1.jti ‖ T1.sub ‖ target_audience ‖ profile_id)`. It is never keyed by
  `sub` alone, so a new T1 (new session) misses the cache by design.
- **TTL:** `min(T2.exp − 30 s, 300 s)`.
- **Scope:** process memory of one Lambda execution environment. Nothing is persisted, and the
  cache is never shared across environments.
- **On a cache hit**, T1 is still fully validated (signature, `exp`) before the cached T2 is
  used.
- The cache is bounded (LRU, max entries configurable) to prevent memory exhaustion.

## Consequences

- A revoked user can keep access for up to 300 s (RR-1, accepted).
- The cache hit rate depends on Lambda environment reuse. That is acceptable, because the
  cache is an optimization and not a dependency.
- Follow-up: emit the cache hit/miss ratio as a metric (Phase 2).
