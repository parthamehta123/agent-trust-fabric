# ADR-0028: Sender-constrained tokens (DPoP vs mTLS)

- **Status:** accepted (design); implementation pending
- **Date:** 2026-10-19
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-ING-01, TM-RT-01, TM-TOOL-04, TM-A2A-01 (new: TM-TOK-01)

## Context

Every token in the system is a **bearer** token: whoever holds it can use it until it expires.
This came up in a review of a session and cookie design (key + salt, server-side sessions,
per-request client proofs). The other items in that review are covered by design: no passwords,
no shared secrets, no sessions, and no API-key lookups. This one is not.

| Hop | Token(s) presented | Lifetime | Who could replay a stolen copy |
|---|---|---|---|
| User → ingress gateway | access token + ID token (frontend client) | IdP-set | anyone with network reach to the gateway |
| Ingress → agent runtime | T2 (`aud` = agent) | ≤ 5 min (cached ≤ 5 min) | anyone on the internal path to that runtime |
| Agent → MCP / inference / A2A gateway | **workload token + T2, both required and bound by the gateway** | 5 min | anyone holding **both** |
| A2A gateway → agent B | T_B (`act`: A) | 5 min | anyone on the path to B |
| MCP gateway → tool server | delegated tool token (`act` chain) | 5 min | the tool server itself, or anyone on that path |

**What contains the risk today:**
- short lifetimes;
- a strict audience per hop, so a token is useless at any other service;
- internal-only networks with per-service security groups;
- tokens are never logged (the log scan is a CI gate);
- full audit.

**What doesn't:** nothing proves that the presenter of a token is the party it was issued to. A
token copied from memory, a debug dump, a misrouted log or a compromised sidecar works from
anywhere that can reach the next hop, for minutes.

**The structural lever we already have.** Egress gateways require the agent's **workload token**
and the user's **T2** together, and bind them (`trustkit.binding`). If the workload token is
bound to a key only the agent holds, then a stolen T2, or even a stolen pair, is useless without
that key. Binding *one* token per hop constrains the whole request.

**Verified external facts (2026-10-19):**
- **Okta** supports DPoP (RFC 9449) for **client-credentials** ("API Services") apps, including a
  required server nonce on the token request ([Okta DPoP guide][okta-dpop]; [developer
  forum][okta-forum]). **No confirmation was found for token exchange (RFC 8693) or JWT-bearer
  (RFC 7523) grants**, which are ours for T2 and tool tokens. A "JWT grant with DPoP" exists only
  as an IETF draft ([draft-parecki-oauth-jwt-dpop-grant][jwt-dpop]).
- **AWS ALB** supports mTLS in *verify* mode, with an S3 trust store, and passes the leaf
  certificate to targets as `X-Amzn-Mtls-Clientcert-Leaf` ([ALB mutual TLS][alb-mtls]).
- **AgentCore Gateway** documents OAuth/JWT inbound authorization. **No DPoP or mTLS support was
  found** ([inbound auth][agentcore-auth]).

## Options considered

**A. Status quo, with shorter lifetimes.** Cut token lifetimes to 1–2 min. That costs more IdP
exchanges and higher latency, and still leaves bearer tokens.

**B. DPoP (RFC 9449), binding the workload token.**
1. Each agent process generates an **ephemeral P-256 DPoP key in memory** at start.
2. It requests its **workload token with DPoP** (client credentials, which Okta supports), so the
   token carries `cnf.jkt`, the key's thumbprint.
3. Every call to an egress gateway carries a **DPoP proof**: a JWT signed by that key, with
   `htm`, `htu`, `iat`, `jti`, and `ath` = the hash of the workload token.
4. The gateway verifies the proof and requires its key thumbprint to equal the workload token's
   `cnf.jkt`. T2 stays bearer, but is only accepted alongside a bound workload token.

*Pros:* application-layer, no PKI, Okta-supported for exactly the token we need, and it works
through ALBs unchanged. *Cons:* about one local ES256 sign per request in the agent, one verify
in the gateway, and replay protection needs thought.

**C. mTLS-bound tokens (RFC 8705) on the internal ALBs.**
1. Agents get client certificates from a private CA.
2. ALB verify mode authenticates them.
3. Gateways compare `X-Amzn-Mtls-Clientcert-Leaf`'s thumbprint with the token's `cnf.x5t#S256`.

*Cons:*
- a **private CA** to run (AWS Private CA has a monthly fee per CA) plus a per-agent certificate
  lifecycle;
- cert-bound tokens from Okta are unverified;
- trust is split between the ALB and the app;
- no session resumption with mTLS on ALBs.

*Pros:* binding at the transport layer, nothing for the app to sign.

**D. Gateway-minted internal tokens.** Gateways would issue their own short, key-bound tokens
for the next hop. That adds a token issuer, which this design deliberately avoided: the IdP is
the only issuer (ADR-0002).

## Decision

Accepted 2026-10-19: **adopt B in phases, keep the IdP the only issuer, and design replay protection around a
stateless server nonce.**

### Phase 1: agent → egress gateways (MCP, inference, A2A)

- **Key:**
  - ephemeral P-256, generated in process memory at start, never written to disk, rotated on
    restart;
  - **not** the agent's KMS key: a per-request KMS `Sign` would add a network round-trip and cost
    to every call;
  - the KMS key keeps signing only the client assertion (`private_key_jwt`).
- **Token:** the workload token is requested with a DPoP proof and must carry `cnf.jkt`. A
  gateway **refuses an unbound workload token** once the profile says `require_dpop: true`. A
  per-profile switch allows a staged rollout, and the decision is audited.
- **Proof checks** (gateway), in the fail-closed order we use for JWTs:
  1. `typ = dpop+jwt`, `alg = ES256`, and the `jwk` header is a public P-256 key;
  2. the signature verifies with that `jwk`;
  3. `htm` and `htu` equal the request's method and **canonical** URL, with no query or fragment;
  4. `ath` = base64url(SHA-256(workload token));
  5. `iat` is within ±60 s;
  6. the `jti` has not been seen in this instance's cache (TTL 120 s);
  7. the RFC 7638 thumbprint of `jwk` equals the workload token's `cnf.jkt`;
  8. when nonces are required, `nonce` is valid (below).
- **Replay across instances: a stateless nonce.** This is the whiteboard's "server + salt", made
  precise.
  - A gateway issues `DPoP-Nonce = base64url(epoch ‖ HMAC-SHA256(K_nonce, epoch ‖ client_id))`,
    with 5-minute epochs. It accepts the current epoch and the previous one.
  - `K_nonce` is a per-environment secret held in Secrets Manager and shared by that plane's
    gateways. Every instance can validate any instance's nonce with no shared state, and a
    captured proof expires with its epoch.
  - The per-instance `jti` cache blocks immediate replay to the same instance.
  - *Not chosen:* a shared DynamoDB replay table (conditional put with TTL). It's exact, but adds
    a write and a dependency to every request. We'd revisit it if the audit shows replay attempts.

### Phase 2: tool hops (needs A-12)

- If Okta can bind **token-exchange** output (A-12), the MCP and A2A gateways request DPoP-bound
  tool tokens and T_B with their own ephemeral keys.
  - **Our** knowledge server and agent runtimes verify the proofs.
  - **Third-party MCP servers** generally won't, so for them the tool token stays bearer,
    contained by audience, lifetime and the response scanning we already do.
- If Okta can't, these hops stay bearer, and that's recorded as a residual risk.

### Ingress (needs A-13 and a frontend)

- AgentCore Gateway has no documented DPoP support, but our interceptor already receives the
  request headers.
- If the frontend obtains a DPoP-bound access token, the **interceptor** can verify the
  `DPoP` header itself (A-13: confirm the gateway passes it through unmodified).
- Out of scope until there's a frontend.

## Consequences

- **Positive:**
  - A stolen workload token, T2 or pair is useless without the agent's in-memory key.
  - A stolen proof is single-use per instance and expires with its nonce epoch (≤ 10 min).
  - No PKI to run, and the IdP stays the only issuer.
- **Negative:**
  - About 1 ES256 sign per call in the agent and 1 verify in the gateway (sub-millisecond).
  - One extra token round-trip when a nonce is required.
  - A per-plane nonce secret to manage (rotation: deploy a new `K_nonce` while accepting both
    for one epoch).
- **Residual (proposed RR-10):**
  - an attacker who can read an agent's process memory has the key, by definition;
  - cross-instance replay inside one nonce epoch remains unless we add the shared replay table;
  - third-party tool hops stay bearer.
- **New assumptions to verify on the sandbox:**
  - **A-12:** Okta binds token-exchange and JWT-bearer output to a DPoP key (or confirms it
    can't).
  - **A-13:** AgentCore Gateway passes the `DPoP` header to the interceptor unmodified.
  - **A-14:** Okta's DPoP nonce behaviour for client credentials (when the nonce is required,
    and its lifetime) matches what agents implement.

## Decisions on the open questions (2026-10-19)

1. **Phase 1 scope: egress only.** Agent → MCP, inference and A2A gateways, through the bound
   workload token. Ingress → runtime stays bearer: only the gateway can reach the runtime, and
   the runtime validates T2 itself (TM-RT-01).
2. **Replay: the stateless HMAC nonce** plus a per-instance `jti` cache. A shared replay table
   is added only if the audit shows replay attempts.
3. **Rollout: a per-profile `require_dpop` switch**, enabled agent by agent. Unbound workload
   tokens are audited, and once a profile has cut over, any unbound token is an alert.
4. **If A-12 fails: tool hops stay bearer**, contained by audience, a 5-min lifetime and
   response scanning, and recorded as RR-10. Enrolment doesn't require DPoP-capable tool servers.
5. **mTLS: not chosen** (no private CA or certificate lifecycle now). We revisit it for a future
   tier that justifies running a private CA. *This one is my default, not yet confirmed.*

## Implementation plan (separate PR)

- `trustkit.dpop`: proof creation (agent) and verification (gateway). Strict header and claim
  checks, URL canonicalisation, `ath`, `jti` cache, and the nonce issuer/validator. Tests include
  replay, wrong method or URL, swapped token, a thumbprint mismatch, a stale nonce, and epoch
  rollover.
- Mock IdP: DPoP on client credentials (`cnf.jkt`, nonce challenge), mirroring Okta's documented
  behaviour.
- Agent runtime: ephemeral key, DPoP token request, a proof on every egress call.
- Gateways: `require_dpop` profile switch; verification in the binder before token checks;
  `DPoP-Nonce` responses.
- IaC: a `K_nonce` per plane in Secrets Manager (gateway roles only).
- Compose e2e: a bound call succeeds; a stolen pair without the key fails; replay fails.
