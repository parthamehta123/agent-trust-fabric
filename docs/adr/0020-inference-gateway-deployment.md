# ADR-0020: Inference gateway deployment (model routes, audience, networks)

- **Status:** accepted
- **Date:** 2026-10-12
- **Deciders:** Partha Mehta
- **Amends:** ADR-0019 §3 (audience) and §4 (model names)
- **Threat-model refs:** TM-INF-01, TM-INF-03, TM-CP-01, RR-3

## Decisions

1. **Own authorization server and audience.**
   - Agents get inference tokens from an `inference` custom AS: `aud = api://inference-gateway`,
     scope `inference.invoke`, client credentials with `private_key_jwt`.
   - A workload token for the tool gateway (`api://tool-gateway`) is rejected with `401`, and
     the reverse holds too. One stolen token never works at both services. Proven in compose e2e.

2. **Logical model names and a routes file.**
   - Agent allowlists name *logical* models (e.g. `claude-sonnet`). Only `ATF_MODEL_ROUTES_PATH`
     maps them to a LiteLLM model id.
   - Responses carry the logical name; provider ids and endpoints never reach agents.
   - Cold start fails if any allowlisted model has no route. An unrouted name at call time
     raises and never falls through to the provider with a raw name.

3. **`api_base` is local-only.**
   - A route's `api_base` redirects prompts to another host, which makes it a data-exfiltration
     lever.
   - It is honoured only when `ATF_ENV` is exactly `local`, and it must be https. Anywhere else
     it is a cold-start failure, the same pattern as ADR-0018 §1.
   - Real environments reach Bedrock through the AWS SDK's own endpoint resolution (VPC
     endpoints in Phase 6).

4. **Provider TLS.** LiteLLM is configured with the deployment's CA bundle
   (`litellm.ssl_verify`). Locally that is the ephemeral CA only.

5. **Networks (local stack).**
   - `inference-gateway` sits on four networks:
     - `inference-edge`: published on `127.0.0.1:8445`.
     - `idp`: for JWKS.
     - `ddb-inference`: its own network to DynamoDB Local.
     - `llm`: internal; it is the only service there besides `mock-llm`.
   - It shares no network with the MCP data or admin planes. With no IAM in DynamoDB Local
     (ED-9), the separate network is what keeps it off the MCP registry table.
   - Pinned subnets (`tools-data`, `tools-admin`) moved to `10.230.0.0/16` and
     `10.231.0.0/16`, outside Docker's default address pools. Before, an auto-assigned network
     could collide with them, depending on creation order.

6. **Local model.**
   - `mock-llm` (test infrastructure, `ATF_ENV=local` only) is an OpenAI-compatible server
     reached through LiteLLM's real HTTP provider path.
   - It requires the provider key, so it can show that agents' tokens never reach the provider.
   - It exposes a call counter, so e2e can show that blocked prompts never reached the model.
