# ADR-0019: Inference gateway (agent → model)

- **Status:** accepted
- **Date:** 2026-10-12
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-INF-01, TM-INF-02, TM-INF-03, TM-TOOL-04, TM-CP-03

## Decisions

1. **We own the gateway and embed the LiteLLM SDK.**
   - `services/inference_gateway` is a FastAPI service with the same authentication, audit and
     container hardening as the rest of the system. It calls models through LiteLLM's Python API
     only.
   - The LiteLLM proxy server is not used: no admin UI, master key or spend database.
   - Vetting on 2026-10-12: LiteLLM 1.105.0 pulls in 58 packages (about 197 MB). `pip-audit`
     reports no known vulnerabilities. The version is pinned through `uv.lock` and audited in CI.

2. **No hidden egress.**
   - `LITELLM_LOCAL_MODEL_COST_MAP=True`, so the model cost map is not fetched from GitHub at
     import.
   - LiteLLM telemetry is off, and no third-party callbacks are registered.
   - No tokenizer downloads: budget reservations use a character-based estimate
     (`ceil(chars / 4) + max_tokens`) and are settled with the provider's reported `usage`.
   - A test asserts that importing and exercising the gateway attempts no network connection
     other than the configured model call.

3. **Inbound authentication uses the workload token, the same as tools (ADR-0016).**
   - The token is `at+jwt` from the workload AS, with `aud` = the inference gateway. `client_id`
     identifies the agent. There is no user delegation on this path: models act for the agent.
   - In AWS, IAM SigV4 at the edge can be layered on top in Phase 6.

4. **Per-agent policy (TM-INF-01).** The inference profile is `agents: {client_id: {models,
   daily_token_budget, max_output_tokens}}`.
   - A model outside the agent's allowlist is denied before any provider call.
   - `max_tokens` is clamped to `max_output_tokens`.
   - In AWS, the gateway's role may invoke only the union of allowlisted model ARNs (Phase 6).

5. **Budgets (TM-INF-02).** DynamoDB holds one item per agent per UTC day.
   - **Reserve:** a conditional `UpdateItem ADD used :estimate` succeeds only if
     `used + estimate <= budget`. Concurrent requests can't overspend.
   - **Settle:** after the call, `ADD used :(actual − estimate)`.
   - A provider error releases the reservation.
   - If the budget store is unavailable, the request is **denied** (fail closed).

6. **Content scanning (TM-INF-03, TM-TOOL-04).**
   - Both the prompt and the completion go through `scan_with_policy`, with the profile's fail
     mode.
   - The production scanner is a `BedrockGuardrailScanner` (`trustkit-aws`, `ApplyGuardrail` API):
     `GUARDRAIL_INTERVENED` with masked outputs gives REDACT; any other intervention gives BLOCK.
   - moto does not implement `ApplyGuardrail`, so the adapter is tested with botocore's `Stubber`
     (ED-10).

7. **API.** An OpenAI-compatible subset, `POST /v1/chat/completions`, with `model` and
   `messages` (text only), and optional `max_tokens` and `temperature`. Streaming, tools and
   function calling are rejected for now (`400`), because each needs its own scanning design.
