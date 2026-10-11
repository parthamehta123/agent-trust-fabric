# agent-trust-fabric

Identity, authorization and governance plane for AI agents:

- **Ingress:** human → agent, with Okta ID-JAG delegated tokens scoped per target.
- **Egress:** agent → tools (MCP), models (LiteLLM → Bedrock) and knowledge (Bedrock KB).
- **Control plane:** an agent registry with security identity records and approval workflow.

> **Status: Phase 1 complete.** The identity spine works end to end against a standards-conformant
> local IdP: caller → interceptor (bind → ID-JAG exchange → T2 → scan → audit) → runtime.
> Nothing is deployed yet. Real-AWS verification items are tracked as A-1b/A-5/A-6 and ED-1..4.

## Documents

- [Architecture](docs/architecture.md): containers, ingress and egress flows, open questions
- [Threat model](docs/threat-model.md): STRIDE per trust boundary, mitigation IDs traced to tests
- [ADRs](docs/adr/): every decision and the reasons for it
- [Emulator divergences](docs/emulator-divergences.md): where moto, the mock IdP and others differ from the real services
- [Security policy](SECURITY.md)

## Layout

| Path | What |
|---|---|
| `packages/trustkit` | Provider-neutral core: JWT validation, profiles, binding, signing, exchange, cache, scanning, audit |
| `packages/trustkit_aws` | KMS ES256 signer |
| `packages/trustkit_http` | Hardened httpx token-endpoint and JWKS client |
| `packages/mock_idp` | Test-only IdP (RFC 8693 → ID-JAG, RFC 7523 → RFC 9068), independent of trustkit |
| `services/interceptor` | AgentCore Gateway REQUEST/RESPONSE interceptor Lambda |

## Roadmap

| Phase | Scope |
|---|---|
| 0 | Repo guardrails, architecture, threat model, ADRs |
| 1 | Identity spine: `trustkit` (JWT validation, ID-JAG/T2 exchange, cache, profiles) + mock IdP + interceptor |
| 2 | Ingress path end-to-end (local gateway harness, agent runtime stub, audit events) |
| 3 | Egress: LiteLLM inference gateway, MCP tool gateway |
| 4 | Agent registry, approval workflow, Cedar policies |
| 5 | Knowledge base with retrieval-time authorization |
| 6 | Terraform (AgentCore gateways, interceptor, IAM, KB, audit) |

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12.

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
uvx pre-commit install
```
