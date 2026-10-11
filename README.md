# agent-trust-fabric

Identity, authorization and governance plane for AI agents:

- **Ingress:** human → agent, with Okta ID-JAG delegated tokens scoped per target.
- **Egress:** agent → tools (MCP), models (LiteLLM → Bedrock) and knowledge (Bedrock KB).
- **Control plane:** an agent registry with security identity records and approval workflow.

> **Status: Phase 0.** Architecture, threat model, ADRs and repository guardrails only. No
> runtime code yet.

## Documents

- [Architecture](docs/architecture.md): containers, ingress and egress flows, open questions
- [Threat model](docs/threat-model.md): STRIDE per trust boundary, mitigation IDs traced to tests
- [ADRs](docs/adr/): every decision and the reasons for it
- [Security policy](SECURITY.md)

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
