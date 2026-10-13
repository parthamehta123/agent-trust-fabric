# agent-trust-fabric

Identity, authorization and governance plane for AI agents:

- **Ingress:** human → agent, with Okta ID-JAG delegated tokens scoped per target.
- **Egress:** agent → tools (MCP), models (LiteLLM → Bedrock) and knowledge (Bedrock KB).
- **Control plane:** an agent registry with security identity records and approval workflow.

> **Status: Phase 4b complete.** Every gateway enforces a **signed policy bundle** built from an
> approved agent registry:
> - registry (two-person, tiered approval) → separate bundle publisher (the only signing key) →
>   ingress interceptor, MCP gateway and inference gateway, each running Cedar before acting;
> - user entitlements are carried in T2 (IdP downscoping) and enforced by a Cedar guardrail;
> - revocation reaches every gateway in seconds, rollback replays are rejected, and a dead
>   publisher fails everything closed.
>
> Nothing is deployed to AWS yet. Real-AWS verification items are tracked as A-1b/A-5/A-6/A-7
> and ED-1..12.

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
| `packages/trustkit_aws` | KMS ES256 signer, Bedrock Guardrails content scanner, S3 bundle transport |
| `packages/trustkit_http` | Hardened httpx token-endpoint and JWKS client |
| `packages/trustkit_policy` | Cedar decision point and signed policy bundles |
| `policies/` | Platform-wide Cedar guardrails (CODEOWNERS-reviewed) |
| `packages/mock_idp` | Test-only IdP (RFC 8693 → ID-JAG, RFC 7523 → RFC 9068), independent of trustkit |
| `services/interceptor` | AgentCore Gateway REQUEST/RESPONSE interceptor Lambda |
| `services/agent_runtime` | Reference agent runtime; authorizes from T2 only |
| `packages/gateway_emulator` | Test-only AgentCore Gateway emulator (documented behaviour) |
| `services/mcp_gateway` | MCP tool gateway: data plane and separate admin plane |
| `services/inference_gateway` | Model gateway embedding the LiteLLM SDK |
| `services/agent_registry` | Agent registry: versioned security records with tiered approval |
| `packages/mock_mcp`, `packages/mock_llm` | Test-only MCP tool server and OpenAI-compatible model server |
| `packages/devstack` | Dev-only ephemeral CA, certs, keys and config generator |
| `deploy/local`, `compose.yaml`, `Makefile` | Hardened local container stack |

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

### Local stack (Docker)

```bash
make up    # ephemeral CA + certs, wheels, build images, start (waits for health)
make e2e   # HTTPS end-to-end suite; trusts only the ephemeral CA
make down  # stop; `make clean` also deletes .local-ca/ and build/
```

Published ports, all on `127.0.0.1`:

| Port | Service |
|---|---|
| 8443 | Ingress gateway |
| 8444 | MCP gateway (data plane) |
| 8445 | Inference gateway |
| 9443 | Test IdP |
| 9445 | MCP admin plane |
| 9446 | Agent registry (admin) |

The agent runtime, tool servers, model server, bundle publisher and DynamoDB Local are reachable
only over internal networks.
