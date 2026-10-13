# ADR-0026: Infrastructure as code and the AWS deployment (Phase 6)

- **Status:** accepted
- **Date:** 2026-10-13
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-CP-02, TM-CP-03, RR-7, RR-8

## Decisions

1. **Write and validate now, apply later.**
   - Complete OpenTofu for a `dev` environment is written and verified **without touching AWS**:
     `fmt`, `validate`, `tofu test` with mocked providers, tflint and checkov.
   - Applying to a sandbox account is a separate, explicitly approved step, with a budget alarm
     and a scripted destroy.

2. **Toolchain** (versions ≥ 14 days old; digests pinned in the Makefile and CI):

   | Tool | How we get it | Assurance |
   |---|---|---|
   | OpenTofu 1.12.6 | official image `ghcr.io/opentofu/opentofu` | cosign keyless signature verified against `opentofu/opentofu` release workflow `@refs/tags/v1.12.6` |
   | tflint 0.64.0 | **our image**: release zip copied onto `gcr.io/distroless/static-debian12:nonroot` (signature verified) | `checksums.txt` keyless signature verified against the tflint release workflow, zip SHA-256 checked. The official image was rejected: its binary is built separately and isn't byte-identical to the signed release. |
   | checkov 3.3.20 | **our image**: hash-pinned requirements (96 packages) on our pinned `python:3.12-slim` | pip-audit clean except RR-8 |

   - Cosign itself runs from `ghcr.io/sigstore/cosign/cosign@sha256:b03690aa…`; nothing is
     installed on the host.

3. **checkov runs sandboxed (RR-8).**
   - Every checkov release pins `asteval==1.0.6`: a sandbox escape to code execution on
     attacker-controlled expressions (GHSA-9w56-46f6-3qhx / PYSEC-2026-3807).
   - `ecdsa` 0.19.2 carries an unfixed timing side channel (PYSEC-2026-1325); it's irrelevant,
     since the linter holds no keys.
   - checkov therefore runs with `--network none`, a read-only root, a **read-only** repo mount,
     `cap_drop ALL`, non-root and no credentials. In CI it runs only in a job with no cloud
     permissions.
   - The two IDs are suppressed **only** in the tool image's own audit, with this ADR as the
     justification.

4. **Compute.**
   - Long-running services run on **ECS Fargate** behind **internal** ALBs.
   - Each service has its own task role and security group, mirroring the compose networks.
   - The interceptor stays a Lambda (AgentCore Gateway).
   - The MCP admin listener's security group admits only the admin network (closes RR-7).

5. **Identity provider.**
   - Okta details (issuer, JWKS, clients, custom AS) are variables.
   - The mock IdP may run **only** in `dev`, as an internal Fargate service, for an end-to-end
     demo. A variable guard prevents it in any other environment.

6. **Layout.** `infra/modules/<component>` and `infra/envs/dev`.
   - Providers are pinned, with a lock file covering darwin_arm64, linux_amd64 and linux_arm64.
   - Remote state: S3 with native lockfile, KMS-encrypted (bootstrap documented, not applied).

7. **Slices:**
   - **6a:** toolchain, network (private subnets plus VPC endpoints), KMS, DynamoDB, S3 bundles,
     budget.
   - **6b:** ECS services, IAM, security groups, ECR.
   - **6c:** interceptor Lambda, AgentCore Gateway, Bedrock Guardrail, Bedrock KB on S3 Vectors.
   - **6d:** CI plan through GitHub OIDC, plus the apply/destroy runbook and the A-x/ED-x checklist.
