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

## 6b decisions (2026-10-13)

8. **Three internal ALBs by plane**, mirroring the compose networks:
   - **data** (MCP, inference and A2A gateways), reachable from agent runtimes only;
   - **admin** (MCP admin, registry), reachable **only** from the AWS Verified Access endpoint;
   - **tools** (knowledge server), reachable only from the MCP gateway and MCP admin.

   Each ALB is TLS 1.3, drops invalid header fields, and returns a default 404.

9. **Certificates:** a wildcard ACM certificate for a domain you own (DNS-validated in its
   public zone), and a private Route 53 zone so plane hostnames resolve only inside the VPC.

10. **Admin access: AWS Verified Access** with the IdP over OIDC. Its policy is **Cedar**: only
    listed admin groups pass. With Verified Access disabled, **nothing** reaches the admin
    plane. This closes **RR-7** in the deployment design: tool servers have no path to the admin
    listener.

11. **Services:**
    - Each service has one task role, one security group (admitting only its plane's ALB on
      8443), and egress to named destinations only: VPC endpoints, gateway-endpoint prefix
      lists, named IdP and runtime CIDRs.
    - Tasks are Fargate on arm64 with a read-only root (ephemeral `/tmp` volume), user
      10001, all capabilities dropped, **no ECS Exec** and no public IP. Images are deployed
      **by digest only**, from immutable, scan-on-push ECR repositories.
    - Who may sign with which key comes from **one map** (`sign_grants`) that generates both the
      IAM policies and the KMS key policies; a `check` block fails on unwired drift.
    - Tests assert:
      - no wildcards in any task policy;
      - only the publisher signs bundles and writes the bucket;
      - only the MCP gateway reads tool secrets;
      - only the inference gateway invokes models;
      - the registry never deletes;
      - the admin plane is reachable only through Verified Access, and closed without it.

## 6c decisions (2026-10-13)

12. **Config and secrets.**
    - Non-secret config (issuers, JWKS URIs, audiences, table names, key ARNs, bundle
      location) is set as task-definition environment variables.
    - Services authenticate to the IdP with `private_key_jwt`, signed by their own KMS key
      (`trustkit_aws.signers`). **No service holds a client secret**, and nothing is injected
      through ECS `secrets`.
    - The execution role has no Secrets Manager access. Tool credentials stay in Secrets
      Manager and are fetched at runtime by the MCP gateway's task role only.

13. **File-shaped config is inline and immutable.**
    - Documents previously read from `ATF_<X>_PATH` (egress profiles, model routes, tool
      authorities, interceptor profiles, guardrails) can also come from `ATF_<X>_JSON`. A shared
      loader accepts **exactly one** of the two.
    - Terraform renders them with `jsonencode`, so every config change is a new task-definition
      or function revision: auditable and reversible.
    - Tests assert the rendered environment stays well under the container-definition limit and
      contains nothing secret-shaped.

14. **The bundle verification key is pinned at deploy.**
    - Terraform reads the bundle key's public half (`aws_kms_public_key`) and passes it as
      `ATF_BUNDLE_PUBLIC_JWK_JSON`.
    - Verifiers have **no** KMS permission on the bundle key. Rotating it is an explicit
      redeploy (ADR-0022).

15. **AgentCore Gateway: our bundle is authoritative.**
    - The gateway uses a `CUSTOM_JWT` authorizer pinned to the IdP discovery URL, with
      `allowed_audience` and `allowed_clients`.
    - A `REQUEST` interceptor Lambda runs the same `trustkit_policy` code: bundle verification,
      `authorize_tool` and the delegated exchange. It does not pass request headers.
    - There is **no** AgentCore Policy engine, so we never keep a second, unsigned copy of
      policy in Terraform state.
    - `exception_level` is left unset, so callers get no debug detail.

16. **Interceptor Lambda.**
    - An arm64 container image from the immutable, scan-on-push ECR repository, deployed **by
      digest**.
    - VPC-attached in private subnets with its own security group. Egress goes only to VPC
      endpoints, gateway prefix lists and the IdP CIDRs.
    - Reserved concurrency and a KMS-encrypted environment.

17. **Bedrock Guardrail.** The inference gateway pins a **published version**, never DRAFT:
    - prompt-attack filter HIGH on input;
    - content filters MEDIUM in both directions;
    - PII (email, phone, name, address) **anonymized** on output, matching ADR-0025's
      mask-at-retrieval rule;
    - credential-shaped data **blocked**: managed AWS key types plus regexes for PEM private
      keys and JWT-shaped bearer tokens.

18. **Knowledge base.**
    - Titan Text Embeddings v2 (1024 dimensions, cosine) on an S3 Vectors index.
      `collection` and `classification_rank` are filterable; provenance is non-filterable.
    - The KB source bucket can be written **only** by the ingest role, which runs our scanner
      and manifest checks. A bucket policy denies every other writer. Each document carries a
      `.metadata.json` with its labels.
    - The Bedrock KB service role is read-only on the source bucket and limited to the one
      vector index.
    - Everything is encrypted with the data key.
    - The data source uses `chunking_strategy = NONE`. The ingest export (`ingest --out-s3`)
      writes **one object per our chunk** with a `.metadata.json` sidecar. Chunk ids, labels and
      provenance therefore reach `Retrieve` exactly as the local store has them, and the
      per-chunk scan and labelling of ADR-0025 §5 still hold. A contract test round-trips the
      export through the `Retrieve` adapter.
    - Follow-up: re-ingest doesn't yet delete objects for withdrawn documents. Until it does, a
      withdrawal is a manual delete by the ingest role followed by a data-source sync.
