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
      `ATF_BUNDLE_PUBLIC_KEY_PEM`. Terraform can't turn DER into a JWK, so the verifier derives
      the JWK itself. It must be P-256, and the derived JWK (and so the `kid` thumbprint) is
      identical to the JWK pin used locally. Exactly one key source may be set.
    - The data source reads through the **alias** this configuration manages
      (`alias/<name>-sign-bundle`). Provider 6.66.0 rejects every key id and key ARN for
      `aws_kms_public_key`, even AWS's documented examples; aliases validate. Repointing the
      alias, or any change to the pinned PEM, shows in the plan as drift.
    - Verifiers have **no** KMS permission on the bundle key. Rotating it is an explicit
      redeploy (ADR-0022).

15. **AgentCore Gateway: our bundle is authoritative.**
    - The gateway uses a `CUSTOM_JWT` authorizer pinned to the IdP discovery URL, with
      `allowed_audience` and `allowed_clients`.
    - An interceptor Lambda on **`REQUEST` and `RESPONSE`**, with **request headers passed**,
      runs the same interceptor code as locally: binding, the ID-JAG/T2 exchange, and response
      scanning.
    - *Corrected in 6c-iii:* the first draft said REQUEST only, without headers. That
      contradicted accepted contracts: ADR-0012 §6 and ADR-0013 require the response phase, and
      ADR-0006/0009 bind `Authorization` plus `X-Subject-Token`. The compensating control is
      ADR-0012 §4. The target's header allowlist is exactly the reserved `x-atf-*` set, and the
      module refuses any credential-bearing header (a contract test keeps that list identical to
      `trustkit.policy`).
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

19. **Named internal hosts for egress (amends ADR-0017 §4, ADR-0018 §1).**
    - **Gap found in 6c-ii:** in AWS the knowledge server (behind the tools ALB) and agent
      runtimes have private addresses, and the SSRF guard refuses every non-public address
      outside `local`. Compose never showed this, because local mode allows its test subnets.
    - `ATF_SSRF_INTERNAL_HOSTS` is a JSON map of **exact lowercase FQDN → private CIDRs**,
      allowed in any environment, with at most 64 entries:
      - each CIDR is RFC 1918 at /16 or narrower, or ULA at /48 or narrower, so loopback,
        link-local (metadata), CGNAT and public space never qualify;
      - a named host is accepted only if **every** resolved address is inside its CIDRs. A
        public answer for it is refused too, so a poisoned record can't divert it;
      - other names are judged exactly as before, with no suffix or wildcard matching.
    - Pinning, SNI and certificate hostname checks are unchanged. The MCP gateway (calls and
      enrolment vetting) and the A2A gateway both honour it.
    - Terraform renders it from the tools-plane records and the private subnet CIDRs. A test
      asserts that admin-plane hosts are never listed.
    - `ATF_SSRF_ALLOW_CIDRS` remains local-only.

20. **IdP variables.**
    - One structured `idp` object: `base_url`, a map from logical authorization server to its
      id (workload, tool, knowledge, inference, registry, admin, ingress, agent), and a map of
      client ids.
    - Issuer, JWKS and token URLs are derived by Okta convention (`{base}/oauth2/{id}`,
      `/v1/keys`, `/v1/token`), as devstack does locally.

21. **Verification notes (6c-ii).**
    - The IaC containers mount `policies/` read-only, so the publisher's
      `ATF_GUARDRAILS_CEDAR` is the reviewed file verbatim (asserted).
    - checkov's parser (python-hcl2) can't parse a leading `&&` continuation line. Test
      conditions are written as `alltrue([...])` lists, and parse errors must stay at 0.
    - The MCP admin service doesn't read an egress profile (only the data plane does), so it
      isn't given one.
    - The CI IaC job still points at a placeholder path and doesn't run. Rewiring it to
      `make iac-validate` is 6d.

22. **The interceptor's gateway id comes from SSM (6c-iii).**
    - The gateway needs the Lambda's ARN, and the Lambda needs the gateway's AWS-assigned id,
      because ADR-0012 §2 resolves the profile only from `GATEWAY_ARN`. That is a dependency
      cycle.
    - Terraform publishes the gateway id to one SSM parameter. The interceptor reads it once at
      cold start (`ATF_GATEWAY_ID_PARAMETER`), binds it into its **single** profile, and still
      matches it exactly.
    - Unreadable, malformed, or more than one profile all mean deny-all (503).
    - This is the one exception to §13 (inline config). The value is plan-visible drift.

23. **Edge and knowledge resources (6c-iii).**
    - **Interceptor:** ingress-only, with no bundle and no S3 or data-key grants. It signs as
      the frontend client with its own KMS key, a new `sign_grants` entry.
    - **Platform permissions:** ENI permissions (no resource-level support) sit in a separate
      platform policy, conditioned to the VPC.
    - **Image pull:** Lambda pulls its image under an ECR repository policy that names only this
      function.
    - **Gateway role:** may invoke only the interceptor and the one runtime, and use the data
      key. A `check` refuses `lambda:*` in any task or function policy, because a direct invoke
      with a forged client context would mint a T2 (TM-INT-03).
    - **Bedrock grants:** only the inference gateway may call `bedrock:ApplyGuardrail`, and only
      the knowledge server may call `bedrock:Retrieve`.
    - **kb-ingest:** assumable only by listed roles (the 6d CI role). It may Put and Delete
      under `corpus/` and nothing else. Syncing the data source is a runbook step.
    - **SSM endpoint:** an `ssm` interface endpoint is added, since private subnets have no
      internet path.

24. **Unverified until a sandbox apply (A-8..A-11 in `architecture.md`):**
    - the gateway's `protocol_type` for an AgentCore Runtime HTTP target (left unset);
    - `jwt_passthrough` as the target credential provider, given the interceptor-set
      `Authorization`;
    - Bedrock KB `chunking_strategy = NONE` with `.metadata.json` sidecars on S3 Vectors;
    - the `aws_kms_public_key` key-id validation behaviour (worked around with the alias, §14).

## 6d decisions (2026-10-14)

25. **CI validates the IaC with the same pinned containers as local.**
    - The stale `terraform` job (wrong path, marketplace binaries, unsandboxed checkov) is
      replaced by `make iac-tools && make iac-validate`.
    - The job has `permissions: contents: read` and no cloud credentials, so tool signatures
      fail closed in CI exactly as on a laptop, and RR-8's sandbox holds.

26. **GitHub OIDC: a read-only plan role and a gated apply role.**
    - The **plan** role is read-only plus state read. It is trusted only for `pull_request` and
      `refs/heads/main` of this repository; fork PRs never receive tokens.
    - The **apply** role is trusted only for `environment:sandbox`: a GitHub environment with a
      required reviewer, run through manual `workflow_dispatch`.
    - A third role, also on `environment:sandbox`, may assume `kb-ingest`.
    - Every trust pins `aud = sts.amazonaws.com` and an exact `sub`. Sessions last at most one
      hour.
    - `infra/bootstrap` (state bucket with native lockfile and KMS, OIDC provider, the roles) is
      applied once, by hand, by an administrator.

27. **CloudTrail: an account trail plus targeted data events.**
    - The trail is multi-region, with log-file validation and KMS encryption.
    - Its log bucket has object lock, and no workload role can write or delete it.
    - Advanced selectors capture:
      - S3 writes on the bundle and corpus buckets;
      - `Invoke` on the interceptor Lambda (TM-INT-03);
      - DynamoDB writes on the `agents` and `mcp-servers` tables.

28. **Runbook plus opt-in AWS probes.**
    - `docs/runbooks/sandbox.md` covers bootstrap, plan review, apply, image push by digest, IdP
      setup, ingest and sync, smoke test, and a scripted destroy with a budget check.
    - `tests/aws_probes/` holds pytest probes for A-1b..A-11 and the ED-x rows. They are marked `aws`
      and skipped unless `ATF_AWS_PROBES=1` and a named profile are set.
