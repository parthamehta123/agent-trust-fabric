# Runbook: sandbox apply, verification and destroy

ADR-0026 §26–28. Applies to a **dedicated sandbox account only**: never one that holds anything
else. Each step names *who* runs it and *with what credentials*. Nothing in this repository runs
any of it automatically.

| Credential | Used for | Where it comes from |
|---|---|---|
| Your admin profile (MFA) | bootstrap, first-phase apply, destroy | Your SSO / IAM Identity Center |
| `atf-ci-plan` | plans on PRs and `main` | GitHub OIDC (bootstrap) |
| `atf-ci-apply` | applies, from the `sandbox` environment | GitHub OIDC (bootstrap) |
| `atf-ci-ingest-ci` → `atf-dev-kb-ingest` | corpus ingest | GitHub OIDC (bootstrap), one hop |

## 0. Before you start

- Budget: `monthly_budget_usd` (default 50) and alert emails in `terraform.tfvars`. Alerts are
  created in phase A, before anything that costs money.
- Decide the names that must agree across stacks, and write them down once:
  - the state bucket;
  - the CloudTrail log bucket (`cloudtrail_bucket_name` in **both** bootstrap and dev, because
    the apply role's guardrails name it);
  - the region allowlist.
- Gates are green locally: `make iac-tools iac-validate` and `uv run pytest`.

## 1. Bootstrap (admin, once, local state)

```bash
cd infra/bootstrap
cp terraform.tfvars.example terraform.tfvars        # fill in; never committed
tofu init && tofu plan -out bootstrap.plan          # review: 3 roles, OIDC provider, state bucket
tofu apply bootstrap.plan
tofu output -json > ~/atf-bootstrap-outputs.json    # keep with the local state file; not in git
```

Keep `terraform.tfstate` from this directory somewhere safe. It is the only record of the
trust anchors.

## 2. GitHub settings (repository admin)

- **Environments:**
  - `sandbox`: required reviewer (you), deployment branch `main` only.
  - `sandbox-ingest`: the same rules.
- **Repository variables:**
  - `ATF_AWS_REGION`;
  - `ATF_PLAN_ROLE_ARN` and `ATF_APPLY_ROLE_ARN` (bootstrap `role_arns`);
  - `ATF_DEV_BACKEND_HCL` (from `backend.hcl.example`, with the bootstrap `state_bucket`);
  - `ATF_DEV_TFVARS` (the full non-secret `terraform.tfvars`).
- **Secret:** `ATF_VERIFIED_ACCESS_CLIENT_SECRET`. This is the only secret, an AWS requirement of
  Verified Access OIDC.
- **Branch protection** on `main`: required reviews, CODEOWNERS, and required checks (`ci`,
  `plan`).

## 3. Phase A: keys, registries, network (admin, targeted, local)

The images and the IdP's client registrations need things that only an apply creates: ECR
repositories, and KMS public keys for `private_key_jwt`. So the first apply is **targeted**:

```bash
cd infra/envs/dev
tofu init -backend-config=backend.hcl
tofu plan -var-file=terraform.tfvars -out phase-a.plan \
  -target=module.kms -target=module.ecr -target=module.network -target=module.budget
tofu apply phase-a.plan
```

## 4. Images by digest (admin or a release job)

- Build each service image (and `interceptor`) for **arm64** from the hash-pinned wheels
  (`make wheels`).
- Push them to the ECR repositories from phase A. Scan-on-push must report no criticals.
- Record each `sha256:` digest in `image_digests` in `ATF_DEV_TFVARS`. Tags are never deployed.

## 5. IdP (Okta) setup (IdP admin)

1. Create the custom authorization servers (workload, inference, registry, admin, ingress,
   knowledge, each tool's AS, and the agent's AS), each with **its own audience**. Use the ids
   and audiences you put in `idp` and `ingress_agent`.
2. Create the clients:
   - `tool_gateway`, `a2a_gateway` and `frontend`: **`private_key_jwt` only**. Register each
     client's JWKS from its KMS public key (`aws kms get-public-key --key-id
     alias/atf-dev-sign-<key>`, converted to a JWK).
   - The Verified Access OIDC client: a client secret, put in the GitHub secret above.
3. Configure the `kb.<collection>.read` scopes and downscoping per user group. Add the admin
   groups that Verified Access admits.
4. Fill `idp_egress_cidrs` with the IdP's published egress ranges.

## 6. Full apply (CI)

1. Open a PR that touches `infra/`. The `plan` workflow posts a read-only plan. Review it:
   - IAM statements (no wildcards);
   - every `*_PUBLIC_KEY_PEM`, digest and egress change.
2. Merge. On `main`, run **apply → "apply dev"**. The `sandbox` environment asks you to approve.
3. The job re-runs every IaC gate, then plans and applies that exact plan.

## 7. Knowledge ingest and sync (CI `sandbox-ingest`, then admin)

```bash
# inside a job on environment sandbox-ingest: OIDC -> atf-ci-ingest-ci -> atf-dev-kb-ingest
python -m atf_knowledge_server.ingest --corpus deploy/local/corpus \
  --config deploy/local/kb-collections.json \
  --out-s3 "s3://$(tofu output -json knowledge | jq -r .source_bucket)/corpus" \
  --ingested-by ci
# then (admin): start the data-source sync
aws bedrock-agent start-ingestion-job --knowledge-base-id <kb_id> --data-source-id <data_source_id>
```

A rejected document means nothing is uploaded. Fix the manifest or the document; never
"force" it.

## 8. Verify (admin, read-only probes)

```bash
cd infra/envs/dev && tofu output -json > /tmp/atf-outputs.json
ATF_AWS_PROBES=1 AWS_PROFILE=<sandbox-admin> ATF_AWS_OUTPUTS=/tmp/atf-outputs.json \
  uv run pytest -m aws tests/aws_probes -v
```

Then work through the checklist below, ticking each row in `docs/emulator-divergences.md` or
`docs/architecture.md` with the date and evidence.

| Item | How it's verified | Probe / step |
|---|---|---|
| A-3, A-10: KB filter and chunk labels on S3 Vectors | automated | `test_knowledge.py` |
| A-8: no `protocol_type` needed for a runtime target | the apply succeeds and the gateway serves a call | step 6, then a smoke call |
| A-9: `jwt_passthrough`, and the interceptor's Authorization reaching the runtime | automated (config) plus a smoke call with a real user | `test_edge.py` + manual |
| A-11: bundle pin equals the KMS key (alias read) | automated | `test_pins_and_audit.py` |
| A-1b: captured real interceptor events match our fixtures | manual: temporarily enable debug capture in a scratch copy of the Lambda, never in this one | manual |
| A-5: can an interceptor remove a client header? | manual: send an `x-atf-decision` header from the client, observe what the runtime receives | manual |
| A-6: gateway behaviour on interceptor error or timeout | manual: point a scratch gateway at a Lambda that sleeps past its timeout | manual |
| A-7: runtime inbound JWT authorizer pinned to the resource AS | manual (AgentCore Runtime config) | manual |
| ED-1/ED-2/ED-4: KMS semantics | automated (ED-4); ED-1 and ED-2 exercised by every signer at runtime | `test_pins_and_audit.py` |
| ED-10: real ApplyGuardrail findings | smoke calls with a prompt-attack string and a PEM header through the inference gateway | manual |
| ED-11: Bedrock through LiteLLM | a smoke completion through the inference gateway | manual |
| Audit: trail logging with the agreed selectors, logs undeletable | automated | `test_pins_and_audit.py` |
| Corpus writable only by kb-ingest | automated (an admin write is denied) | `test_pins_and_audit.py` |

## 9. Destroy (admin, local)

```bash
cd infra/envs/dev
tofu plan -destroy -var-file=terraform.tfvars -out destroy.plan   # review
tofu apply destroy.plan
```

**Retained by design** (expected "cannot delete" errors; handle them deliberately):

- the CloudTrail log bucket and the bundle bucket: object lock (GOVERNANCE). Leave them until
  retention ends, or remove them as the account admin with an explicit, recorded bypass;
- guardrail versions (`skip_destroy`);
- KMS keys: scheduled for deletion after 30 days, not deleted immediately;
- the bootstrap stack: destroy it last, if at all.

Afterwards, check the budget's actual spend and Cost Explorer for anything still running (VPC
endpoints, Verified Access, ALBs, KMS keys).
