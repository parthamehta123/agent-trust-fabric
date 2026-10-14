mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::atf-state-test" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/33333333-3333-3333-3333-333333333333" }
  }
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
  }
}

variables {
  region                 = "us-east-1"
  allowed_account_ids    = ["123456789012"]
  github_repository      = "parthamehta123/agent-trust-fabric"
  state_bucket_name      = "atf-state-test"
  cloudtrail_bucket_name = "atf-dev-trail-test"
  allowed_regions        = ["us-east-1"]
}

run "exact_subjects_per_role" {
  command = plan
  assert {
    condition = alltrue([
      for k, t in output.trusts : t.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    ])
    error_message = "Every CI trust pins the STS audience."
  }
  assert {
    condition = toset(output.trusts["plan"].Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]) == toset([
      "repo:parthamehta123/agent-trust-fabric:pull_request",
      "repo:parthamehta123/agent-trust-fabric:ref:refs/heads/main",
    ])
    error_message = "Plan: this repository's pull requests and main only."
  }
  assert {
    condition     = toset(output.trusts["apply"].Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]) == toset(["repo:parthamehta123/agent-trust-fabric:environment:sandbox"])
    error_message = "Apply: only the reviewed sandbox environment."
  }
  assert {
    condition     = toset(output.trusts["ingest-ci"].Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]) == toset(["repo:parthamehta123/agent-trust-fabric:environment:sandbox-ingest"])
    error_message = "Ingest: its own environment, so its subject differs from apply's."
  }
  assert {
    condition = alltrue([
      for k, t in output.trusts : !strcontains(jsonencode(t), "*") && !can(t.Statement[0].Condition.StringLike)
    ])
    error_message = "No wildcards and no pattern matching in any trust."
  }
  assert {
    condition     = alltrue([for r in aws_iam_role.ci : r.max_session_duration == 3600])
    error_message = "CI sessions last at most an hour."
  }
}

run "plan_reads_no_workload_data" {
  command = plan
  assert {
    condition     = one([for st in jsondecode(aws_iam_role_policy.plan.policy).Statement : st if st.Sid == "NoDataReads"]).NotResource == ["arn:aws:s3:::atf-state-test/*"]
    error_message = "The plan role may read state objects and no other objects."
  }
  assert {
    condition = length(setintersection(
      toset(one([for st in jsondecode(aws_iam_role_policy.plan.policy).Statement : st if st.Sid == "NoItemsOrSecrets"]).Action),
      toset(["dynamodb:GetItem", "dynamodb:Scan", "secretsmanager:GetSecretValue", "lambda:InvokeFunction", "bedrock:Retrieve"]),
    )) == 5
    error_message = "No table items, secret values, invocations or retrievals from a PR job."
  }
  assert {
    condition     = one([for st in jsondecode(aws_iam_role_policy.plan.policy).Statement : st if st.Sid == "LockOnly"]).Resource == "arn:aws:s3:::atf-state-test/*.tflock"
    error_message = "Plan writes lock objects only, never state."
  }
}

run "apply_guardrails" {
  command = plan
  assert {
    condition = alltrue([
      for sid in ["NoAccountOrIdentitySprawl", "AuditStaysOn", "AuditLogsUntouchable", "StateUntouchable", "TrustUntouchable", "AllowedRegionsOnly"] :
      anytrue([for st in jsondecode(aws_iam_role_policy.apply_guardrails.policy).Statement : st.Sid == sid && st.Effect == "Deny"])
    ])
    error_message = "Every guardrail is an explicit deny."
  }
  assert {
    condition     = contains(one([for st in jsondecode(aws_iam_role_policy.apply_guardrails.policy).Statement : st if st.Sid == "AuditLogsUntouchable"]).Resource, "arn:aws:s3:::atf-dev-trail-test/*")
    error_message = "The apply role can't touch audit logs."
  }
  assert {
    condition = contains(
      one([for st in jsondecode(aws_iam_role_policy.apply_guardrails.policy).Statement : st if st.Sid == "TrustUntouchable"]).Resource,
      "arn:aws:iam::123456789012:role/atf-ci-apply",
    )
    error_message = "The apply role can't change its own trust or policies."
  }
  assert {
    condition     = one([for st in jsondecode(aws_iam_role_policy.apply_guardrails.policy).Statement : st if st.Sid == "AllowedRegionsOnly"]).Condition.StringNotEquals["aws:RequestedRegion"] == ["us-east-1"]
    error_message = "Regional actions only in allowed regions."
  }
}

run "ingest_ci_is_one_hop" {
  command = plan
  assert {
    condition     = jsondecode(aws_iam_role_policy.ingest_ci.policy).Statement == [{ Effect = "Allow", Action = ["sts:AssumeRole"], Resource = "arn:aws:iam::123456789012:role/atf-dev-kb-ingest" }]
    error_message = "ingest-ci can only assume kb-ingest."
  }
}

run "state_locked_down" {
  command = plan
  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled" && !aws_s3_bucket.state.force_destroy
    error_message = "State is versioned and never force-destroyed."
  }
  assert {
    condition     = aws_kms_key.state.enable_key_rotation
    error_message = "State key rotates."
  }
}

run "wildcard_repo_refused" {
  command = plan
  variables {
    github_repository = "parthamehta123/*"
  }
  expect_failures = [var.github_repository]
}
