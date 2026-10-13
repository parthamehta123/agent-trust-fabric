# Security invariants for the 6a foundations, on a mocked provider (no AWS access).
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", name = "us-east-1" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/atf-dev/vpc-flow-logs" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/atf-dev-shared-mock" }
  }
  mock_resource "aws_security_group" {
    defaults = { id = "sg-shared-mock" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/shared-mock" }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/atf/0123456789abcdef", dns_name = "internal-atf.elb.amazonaws.com", zone_id = "Z35SXDOTRQ7X7K" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/atf/0123456789abcdef" }
  }
  mock_resource "aws_lb_listener" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/atf/0123456789abcdef/0123456789abcdef" }
  }
  mock_resource "aws_acm_certificate" {
    defaults = { arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:us-east-1:123456789012:cluster/atf-dev" }
  }
  mock_resource "aws_ecr_repository" {
    defaults = { arn = "arn:aws:ecr:us-east-1:123456789012:repository/atf-dev/svc", repository_url = "123456789012.dkr.ecr.us-east-1.amazonaws.com/atf-dev/svc" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:us-east-1:123456789012:table/atf-dev-table" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::atf-dev-bundles-test" }
  }
}


override_resource {
  target = module.kms.aws_kms_key.data
  values = { arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111" }
}

variables {
  region              = "us-east-1"
  allowed_account_ids = ["123456789012"]
  azs                 = ["us-east-1a", "us-east-1b"]
  bundle_bucket_name  = "atf-dev-bundles-test"
  budget_alert_emails = ["owner@example.com"]
  domain              = "atf.example.com"
  public_zone_id      = "Z123"
  image_digests = {
    "mcp-gateway"       = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    "mcp-admin"         = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    "inference-gateway" = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    "a2a-gateway"       = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    "agent-registry"    = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    "bundle-publisher"  = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    "knowledge-server"  = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
  }
  verified_access_client_secret = "test-only"
}

run "plans_cleanly" {
  command = plan
  assert {
    condition     = output.table_names["agents"] == "atf-dev-agents"
    error_message = "Tables are named per environment."
  }
}

run "mock_idp_refused_outside_dev" {
  command = plan
  variables {
    environment     = "prod"
    deploy_mock_idp = true
  }
  expect_failures = [check.mock_idp_dev_only]
}

run "public_cidr_refused" {
  command = plan
  variables {
    vpc_cidr = "8.8.0.0/16"
  }
  expect_failures = [var.vpc_cidr]
}

run "no_wildcards_in_any_task_policy" {
  command = plan
  assert {
    condition = alltrue(flatten([
      for svc, stmts in output.service_policies : [
        for st in stmts : !anytrue([for a in flatten([st.Action]) : strcontains(a, "*")]) && !anytrue([for r in flatten([st.Resource]) : r == "*"])
      ]
    ]))
    error_message = "Task policies must name exact actions and resources."
  }
}

run "only_publisher_signs_bundles_and_writes_bucket" {
  command = plan
  assert {
    condition     = [for svc, key in output.sign_grants : svc if key == "bundle"] == ["bundle-publisher"]
    error_message = "Exactly one service, the publisher, may sign bundles."
  }
  assert {
    condition = [
      for svc, stmts in output.service_policies : svc
      if anytrue([for st in stmts : contains(flatten([st.Action]), "s3:PutObject")])
    ] == ["bundle-publisher"]
    error_message = "Only the publisher writes bundles."
  }
  assert {
    condition = sort([
      for svc, stmts in output.service_policies : svc
      if anytrue([for st in stmts : contains(flatten([st.Action]), "kms:Sign")])
    ]) == sort(keys(output.sign_grants))
    error_message = "kms:Sign appears only where sign_grants says so."
  }
}

run "secrets_and_models_scoped_to_one_service" {
  command = plan
  variables {
    allowed_model_arns = ["arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-test"]
  }
  assert {
    condition = [
      for svc, stmts in output.service_policies : svc
      if anytrue([for st in stmts : contains(flatten([st.Action]), "secretsmanager:GetSecretValue")])
    ] == ["mcp-gateway"]
    error_message = "Only the MCP gateway reads tool secrets."
  }
  assert {
    condition = [
      for svc, stmts in output.service_policies : svc
      if anytrue([for st in stmts : contains(flatten([st.Action]), "bedrock:InvokeModel")])
    ] == ["inference-gateway"]
    error_message = "Only the inference gateway invokes models."
  }
}

run "registry_never_deletes" {
  command = plan
  assert {
    condition     = !anytrue([for st in output.service_policies["agent-registry"] : anytrue([for a in flatten([st.Action]) : strcontains(a, "Delete")])])
    error_message = "Registry history is append-only."
  }
}

run "admin_plane_only_via_verified_access" {
  command = plan
  assert {
    condition     = output.plane_sources.admin == sort([output.verified_access_security_group])
    error_message = "Only the Verified Access endpoint reaches the admin ALB (RR-7)."
  }
  assert {
    condition     = output.tools_clients == ["mcp-gateway", "mcp-admin"]
    error_message = "Only the MCP gateway and admin reach tool servers."
  }
}

run "admin_plane_closed_without_verified_access" {
  command = plan
  variables {
    enable_verified_access = false
  }
  assert {
    condition     = length(output.plane_sources.admin) == 0
    error_message = "With Verified Access off, nothing reaches the admin plane."
  }
}
