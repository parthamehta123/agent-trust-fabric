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
  mock_data "aws_kms_public_key" {
    # Test-only P-256 public key (no private half exists anywhere).
    defaults = { public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl8kDwiphFQn5u2NG0+rgSZe0d0tj\nto7pa46BroT6zYTQGCzXvO7i6okgDFfuGpeAfbysM1PpWh+vCUmgbxA/sw==\n-----END PUBLIC KEY-----\n" }
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
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222" }
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
  mock_resource "aws_bedrock_guardrail" {
    defaults = { guardrail_id = "gr0123456789", guardrail_arn = "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr0123456789" }
  }
  mock_resource "aws_bedrock_guardrail_version" {
    defaults = { version = "1" }
  }
  mock_resource "aws_s3vectors_index" {
    defaults = { index_arn = "arn:aws:s3vectors:us-east-1:123456789012:bucket/atf-dev-vectors/index/atf-dev-chunks" }
  }
  mock_resource "aws_bedrockagent_knowledge_base" {
    defaults = { id = "KBTEST12345", arn = "arn:aws:bedrock:us-east-1:123456789012:knowledge-base/KBTEST12345" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:function:atf-dev-interceptor" }
  }
  mock_resource "aws_bedrockagentcore_gateway" {
    defaults = { gateway_id = "atf-dev-ingress-abcde12345", gateway_url = "https://atf-dev-ingress-abcde12345.gateway.bedrock-agentcore.us-east-1.amazonaws.com" }
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
    "interceptor"       = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  }
  ingress_agent = {
    name                 = "agent-alpha"
    runtime_arn          = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent_alpha-abc123"
    authorization_server = { id = "aus-agent-alpha", audience = "api://agent-alpha" }
    scopes               = ["agent.invoke", "kb.public.read"]
  }
  kb_source_bucket_name         = "atf-dev-kb-source-test"
  kb_ingest_principal_arns      = ["arn:aws:iam::123456789012:role/atf-ci-ingest"]
  cloudtrail_bucket_name        = "atf-dev-trail-test"
  verified_access_client_secret = "test-only"
  idp = {
    base_url = "https://example.okta.com"
    authorization_servers = {
      workload  = { id = "aus-workload", audience = "api://tool-gateway" }
      inference = { id = "aus-inference", audience = "api://inference-gateway" }
      registry  = { id = "aus-registry", audience = "api://agent-registry" }
      admin     = { id = "aus-admin", audience = "api://mcp-admin" }
      ingress   = { id = "aus-ingress", audience = "api://agent-ingress" }
      knowledge = { id = "aus-knowledge", audience = "api://knowledge" }
    }
    tool_authorization_servers = {
      tickets = { id = "aus-tickets", audience = "api://tool-tickets" }
    }
    clients = { tool_gateway = "0oa-tool-gateway", a2a_gateway = "0oa-a2a-gateway", frontend = "0oa-chat" }
  }
  model_routes = { "claude-sonnet" = { provider_model = "bedrock/anthropic.claude-sonnet-test-v1:0" } }
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


# ------------------------------------------------------------------ 6c-ii: runtime config

run "every_service_gets_the_env_its_code_reads" {
  # Lists come from the services' own env reads (build_app / app_from_env / publish main).
  command = plan
  assert {
    condition = alltrue([
      for svc, keys in {
        "mcp-gateway"       = ["ATF_DDB_TABLE", "ATF_EGRESS_PROFILE_JSON", "ATF_TOOL_AUTHORITIES_JSON", "ATF_SSRF_INTERNAL_HOSTS", "ATF_BUNDLE_ISSUER", "ATF_BUNDLE_PUBLIC_KEY_PEM", "ATF_BUNDLE_S3_BUCKET", "ATF_BUNDLE_S3_KEY"]
        "mcp-admin"         = ["ATF_ADMIN_ISSUER", "ATF_ADMIN_AUDIENCE", "ATF_ADMIN_JWKS_URI", "ATF_DDB_TABLE", "ATF_TOOL_AUTHORITIES_JSON", "ATF_SSRF_INTERNAL_HOSTS"]
        "inference-gateway" = ["ATF_BUDGET_TABLE", "ATF_INFERENCE_PROFILE_JSON", "ATF_MODEL_ROUTES_JSON", "ATF_GUARDRAIL_ID", "ATF_GUARDRAIL_VERSION", "ATF_BUNDLE_ISSUER", "ATF_BUNDLE_PUBLIC_KEY_PEM", "ATF_BUNDLE_S3_BUCKET", "ATF_BUNDLE_S3_KEY"]
        "a2a-gateway"       = ["ATF_A2A_EGRESS_PROFILE_JSON", "ATF_A2A_PUBLIC_URL", "ATF_A2A_TARGET_SCOPES", "ATF_SSRF_INTERNAL_HOSTS", "ATF_BUNDLE_ISSUER", "ATF_BUNDLE_PUBLIC_KEY_PEM", "ATF_BUNDLE_S3_BUCKET", "ATF_BUNDLE_S3_KEY"]
        "agent-registry"    = ["ATF_REGISTRY_ISSUER", "ATF_REGISTRY_AUDIENCE", "ATF_REGISTRY_JWKS_URI", "ATF_REGISTRY_TABLE"]
        "bundle-publisher"  = ["ATF_REGISTRY_TABLE", "ATF_BUNDLE_ISSUER", "ATF_BUNDLE_SIGNING_KEY", "ATF_BUNDLE_S3_BUCKET", "ATF_BUNDLE_S3_KEY", "ATF_GUARDRAILS_CEDAR"]
        "knowledge-server"  = ["ATF_KB_ISSUER", "ATF_KB_AUDIENCE", "ATF_KB_JWKS_URI", "ATF_KB_BEDROCK_ID", "ATF_BUNDLE_ISSUER", "ATF_BUNDLE_PUBLIC_KEY_PEM", "ATF_BUNDLE_S3_BUCKET", "ATF_BUNDLE_S3_KEY"]
        } : alltrue([
          length(setsubtract(keys, keys(output.service_environment[svc]))) == 0,
          output.service_environment[svc]["ATF_ENV"] == "dev",
          output.service_environment[svc]["AWS_REGION"] == "us-east-1",
      ])
    ])
    error_message = "A service is missing an environment variable its code requires."
  }
}

run "no_local_only_or_secret_shaped_env" {
  command = plan
  assert {
    condition = alltrue(flatten([
      for svc, env in output.service_environment : [
        for k, v in env : alltrue([
          !endswith(k, "_PATH"),
          !contains(["ATF_SSRF_ALLOW_CIDRS", "ATF_LOCAL_KEYS_DIR", "ATF_CA_BUNDLE", "ATF_MOCK_LLM_KEY"], k),
          !startswith(k, "AWS_ENDPOINT_URL"),
          !startswith(k, "AWS_ACCESS_KEY"),
          !strcontains(k, "SECRET"),
          v != "local",
          !can(regex("PRIVATE KEY|AKIA[0-9A-Z]{16}|client_secret|(^|[^a-z])local:[a-z]", v)),
        ])
      ]
    ]))
    error_message = "Rendered env holds a local-only switch or secret-shaped material."
  }
}

run "env_fits_with_headroom" {
  # ECS caps a container definition near 64 KiB; keep each service's env under 48 KiB.
  command = plan
  assert {
    condition = alltrue([
      for svc, env in output.service_environment : sum([for k, v in env : length(k) + length(v) + 8]) < 49152
    ])
    error_message = "A service's rendered environment is too close to the container-definition limit."
  }
}

run "bundle_key_pinned_not_granted" {
  command = plan
  assert {
    condition = alltrue([
      for svc in ["mcp-gateway", "inference-gateway", "a2a-gateway", "knowledge-server"] :
      startswith(output.service_environment[svc]["ATF_BUNDLE_PUBLIC_KEY_PEM"], "-----BEGIN PUBLIC KEY-----")
    ])
    error_message = "Every verifier pins the bundle key's public half."
  }
  assert {
    # Verifiers never call KMS for it: only signers (sign_grants) hold any KMS signing action.
    condition = alltrue(flatten([
      for svc, stmts in output.service_policies : [
        for st in stmts : contains(["bundle-publisher", "mcp-gateway", "a2a-gateway", "interceptor"], svc)
        if length(setintersection(toset(flatten([st.Action])), toset(["kms:Sign", "kms:GetPublicKey"]))) > 0
      ]
    ]))
    error_message = "Only signers may hold kms:Sign or kms:GetPublicKey."
  }
}

run "clients_sign_with_their_own_kms_key" {
  command = plan
  assert {
    condition     = jsondecode(output.service_environment["mcp-gateway"]["ATF_EGRESS_PROFILE_JSON"]).client.signing_key == output.signing_keys["tool-gateway"]
    error_message = "The MCP gateway signs client assertions with its own KMS key."
  }
  assert {
    condition     = jsondecode(output.service_environment["a2a-gateway"]["ATF_A2A_EGRESS_PROFILE_JSON"]).client.signing_key == output.signing_keys["a2a-gateway"]
    error_message = "The A2A gateway signs client assertions with its own KMS key."
  }
  assert {
    condition     = output.service_environment["bundle-publisher"]["ATF_BUNDLE_SIGNING_KEY"] == output.signing_keys["bundle"]
    error_message = "The publisher signs bundles with the bundle key."
  }
}

run "tool_authorities_one_audience_per_as" {
  command = plan
  assert {
    condition = jsondecode(output.service_environment["mcp-gateway"]["ATF_TOOL_AUTHORITIES_JSON"]) == {
      "api://knowledge"    = { issuer = "https://example.okta.com/oauth2/aus-knowledge", token_endpoint = "https://example.okta.com/oauth2/aus-knowledge/v1/token", jwks_uri = "https://example.okta.com/oauth2/aus-knowledge/v1/keys" }
      "api://tool-tickets" = { issuer = "https://example.okta.com/oauth2/aus-tickets", token_endpoint = "https://example.okta.com/oauth2/aus-tickets/v1/token", jwks_uri = "https://example.okta.com/oauth2/aus-tickets/v1/keys" }
    }
    error_message = "Tool authorities: the knowledge AS plus each tool AS, by Okta convention."
  }
}

run "internal_egress_is_tools_plane_only" {
  command = plan
  assert {
    condition = jsondecode(output.service_environment["mcp-gateway"]["ATF_SSRF_INTERNAL_HOSTS"]) == {
      "knowledge.atf.example.com" = ["10.40.0.0/20", "10.40.16.0/20"]
    }
    error_message = "MCP egress may reach only the tools plane, confined to the private subnets."
  }
  assert {
    condition     = output.service_environment["mcp-admin"]["ATF_SSRF_INTERNAL_HOSTS"] == output.service_environment["mcp-gateway"]["ATF_SSRF_INTERNAL_HOSTS"]
    error_message = "Enrolment vetting and calls use the same internal hosts."
  }
}

run "admin_host_as_a2a_target_refused" {
  command = plan
  variables {
    a2a_internal_hosts = { "registry.atf.example.com" = ["10.40.0.0/20"] }
  }
  expect_failures = [check.no_admin_hosts_in_egress]
}

run "non_bedrock_route_refused" {
  command = plan
  variables {
    model_routes = { mock = { provider_model = "openai/mock-sonnet" } }
  }
  expect_failures = [var.model_routes]
}

run "shared_audience_refused" {
  command = plan
  variables {
    idp = {
      base_url = "https://example.okta.com"
      authorization_servers = {
        workload  = { id = "aus-workload", audience = "api://tool-gateway" }
        inference = { id = "aus-inference", audience = "api://inference-gateway" }
        registry  = { id = "aus-registry", audience = "api://agent-registry" }
        admin     = { id = "aus-admin", audience = "api://mcp-admin" }
        ingress   = { id = "aus-ingress", audience = "api://agent-ingress" }
        knowledge = { id = "aus-knowledge", audience = "api://knowledge" }
      }
      tool_authorization_servers = { tickets = { id = "aus-tickets", audience = "api://knowledge" } }
      clients                    = { tool_gateway = "a", a2a_gateway = "b", frontend = "c" }
    }
  }
  expect_failures = [var.idp]
}

run "guardrails_rendered_from_the_repo" {
  command = plan
  assert {
    condition     = output.service_environment["bundle-publisher"]["ATF_GUARDRAILS_CEDAR"] == file("../../../policies/guardrails.cedar")
    error_message = "The publisher's guardrails are the reviewed file, verbatim."
  }
}


# ------------------------------------------------------------------ 6c-iii: edge + knowledge

run "interceptor_is_ingress_only_and_bound_by_parameter" {
  command = plan
  assert {
    condition = alltrue([
      output.interceptor_environment["ATF_GATEWAY_ID_PARAMETER"] == "/atf-dev/interceptor/gateway-id",
      length(jsondecode(output.interceptor_environment["ATF_PROFILES_JSON"]).profiles) == 1,
      !anytrue([for k in keys(output.interceptor_environment) : startswith(k, "ATF_BUNDLE_") || endswith(k, "_PATH") || k == "ATF_CA_BUNDLE"]),
    ])
    error_message = "One profile bound from SSM at cold start; no bundle, no local-only settings."
  }
  assert {
    condition     = jsondecode(output.interceptor_environment["ATF_PROFILES_JSON"]).profiles[0].ingress_clients["0oa-chat"] == output.signing_keys["interceptor"]
    error_message = "The frontend client's assertions are signed with the interceptor's own KMS key."
  }
  assert {
    condition = toset([for st in output.service_policies["interceptor"] : join(",", sort(flatten([st.Action])))]) == toset([
      "kms:GetPublicKey,kms:Sign", "ssm:GetParameter",
    ])
    error_message = "The interceptor may sign with its key and read its gateway id; nothing else."
  }
}

run "bedrock_access_scoped_to_one_service_each" {
  command = plan
  assert {
    condition = [
      for svc, stmts in output.service_policies : svc
      if anytrue([for st in stmts : contains(flatten([st.Action]), "bedrock:ApplyGuardrail")])
    ] == ["inference-gateway"]
    error_message = "Only the inference gateway applies the guardrail."
  }
  assert {
    condition = [
      for svc, stmts in output.service_policies : svc
      if anytrue([for st in stmts : contains(flatten([st.Action]), "bedrock:Retrieve")])
    ] == ["knowledge-server"]
    error_message = "Only the knowledge server retrieves from the KB."
  }
  assert {
    condition = alltrue([
      output.service_environment["inference-gateway"]["ATF_GUARDRAIL_VERSION"] == "1",
      output.service_environment["inference-gateway"]["ATF_GUARDRAIL_ID"] == "gr0123456789",
      output.service_environment["knowledge-server"]["ATF_KB_BEDROCK_ID"] == "KBTEST12345",
    ])
    error_message = "The gateway pins the published guardrail version; the knowledge server uses the KB."
  }
}

run "nobody_invokes_lambda_but_the_gateway" {
  command = plan
  assert {
    condition = !anytrue(flatten([
      for svc, stmts in output.service_policies : [for st in stmts : anytrue([for a in flatten([st.Action]) : startswith(a, "lambda:")])]
    ]))
    error_message = "No task or function role may invoke Lambda."
  }
}

run "kb_outputs_for_the_runbook" {
  command = plan
  assert {
    condition     = output.knowledge.source_bucket == "atf-dev-kb-source-test"
    error_message = "The ingest runbook needs the corpus bucket."
  }
}


# ------------------------------------------------------------------ 6d-ii: audit

run "trail_covers_every_security_relevant_write" {
  command = plan
  assert {
    condition     = length(output.audit.data_event_arns.s3) == 2 && length(output.audit.data_event_arns.lambda) == 1 && length(output.audit.data_event_arns.dynamodb) == 2
    error_message = "Bundles and corpus writes, interceptor invokes, agents and mcp-servers writes."
  }
  assert {
    condition     = output.audit.bucket == "atf-dev-trail-test"
    error_message = "The trail writes to the bucket bootstrap's guardrails protect."
  }
}
