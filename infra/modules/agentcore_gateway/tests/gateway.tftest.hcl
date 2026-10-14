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
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/atf-dev-ingress-gateway" }
  }
  mock_resource "aws_bedrockagentcore_gateway" {
    defaults = { gateway_id = "atf-dev-ingress-abcde12345", gateway_arn = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/atf-dev-ingress-abcde12345" }
  }
  mock_resource "aws_ssm_parameter" {
    defaults = { arn = "arn:aws:ssm:us-east-1:123456789012:parameter/atf-dev/interceptor/gateway-id" }
  }
}

variables {
  name                      = "atf-dev-ingress"
  kms_key_arn               = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  discovery_url             = "https://example.okta.com/oauth2/aus-ingress/.well-known/openid-configuration"
  allowed_audiences         = ["api://agent-ingress"]
  allowed_clients           = ["0oa-chat"]
  interceptor_arn           = "arn:aws:lambda:us-east-1:123456789012:function:atf-dev-interceptor"
  target_name               = "agent-alpha"
  target_runtime_arn        = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent_alpha-abc123"
  gateway_id_parameter_name = "/atf-dev/interceptor/gateway-id"
}

run "jwt_pinned_interceptor_both_phases" {
  command = plan
  assert {
    condition     = aws_bedrockagentcore_gateway.this.authorizer_type == "CUSTOM_JWT"
    error_message = "Inbound calls need an IdP token."
  }
  assert {
    condition = alltrue([
      toset(aws_bedrockagentcore_gateway.this.authorizer_configuration[0].custom_jwt_authorizer[0].allowed_audience) == toset(["api://agent-ingress"]),
      toset(aws_bedrockagentcore_gateway.this.authorizer_configuration[0].custom_jwt_authorizer[0].allowed_clients) == toset(["0oa-chat"]),
    ])
    error_message = "Audience and client are pinned."
  }
  assert {
    condition     = aws_bedrockagentcore_gateway.this.interceptor_configuration[0].interception_points == toset(["REQUEST", "RESPONSE"])
    error_message = "The interceptor runs on requests and responses (ADR-0012 §6, ADR-0013)."
  }
  assert {
    condition     = aws_bedrockagentcore_gateway.this.interceptor_configuration[0].input_configuration[0].pass_request_headers
    error_message = "The interceptor needs Authorization + X-Subject-Token to bind the user."
  }
  assert {
    condition     = length(aws_bedrockagentcore_gateway.this.policy_engine_configuration) == 0 && aws_bedrockagentcore_gateway.this.exception_level == null
    error_message = "No second policy source; no debug detail to callers."
  }
}

run "target_never_receives_credentials" {
  command = plan
  assert {
    condition     = toset(aws_bedrockagentcore_gateway_target.runtime.metadata_configuration[0].allowed_request_headers) == toset(["x-atf-request-id", "x-atf-decision", "x-atf-scan-verdict"])
    error_message = "Only the reserved x-atf-* headers are forwarded."
  }
}

run "gateway_role_is_minimal" {
  command = plan
  assert {
    condition = toset(flatten([for st in jsondecode(aws_iam_role_policy.this.policy).Statement : st.Action])) == toset([
      "lambda:InvokeFunction", "bedrock-agentcore:InvokeAgentRuntime", "kms:Decrypt", "kms:GenerateDataKey",
    ])
    error_message = "Invoke the interceptor and the runtime, use the key; nothing else."
  }
  assert {
    condition     = jsondecode(aws_iam_role.this.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "Confused-deputy guard on the service trust."
  }
}

run "gateway_id_published_for_the_interceptor" {
  command = plan
  assert {
    condition     = aws_ssm_parameter.gateway_id.name == var.gateway_id_parameter_name && aws_ssm_parameter.gateway_id.value == "atf-dev-ingress-abcde12345"
    error_message = "The exact gateway id is published for the interceptor (ADR-0026 §22)."
  }
}

run "credential_header_refused" {
  command = plan
  variables {
    allowed_request_headers = ["x-atf-request-id", "x-atf-decision", "x-atf-scan-verdict", "X-Subject-Token"]
  }
  expect_failures = [var.allowed_request_headers]
}

run "missing_reserved_header_refused" {
  command = plan
  variables {
    allowed_request_headers = ["x-atf-request-id", "x-atf-decision"]
  }
  expect_failures = [var.allowed_request_headers]
}

run "open_audience_refused" {
  command = plan
  variables {
    allowed_audiences = []
  }
  expect_failures = [var.allowed_audiences]
}
