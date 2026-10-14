mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/atf-dev-interceptor" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/atf-dev/lambda/interceptor" }
  }
}

variables {
  name_prefix          = "atf-dev"
  repository_url       = "123456789012.dkr.ecr.us-east-1.amazonaws.com/atf-dev/interceptor"
  image_digest         = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  kms_key_arn          = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  function_policy_json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
  environment          = { ATF_ENV = "dev" }
  vpc_id               = "vpc-123"
  subnet_ids           = ["subnet-a", "subnet-b"]
  egress_cidrs         = { okta = "203.0.113.0/24" }
}

run "hardened_function" {
  command = plan
  assert {
    condition     = aws_lambda_function.this.package_type == "Image" && endswith(aws_lambda_function.this.image_uri, "@${var.image_digest}")
    error_message = "Container image by digest only."
  }
  assert {
    condition     = toset(aws_lambda_function.this.architectures) == toset(["arm64"])
    error_message = "arm64, matching the service images."
  }
  assert {
    condition     = aws_lambda_function.this.reserved_concurrent_executions == 50 && aws_lambda_function.this.kms_key_arn == var.kms_key_arn
    error_message = "Reserved concurrency and a KMS-encrypted environment."
  }
  assert {
    condition     = length(aws_lambda_function.this.vpc_config[0].subnet_ids) == 2 && aws_lambda_function.this.timeout > 4
    error_message = "VPC-attached; timeout above the internal deadline."
  }
}

run "named_egress_only" {
  command = plan
  assert {
    condition     = length(aws_vpc_security_group_egress_rule.to_cidr) == 1 && aws_vpc_security_group_egress_rule.to_cidr["okta"].from_port == 443
    error_message = "Egress only to named destinations on 443."
  }
}

run "eni_permissions_confined_to_the_vpc" {
  command = plan
  assert {
    condition = alltrue([
      for st in jsondecode(aws_iam_role_policy.platform.policy).Statement :
      st.Resource != "*" || strcontains(jsonencode(st.Condition), "vpc/vpc-123")
    ])
    error_message = "The only wildcard resource (ENI actions) is conditioned on this VPC."
  }
}

run "tag_refused" {
  command = plan
  variables {
    image_digest = "latest"
  }
  expect_failures = [var.image_digest]
}

run "timeout_must_exceed_deadline" {
  command = plan
  variables {
    timeout_s = 3
  }
  expect_failures = [var.timeout_s]
}
