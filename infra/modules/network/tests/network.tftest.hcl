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
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/atf-test/vpc-flow-logs" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/atf-test-vpc-flow-logs" }
  }
}

variables {
  name             = "atf-test"
  cidr             = "10.40.0.0/16"
  azs              = ["us-east-1a", "us-east-1b"]
  logs_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}

run "private_only" {
  command = plan
  assert {
    condition     = length(aws_subnet.private) == 2 && alltrue([for s in aws_subnet.private : !s.map_public_ip_on_launch])
    error_message = "Private subnets only, one per AZ."
  }
  assert {
    condition     = length(aws_default_security_group.this.ingress) == 0 && length(aws_default_security_group.this.egress) == 0
    error_message = "The default security group must have no rules."
  }
  assert {
    condition     = alltrue([for k in ["bedrock-runtime", "kms", "sts", "secretsmanager"] : contains(keys(aws_vpc_endpoint.interface), k)])
    error_message = "AWS APIs must be reachable privately."
  }
  assert {
    condition     = aws_flow_log.this.traffic_type == "ALL"
    error_message = "Flow logs capture all traffic."
  }
}

run "public_cidr_refused" {
  command = plan
  variables {
    cidr = "8.8.0.0/16"
  }
  expect_failures = [var.cidr]
}

run "single_az_refused" {
  command = plan
  variables {
    azs = ["us-east-1a"]
  }
  expect_failures = [var.azs]
}
