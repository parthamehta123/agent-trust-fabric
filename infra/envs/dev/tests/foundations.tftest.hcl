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
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/atf-dev-bundle-publisher" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/atf-dev/vpc-flow-logs" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::atf-dev-bundles-test" }
  }
}

variables {
  region              = "us-east-1"
  allowed_account_ids = ["123456789012"]
  azs                 = ["us-east-1a", "us-east-1b"]
  bundle_bucket_name  = "atf-dev-bundles-test"
  budget_alert_emails = ["owner@example.com"]
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
