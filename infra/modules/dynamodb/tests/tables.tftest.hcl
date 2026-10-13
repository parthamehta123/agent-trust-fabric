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
}

variables {
  name        = "atf-test"
  kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}

run "encrypted_recoverable_protected" {
  command = plan
  assert {
    condition     = alltrue([for t in aws_dynamodb_table.this : t.point_in_time_recovery[0].enabled])
    error_message = "Every table needs point-in-time recovery."
  }
  assert {
    condition     = alltrue([for t in aws_dynamodb_table.this : t.server_side_encryption[0].enabled && t.server_side_encryption[0].kms_key_arn == var.kms_key_arn])
    error_message = "Every table must use the customer-managed key."
  }
  assert {
    condition     = alltrue([for t in aws_dynamodb_table.this : t.deletion_protection_enabled])
    error_message = "Deletion protection must default on."
  }
}

run "key_schemas_match_services" {
  command = plan
  assert {
    condition     = aws_dynamodb_table.this["agents"].hash_key == "agent_id" && aws_dynamodb_table.this["agents"].range_key == "version"
    error_message = "The registry table is (agent_id, version)."
  }
  assert {
    condition     = aws_dynamodb_table.this["mcp-servers"].hash_key == "server_id" && aws_dynamodb_table.this["budgets"].hash_key == "pk"
    error_message = "MCP and budget tables must match their services."
  }
}
