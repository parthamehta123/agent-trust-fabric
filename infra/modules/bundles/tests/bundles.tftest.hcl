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
  bucket_name        = "atf-bundles-test"
  kms_key_arn        = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  publisher_role_arn = "arn:aws:iam::123456789012:role/atf-dev-bundle-publisher"
}

run "locked_down" {
  command = plan
  assert {
    condition     = aws_s3_bucket.this.object_lock_enabled && !aws_s3_bucket.this.force_destroy
    error_message = "Object lock on; no force-destroy."
  }
  assert {
    condition     = aws_s3_bucket_versioning.this.versioning_configuration[0].status == "Enabled"
    error_message = "Versioning must be enabled."
  }
  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.this.block_public_acls,
      aws_s3_bucket_public_access_block.this.block_public_policy,
      aws_s3_bucket_public_access_block.this.ignore_public_acls,
      aws_s3_bucket_public_access_block.this.restrict_public_buckets,
    ])
    error_message = "All public access must be blocked."
  }
  assert {
    condition     = one([for r in aws_s3_bucket_server_side_encryption_configuration.this.rule : r.apply_server_side_encryption_by_default[0].sse_algorithm]) == "aws:kms"
    error_message = "SSE-KMS required."
  }
}

run "only_publisher_writes_tls_only" {
  command = plan
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.this.policy).Statement[1].Condition.ArnNotEquals["aws:PrincipalArn"] == var.publisher_role_arn
    error_message = "Every principal but the publisher is denied writes."
  }
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.this.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "Plain HTTP must be denied."
  }
  assert {
    condition     = contains(jsondecode(aws_s3_bucket_policy.this.policy).Statement[1].Action, "s3:BypassGovernanceRetention")
    error_message = "Nobody but the publisher may bypass object-lock governance."
  }
}

run "events_published" {
  command = plan
  assert {
    condition     = aws_s3_bucket_notification.this.eventbridge
    error_message = "Bundle bucket events must reach EventBridge for alerting."
  }
}
