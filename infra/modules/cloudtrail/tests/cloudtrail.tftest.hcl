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
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::atf-dev-trail-test", id = "atf-dev-trail-test" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/44444444-4444-4444-4444-444444444444" }
  }
}

variables {
  name                 = "atf-dev"
  bucket_name          = "atf-dev-trail-test"
  s3_write_bucket_arns = ["arn:aws:s3:::atf-dev-bundles", "arn:aws:s3:::atf-dev-kb-source"]
  lambda_arns          = ["arn:aws:lambda:us-east-1:123456789012:function:atf-dev-interceptor"]
  dynamodb_table_arns  = ["arn:aws:dynamodb:us-east-1:123456789012:table/atf-dev-agents", "arn:aws:dynamodb:us-east-1:123456789012:table/atf-dev-mcp-servers"]
}

run "trail_is_complete_and_verifiable" {
  command = plan
  assert {
    condition     = aws_cloudtrail.this.is_multi_region_trail && aws_cloudtrail.this.include_global_service_events && aws_cloudtrail.this.enable_log_file_validation && aws_cloudtrail.this.enable_logging
    error_message = "Multi-region, global events, log-file validation, logging on."
  }
  assert {
    condition     = aws_cloudtrail.this.kms_key_id == aws_kms_key.trail.arn && aws_kms_key.trail.enable_key_rotation
    error_message = "Encrypted with its own rotating key."
  }
}

run "data_events_exactly_where_they_matter" {
  command = plan
  assert {
    condition = toset([for s in aws_cloudtrail.this.advanced_event_selector : s.name]) == toset([
      "management", "s3-writes-bundles-and-corpus", "interceptor-invokes", "control-plane-table-writes",
    ])
    error_message = "Management events plus the three targeted data-event scopes."
  }
  assert {
    condition = toset(one([
      for f in one([for s in aws_cloudtrail.this.advanced_event_selector : s if s.name == "s3-writes-bundles-and-corpus"]).field_selector : f if f.field == "resources.ARN"
    ]).starts_with) == toset(["arn:aws:s3:::atf-dev-bundles/", "arn:aws:s3:::atf-dev-kb-source/"])
    error_message = "S3 object writes on the bundle and corpus buckets only."
  }
  assert {
    condition = alltrue([
      for s in aws_cloudtrail.this.advanced_event_selector : s.name != "s3-writes-bundles-and-corpus" && s.name != "control-plane-table-writes" ? true :
      tolist(one([for f in s.field_selector : f if f.field == "readOnly"]).equals) == tolist(["false"])
    ])
    error_message = "S3 and DynamoDB selectors record writes, not every read."
  }
  assert {
    condition = toset(one([
      for f in one([for s in aws_cloudtrail.this.advanced_event_selector : s if s.name == "interceptor-invokes"]).field_selector : f if f.field == "resources.ARN"
    ]).equals) == toset(var.lambda_arns)
    error_message = "Every interceptor invocation is recorded (TM-INT-03)."
  }
}

run "logs_cannot_be_deleted_or_forged" {
  command = plan
  assert {
    condition     = aws_s3_bucket.logs.object_lock_enabled && one(aws_s3_bucket_object_lock_configuration.logs.rule).default_retention[0].days == 365
    error_message = "Object lock with the retention period."
  }
  assert {
    condition = contains(
      one([for st in jsondecode(aws_s3_bucket_policy.logs.policy).Statement : st if st.Sid == "NobodyDeletesLogs"]).Action,
      "s3:DeleteObjectVersion",
    )
    error_message = "No principal deletes log versions."
  }
  assert {
    condition     = one([for st in jsondecode(aws_s3_bucket_policy.logs.policy).Statement : st if st.Sid == "OnlyTheTrailWrites"]).Condition.StringNotEquals["aws:PrincipalServiceName"] == "cloudtrail.amazonaws.com"
    error_message = "Only CloudTrail writes logs."
  }
  assert {
    condition = alltrue([
      for st in jsondecode(aws_s3_bucket_policy.logs.policy).Statement : st.Effect == "Deny" || st.Condition.StringEquals["aws:SourceArn"] == "arn:aws:cloudtrail:us-east-1:123456789012:trail/atf-dev"
    ])
    error_message = "Every allow is scoped to this trail (confused-deputy guard)."
  }
}

run "short_retention_refused" {
  command = plan
  variables {
    retention_days = 30
  }
  expect_failures = [var.retention_days]
}
