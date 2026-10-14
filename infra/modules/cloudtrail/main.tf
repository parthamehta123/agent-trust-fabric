# Account audit trail (ADR-0026 §27): multi-region, log-file validation, its own KMS key, a log
# bucket nobody can delete from (object lock, deny-delete), and data events only where a
# mutation is security-relevant.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  arn_prefix = "arn:${data.aws_partition.current.partition}"
  acct       = data.aws_caller_identity.current.account_id
  trail_arn  = "${local.arn_prefix}:cloudtrail:${data.aws_region.current.region}:${local.acct}:trail/${var.name}"
}

# ------------------------------------------------------------------ key
resource "aws_kms_key" "trail" {
  description             = "${var.name} CloudTrail logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministers"
        Effect    = "Allow"
        Principal = { AWS = "${local.arn_prefix}:iam::${local.acct}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "ThisTrailEncrypts"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "${local.arn_prefix}:cloudtrail:*:${local.acct}:trail/*" }
        }
      },
      {
        Sid       = "TrailDescribesKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AccountReadsLogs"
        Effect    = "Allow"
        Principal = { AWS = "${local.arn_prefix}:iam::${local.acct}:root" }
        Action    = ["kms:Decrypt", "kms:ReEncryptFrom"]
        Resource  = "*"
        Condition = {
          StringEquals = { "kms:CallerAccount" = local.acct }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "${local.arn_prefix}:cloudtrail:*:${local.acct}:trail/*" }
        }
      },
    ]
  })
}

# ------------------------------------------------------------------ log bucket
resource "aws_s3_bucket" "logs" {
  # checkov:skip=CKV_AWS_18:This is the audit sink; access to it is itself recorded by the trail.
  # checkov:skip=CKV_AWS_144:Sandbox audit; object lock + versioning, no cross-region copy.
  # checkov:skip=CKV2_AWS_62:No consumers of log-object events.
  bucket              = var.bucket_name
  object_lock_enabled = true
  force_destroy       = false
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    default_retention {
      mode = "GOVERNANCE" # the CI apply role is denied BypassGovernanceRetention (bootstrap)
      days = var.retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-after-retention"
    status = "Enabled"
    filter {}
    expiration {
      days = var.retention_days + 1
    }
    noncurrent_version_expiration {
      noncurrent_days = var.retention_days + 1
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.logs.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "TrailWrites"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/AWSLogs/${local.acct}/*"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        # Only lifecycle expiry removes logs; no principal may delete or rewrite them.
        Sid       = "NobodyDeletesLogs"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold"]
        Resource  = "${aws_s3_bucket.logs.arn}/*"
      },
      {
        # Absent for IAM principals, so StringNotEquals denies every non-service writer.
        Sid       = "OnlyTheTrailWrites"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/*"
        Condition = { StringNotEquals = { "aws:PrincipalServiceName" = "cloudtrail.amazonaws.com" } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# ------------------------------------------------------------------ trail
resource "aws_cloudtrail" "this" {
  # checkov:skip=CKV2_AWS_10:No CloudWatch Logs delivery in the sandbox; S3 with validation is the record.
  # checkov:skip=CKV_AWS_252:No SNS delivery notifications in the sandbox.
  name                          = var.name
  s3_bucket_name                = aws_s3_bucket.logs.id
  kms_key_id                    = aws_kms_key.trail.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  advanced_event_selector {
    name = "management"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "s3-writes-bundles-and-corpus"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field  = "readOnly"
      equals = ["false"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = [for b in var.s3_write_bucket_arns : "${b}/"]
    }
  }

  advanced_event_selector {
    name = "interceptor-invokes"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::Lambda::Function"]
    }
    field_selector {
      field  = "resources.ARN"
      equals = var.lambda_arns
    }
  }

  advanced_event_selector {
    name = "control-plane-table-writes"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::DynamoDB::Table"]
    }
    field_selector {
      field  = "readOnly"
      equals = ["false"]
    }
    field_selector {
      field  = "resources.ARN"
      equals = var.dynamodb_table_arns
    }
  }

  depends_on = [aws_s3_bucket_policy.logs]
}
