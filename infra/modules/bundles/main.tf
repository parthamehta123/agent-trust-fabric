# Signed policy bundles (ADR-0022 §7): versioned + object lock (forensic history that can't be
# rewritten), SSE-KMS, no public access, TLS only, and only the publisher role may write.

resource "aws_s3_bucket" "this" {
  # checkov:skip=CKV_AWS_18:Writes are audited by CloudTrail S3 data events (ADR-0026, 6d), not access logs.
  # checkov:skip=CKV_AWS_144:Bundles are regenerated every heartbeat; DR re-publishes in the recovery region.
  bucket              = var.bucket_name
  object_lock_enabled = true
  force_destroy       = false
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "OnlyPublisherWrites"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:BypassGovernanceRetention"]
        Resource  = "${aws_s3_bucket.this.arn}/*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = var.publisher_role_arn } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.this]
}

# Every object event goes to EventBridge: an unexpected write (anything but the publisher's
# cadence) is an alertable signal (ADR-0026).
resource "aws_s3_bucket_notification" "this" {
  bucket      = aws_s3_bucket.this.id
  eventbridge = true
}
