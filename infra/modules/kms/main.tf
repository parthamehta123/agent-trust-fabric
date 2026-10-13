# Keys (ADR-0010, ADR-0022): one symmetric data key (tables, buckets, logs), the bundle-signing
# key (ES256, only the publisher may Sign), and one signing key per OAuth client (private_key_jwt).

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_root = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
}

resource "aws_kms_key" "data" {
  description             = "${var.name} data encryption (DynamoDB, S3, logs)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.name}/*"
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.data.key_id
}

# Asymmetric signing keys: rotation isn't supported for asymmetric KMS keys; rotate by
# creating a new key and re-pinning (bundle key) or re-registering the JWKS (client keys).
resource "aws_kms_key" "signing" {
  for_each                 = toset(concat(["bundle"], var.client_keys))
  description              = "${var.name} ES256 signing key: ${each.key}"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid       = "AccountAdminNoSign"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = ["kms:Describe*", "kms:Get*", "kms:List*", "kms:Create*", "kms:Put*", "kms:Update*", "kms:Enable*", "kms:Disable*", "kms:Revoke*", "kms:Delete*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:TagResource", "kms:UntagResource"]
        Resource  = "*"
      }],
      length(lookup(var.signers, each.key, [])) == 0 ? [] : [{
        Sid       = "SignOnlyForItsOwner"
        Effect    = "Allow"
        Principal = { AWS = var.signers[each.key] }
        Action    = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
        Resource  = "*"
      }],
    )
  })
}

resource "aws_kms_alias" "signing" {
  for_each      = aws_kms_key.signing
  name          = "alias/${var.name}-sign-${each.key}"
  target_key_id = each.value.key_id
}
