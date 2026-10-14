# Bootstrap (ADR-0026 §26): remote state, GitHub OIDC, and the three CI roles.
#   plan      : pull requests + main of one repository; read-only, and denied *data* reads
#   apply     : only the `sandbox` GitHub environment (required reviewer); admin minus guardrails
#   ingest-ci : only the `sandbox-ingest` environment; may only assume kb-ingest

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  arn_prefix = "arn:${data.aws_partition.current.partition}"
  acct       = data.aws_caller_identity.current.account_id
  oidc_host  = "token.actions.githubusercontent.com"
  repo_sub   = "repo:${var.github_repository}"

  # Exact subjects, never patterns: forks, other repos and other branches get nothing.
  subjects = {
    plan      = ["${local.repo_sub}:pull_request", "${local.repo_sub}:ref:refs/heads/main"]
    apply     = ["${local.repo_sub}:environment:${var.apply_environment}"]
    ingest-ci = ["${local.repo_sub}:environment:${var.ingest_environment}"]
  }
  role_arns = { for k in keys(local.subjects) : k => "${local.arn_prefix}:iam::${local.acct}:role/${var.name}-ci-${k}" }

  state_arn   = aws_s3_bucket.state.arn
  trail_arn   = "${local.arn_prefix}:s3:::${var.cloudtrail_bucket_name}"
  kb_ingest   = "${local.arn_prefix}:iam::${local.acct}:role/${var.kb_ingest_role_name}"
  global_svcs = ["iam:*", "sts:*", "organizations:*", "route53:*", "cloudfront:*", "budgets:*", "ce:*", "support:*", "health:*", "trustedadvisor:*", "acm:*", "waf:*", "wafv2:*", "shield:*", "globalaccelerator:*"]
}

# ------------------------------------------------------------------ state
resource "aws_kms_key" "state" {
  description             = "${var.name} OpenTofu state"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministers"
      Effect    = "Allow"
      Principal = { AWS = "${local.arn_prefix}:iam::${local.acct}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_s3_bucket" "state" {
  # checkov:skip=CKV_AWS_18:State access is recorded by CloudTrail data events, not access logs.
  # checkov:skip=CKV_AWS_144:Sandbox state; versioning gives recovery, no cross-region copy.
  # checkov:skip=CKV2_AWS_62:No consumers of state-object events.
  bucket        = var.state_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.state]
}

# ------------------------------------------------------------------ GitHub OIDC
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "ci" {
  for_each             = local.subjects
  name                 = "${var.name}-ci-${each.key}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_host}:aud" = "sts.amazonaws.com"
          "${local.oidc_host}:sub" = each.value
        }
      }
    }]
  })
}

# ------------------------------------------------------------------ plan: read-only, no data
resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.ci["plan"].name
  policy_arn = "${local.arn_prefix}:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "plan" {
  name = "state-and-no-data"
  role = aws_iam_role.ci["plan"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ReadState", Effect = "Allow", Action = ["s3:GetObject", "s3:ListBucket"], Resource = [local.state_arn, "${local.state_arn}/*"] },
      # Native S3 locking: a plan takes the lock, so it may write and remove lock objects only.
      { Sid = "LockOnly", Effect = "Allow", Action = ["s3:PutObject", "s3:DeleteObject"], Resource = "${local.state_arn}/*.tflock" },
      { Sid = "StateKey", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.state.arn },
      {
        # ReadOnlyAccess would let a PR-triggered job read workload *data*; it never may.
        Sid         = "NoDataReads"
        Effect      = "Deny"
        Action      = ["s3:GetObject", "s3:GetObjectVersion"]
        NotResource = ["${local.state_arn}/*"]
      },
      {
        Sid      = "NoItemsOrSecrets"
        Effect   = "Deny"
        Action   = ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:GetRecords", "secretsmanager:GetSecretValue", "ssm:GetParameterHistory", "kms:Decrypt", "lambda:InvokeFunction", "bedrock:InvokeModel", "bedrock:Retrieve"]
        Resource = "*"
        Condition = {
          # kms:Decrypt stays allowed for the state key only (the explicit allow above).
          StringNotEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
        }
      },
    ]
  })
}

# ------------------------------------------------------------------ apply: admin minus guardrails
resource "aws_iam_role_policy_attachment" "apply_admin" {
  role       = aws_iam_role.ci["apply"].name
  policy_arn = "${local.arn_prefix}:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy" "apply_guardrails" {
  name = "guardrails"
  role = aws_iam_role.ci["apply"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "NoAccountOrIdentitySprawl"
        Effect   = "Deny"
        Action   = ["organizations:*", "account:*", "aws-portal:*", "billing:*", "iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:CreateServiceSpecificCredential"]
        Resource = "*"
      },
      {
        Sid      = "AuditStaysOn"
        Effect   = "Deny"
        Action   = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"]
        Resource = "*"
      },
      {
        Sid      = "AuditLogsUntouchable"
        Effect   = "Deny"
        Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration", "s3:PutBucketVersioning", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold"]
        Resource = [local.trail_arn, "${local.trail_arn}/*"]
      },
      {
        Sid      = "StateUntouchable"
        Effect   = "Deny"
        Action   = ["s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration"]
        Resource = local.state_arn
      },
      {
        # The apply role can't widen its own (or any CI role's) trust, or swap the IdP.
        Sid    = "TrustUntouchable"
        Effect = "Deny"
        Action = [
          "iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider", "iam:UpdateOpenIDConnectProviderThumbprint", "iam:AddClientIDToOpenIDConnectProvider", "iam:RemoveClientIDFromOpenIDConnectProvider",
          "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:DeleteRole", "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary", "iam:UpdateRole",
        ]
        Resource = concat(values(local.role_arns), [aws_iam_openid_connect_provider.github.arn])
      },
      {
        Sid       = "AllowedRegionsOnly"
        Effect    = "Deny"
        NotAction = local.global_svcs
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions } }
      },
    ]
  })
}

# ------------------------------------------------------------------ ingest-ci: one hop to kb-ingest
resource "aws_iam_role_policy" "ingest_ci" {
  name = "assume-kb-ingest"
  role = aws_iam_role.ci["ingest-ci"].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["sts:AssumeRole"], Resource = local.kb_ingest }]
  })
}
