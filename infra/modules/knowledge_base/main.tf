# Knowledge base on S3 Vectors (ADR-0025 §7, ADR-0026 §18).
#   source bucket : only the kb-ingest role writes (it runs our scanner + manifest checks first)
#   vector index  : Titan v2, 1024 dims, cosine; collection + classification_rank filterable
#   Bedrock KB    : read-only on the source, limited to this one index; chunking NONE so our
#                   chunk ids, labels and provenance survive into Retrieve results

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  arn_prefix = "arn:${data.aws_partition.current.partition}"
  acct       = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  embed_arn  = "${local.arn_prefix}:bedrock:${local.region}::foundation-model/${var.embedding_model_id}"
  prefix     = "corpus/"
  # Everything but the two filter keys is stored, returned, and never filterable.
  non_filterable = ["AMAZON_BEDROCK_TEXT", "AMAZON_BEDROCK_METADATA", "chunk_id", "doc_id", "title", "classification", "source", "sha256", "ingested_by", "ingested_at"]
}

# ------------------------------------------------------------------ source bucket
resource "aws_s3_bucket" "source" {
  # checkov:skip=CKV_AWS_18:Writes are audited by CloudTrail S3 data events (ADR-0026, 6d), not access logs.
  # checkov:skip=CKV_AWS_144:The corpus is re-ingestible from its owners; no cross-region copy in dev.
  bucket        = var.source_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "source" {
  bucket                  = aws_s3_bucket.source.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "source" {
  bucket = aws_s3_bucket.source.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "source" {
  bucket = aws_s3_bucket.source.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source" {
  bucket = aws_s3_bucket.source.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "source" {
  bucket = aws_s3_bucket.source.id
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "source" {
  bucket = aws_s3_bucket.source.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.source.arn, "${aws_s3_bucket.source.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "OnlyIngestWrites"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectAcl", "s3:RestoreObject"]
        Resource  = "${aws_s3_bucket.source.arn}/*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = aws_iam_role.ingest.arn } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.source]
}

resource "aws_s3_bucket_notification" "source" {
  bucket      = aws_s3_bucket.source.id
  eventbridge = true # every corpus write is an auditable event
}

# ------------------------------------------------------------------ vectors
resource "aws_s3vectors_vector_bucket" "this" {
  vector_bucket_name = "${var.name}-vectors"
  force_destroy      = false
  encryption_configuration = [{
    sse_type    = "aws:kms"
    kms_key_arn = var.kms_key_arn
  }]
}

resource "aws_s3vectors_index" "this" {
  vector_bucket_name = aws_s3vectors_vector_bucket.this.vector_bucket_name
  index_name         = "${var.name}-chunks"
  data_type          = "float32"
  dimension          = var.dimensions
  distance_metric    = "cosine"
  metadata_configuration {
    non_filterable_metadata_keys = local.non_filterable
  }
}

# ------------------------------------------------------------------ Bedrock KB service role
resource "aws_iam_role" "kb" {
  name = "${var.name}-kb"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      # Confused-deputy guard: only knowledge bases in this account.
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.acct }
        ArnLike      = { "aws:SourceArn" = "${local.arn_prefix}:bedrock:${local.region}:${local.acct}:knowledge-base/*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "kb" {
  role = aws_iam_role.kb.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = local.embed_arn },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.source.arn, Condition = { StringLike = { "s3:prefix" = ["${local.prefix}*"] } } },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.source.arn}/${local.prefix}*" },
      { Effect = "Allow", Action = ["s3vectors:GetIndex", "s3vectors:PutVectors", "s3vectors:GetVectors", "s3vectors:DeleteVectors", "s3vectors:QueryVectors"], Resource = aws_s3vectors_index.this.index_arn },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.kms_key_arn },
    ]
  })
}

resource "aws_bedrockagent_knowledge_base" "this" {
  name     = var.name
  role_arn = aws_iam_role.kb.arn
  knowledge_base_configuration {
    type = "VECTOR"
    vector_knowledge_base_configuration {
      embedding_model_arn = local.embed_arn
      embedding_model_configuration {
        bedrock_embedding_model_configuration {
          dimensions          = var.dimensions
          embedding_data_type = "FLOAT32"
        }
      }
    }
  }
  storage_configuration {
    type = "S3_VECTORS"
    s3_vectors_configuration {
      index_arn = aws_s3vectors_index.this.index_arn
    }
  }
  depends_on = [aws_iam_role_policy.kb]
}

resource "aws_bedrockagent_data_source" "this" {
  knowledge_base_id = aws_bedrockagent_knowledge_base.this.id
  name              = "${var.name}-corpus"
  # A withdrawn document's vectors go when its objects go (followed by a sync).
  data_deletion_policy = "DELETE"
  data_source_configuration {
    type = "S3"
    s3_configuration {
      bucket_arn         = aws_s3_bucket.source.arn
      inclusion_prefixes = [local.prefix]
    }
  }
  server_side_encryption_configuration {
    kms_key_arn = var.kms_key_arn
  }
  vector_ingestion_configuration {
    chunking_configuration {
      chunking_strategy = "NONE" # one object = one of our chunks (ingest --out-s3)
    }
  }
}

# ------------------------------------------------------------------ ingest role
# Assumed only by listed principals (the CI OIDC role from 6d, optionally an operator role). The
# ingest CLI runs the scanner and manifest checks where the corpus lives, then writes here.
resource "aws_iam_role" "ingest" {
  name                 = "${var.name}-kb-ingest"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.ingest_principal_arns }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ingest" {
  role = aws_iam_role.ingest.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:PutObject", "s3:DeleteObject"], Resource = "${aws_s3_bucket.source.arn}/${local.prefix}*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.source.arn, Condition = { StringLike = { "s3:prefix" = ["${local.prefix}*"] } } },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = var.kms_key_arn },
    ]
  })
}
