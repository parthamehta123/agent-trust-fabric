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
    defaults = { arn = "arn:aws:s3:::atf-dev-kb-source-test" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/atf-dev-kb-ingest" }
  }
  mock_resource "aws_s3vectors_index" {
    defaults = { index_arn = "arn:aws:s3vectors:us-east-1:123456789012:bucket/atf-dev-vectors/index/atf-dev-chunks" }
  }
  mock_resource "aws_bedrockagent_knowledge_base" {
    defaults = { id = "KBTEST12345", arn = "arn:aws:bedrock:us-east-1:123456789012:knowledge-base/KBTEST12345" }
  }
}

variables {
  name                  = "atf-dev"
  source_bucket_name    = "atf-dev-kb-source-test"
  kms_key_arn           = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  ingest_principal_arns = ["arn:aws:iam::123456789012:role/atf-ci-plan"]
}

run "vectors_match_the_contract" {
  command = plan
  assert {
    condition     = aws_s3vectors_index.this.dimension == 1024 && aws_s3vectors_index.this.distance_metric == "cosine" && aws_s3vectors_index.this.data_type == "float32"
    error_message = "Titan v2: 1024 dims, cosine, float32."
  }
  assert {
    # The pre-filter (bedrock_kb.to_kb_filter) uses exactly these two keys; they must stay filterable.
    condition = length(setintersection(
      toset(aws_s3vectors_index.this.metadata_configuration[0].non_filterable_metadata_keys),
      toset(["collection", "classification_rank"]),
    )) == 0
    error_message = "collection and classification_rank must be filterable."
  }
  assert {
    condition     = one(aws_bedrockagent_knowledge_base.this.knowledge_base_configuration[0].vector_knowledge_base_configuration[0].embedding_model_configuration[0].bedrock_embedding_model_configuration).dimensions == aws_s3vectors_index.this.dimension
    error_message = "KB embedding dimensions must equal the index dimension."
  }
  assert {
    condition     = aws_bedrockagent_data_source.this.vector_ingestion_configuration[0].chunking_configuration[0].chunking_strategy == "NONE"
    error_message = "Our chunks are the unit (ADR-0026 §18): no re-chunking."
  }
  assert {
    condition     = aws_bedrockagent_data_source.this.data_deletion_policy == "DELETE"
    error_message = "Withdrawn documents' vectors must go on sync."
  }
}

run "only_ingest_writes_the_corpus" {
  command = plan
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.source.policy).Statement[1].Condition.ArnNotEquals["aws:PrincipalArn"] == "arn:aws:iam::123456789012:role/atf-dev-kb-ingest"
    error_message = "Every principal but kb-ingest is denied corpus writes."
  }
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.source.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "Plain HTTP must be denied."
  }
  assert {
    condition     = jsondecode(aws_iam_role.ingest.assume_role_policy).Statement[0].Principal.AWS == var.ingest_principal_arns
    error_message = "Only the listed principals may assume kb-ingest."
  }
  assert {
    condition = alltrue([
      for st in jsondecode(aws_iam_role_policy.ingest.policy).Statement :
      !anytrue([for a in flatten([st.Action]) : strcontains(a, "*") || startswith(a, "bedrock:") || a == "s3:GetObject"])
    ])
    error_message = "kb-ingest writes the corpus only: no wildcards, no Bedrock, no reads."
  }
}

run "kb_role_is_read_only_and_scoped" {
  command = plan
  assert {
    condition = alltrue([
      for st in jsondecode(aws_iam_role_policy.kb.policy).Statement :
      !anytrue([for a in flatten([st.Action]) : contains(["s3:PutObject", "s3:DeleteObject"], a) || strcontains(a, "*")]) && st.Resource != "*"
    ])
    error_message = "The Bedrock KB role never writes the corpus and names exact resources."
  }
  assert {
    condition     = jsondecode(aws_iam_role.kb.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "Confused-deputy guard on the Bedrock trust."
  }
}

run "encrypted_and_private" {
  command = plan
  assert {
    condition     = one(aws_s3vectors_vector_bucket.this.encryption_configuration).kms_key_arn == var.kms_key_arn
    error_message = "Vectors are encrypted with the data key."
  }
  assert {
    condition     = aws_bedrockagent_data_source.this.server_side_encryption_configuration[0].kms_key_arn == var.kms_key_arn
    error_message = "Data source encrypted with the data key."
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.source.restrict_public_buckets && aws_s3_bucket_public_access_block.source.block_public_policy
    error_message = "No public access to the corpus."
  }
}

run "wildcard_principal_refused" {
  command = plan
  variables {
    ingest_principal_arns = ["*"]
  }
  expect_failures = [var.ingest_principal_arns]
}
