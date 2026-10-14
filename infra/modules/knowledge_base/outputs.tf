output "knowledge_base_id" {
  value       = aws_bedrockagent_knowledge_base.this.id
  description = "KB id (ATF_KB_BEDROCK_ID)."
}

output "knowledge_base_arn" {
  value       = aws_bedrockagent_knowledge_base.this.arn
  description = "KB ARN (scopes bedrock:Retrieve)."
}

output "source_bucket" {
  value       = aws_s3_bucket.source.bucket
  description = "Corpus bucket (ingest --out-s3 s3://<bucket>/corpus)."
}

output "ingest_role_arn" {
  value       = aws_iam_role.ingest.arn
  description = "The only writer of the corpus bucket."
}

output "data_source_id" {
  value       = aws_bedrockagent_data_source.this.data_source_id
  description = "Data source to sync after ingest (runbook)."
}

output "source_bucket_arn" {
  value       = aws_s3_bucket.source.arn
  description = "Corpus bucket ARN (CloudTrail data events)."
}
