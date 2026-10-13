output "bucket_arn" {
  value       = aws_s3_bucket.this.arn
  description = "Bundle bucket ARN."
}

output "bucket_name" {
  value       = aws_s3_bucket.this.id
  description = "Bundle bucket name."
}
