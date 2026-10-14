output "trail_arn" {
  value       = aws_cloudtrail.this.arn
  description = "Trail ARN."
}

output "bucket_name" {
  value       = aws_s3_bucket.logs.bucket
  description = "Log bucket."
}
