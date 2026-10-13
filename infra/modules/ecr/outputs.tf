output "repository_urls" {
  value       = { for k, r in aws_ecr_repository.this : k => r.repository_url }
  description = "Repository URL by service."
}

output "repository_arns" {
  value       = { for k, r in aws_ecr_repository.this : k => r.arn }
  description = "Repository ARN by service."
}
