output "function_arn" {
  value       = aws_lambda_function.this.arn
  description = "Interceptor ARN (gateway interceptor_configuration)."
}

output "role_arn" {
  value       = aws_iam_role.this.arn
  description = "Execution role (KMS signer for the frontend client)."
}

output "security_group_id" {
  value       = aws_security_group.this.id
  description = "Interceptor security group."
}
