output "data_key_arn" {
  value       = aws_kms_key.data.arn
  description = "Symmetric data key."
}

output "signing_key_arns" {
  value       = { for k, v in aws_kms_key.signing : k => v.arn }
  description = "Signing key ARNs by name ('bundle' plus client keys)."
}
