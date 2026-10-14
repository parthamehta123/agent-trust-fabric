output "role_arns" {
  value       = { for k, r in aws_iam_role.ci : k => r.arn }
  description = "CI role ARNs (repository variables for the workflows)."
}

output "trusts" {
  value       = { for k, r in aws_iam_role.ci : k => jsondecode(r.assume_role_policy) }
  description = "Effective trust policies (asserted in tests)."
}

output "state_bucket" {
  value       = aws_s3_bucket.state.bucket
  description = "Remote state bucket (envs/*/backend.hcl)."
}

output "state_kms_key_arn" {
  value       = aws_kms_key.state.arn
  description = "State encryption key (backend kms_key_id)."
}
