output "vpc_id" {
  value       = module.network.vpc_id
  description = "VPC id."
}

output "table_names" {
  value       = module.tables.table_names
  description = "DynamoDB tables."
}

output "bundle_bucket" {
  value       = module.bundles.bucket_name
  description = "Bundle bucket."
}

output "signing_keys" {
  value       = module.kms.signing_key_arns
  description = "Signing key ARNs."
}

output "service_policies" {
  value       = local.policies
  description = "Effective task-role statements per service (reviewed and asserted in tests)."
}

output "plane_sources" {
  value = {
    data  = module.alb_data.allowed_sources
    admin = module.alb_admin.allowed_sources
    tools = module.alb_tools.allowed_sources
  }
  description = "Who can reach each plane's ALB."
}

output "service_security_groups" {
  value       = { for k, m in module.svc : k => m.security_group_id }
  description = "Task security group per service."
}

output "verified_access_security_group" {
  value       = var.enable_verified_access ? module.verified_access[0].security_group_id : null
  description = "The only source admitted to the admin ALB."
}

output "sign_grants" {
  value       = local.sign_grants
  description = "Service -> the one signing key it may use (drives IAM and KMS key policies)."
}

output "tools_clients" {
  value       = local.tools_clients
  description = "Services allowed to reach tool servers."
}

output "service_environment" {
  value       = local.rendered_env
  description = "Rendered, non-secret runtime environment per service (reviewed and asserted in tests)."
}
