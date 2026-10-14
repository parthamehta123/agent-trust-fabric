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
  value       = merge(local.policies, local.function_policies)
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

output "interceptor_environment" {
  value       = local.interceptor_env
  description = "Rendered interceptor environment (asserted in tests)."
}

output "gateway_url" {
  value       = module.gateway.gateway_url
  description = "Ingress gateway URL for the frontend."
}

output "knowledge" {
  value = {
    source_bucket   = module.knowledge_base.source_bucket
    ingest_role_arn = module.knowledge_base.ingest_role_arn
    data_source_id  = module.knowledge_base.data_source_id
    kb_id           = module.knowledge_base.knowledge_base_id
  }
  description = "What the ingest runbook needs."
}

output "audit" {
  value = {
    trail_arn       = module.cloudtrail.trail_arn
    bucket          = module.cloudtrail.bucket_name
    data_event_arns = { s3 = [module.bundles.bucket_arn, module.knowledge_base.source_bucket_arn], lambda = [module.interceptor.function_arn], dynamodb = [local.tables["agents"], local.tables["mcp-servers"]] }
  }
  description = "What the trail records (asserted in tests)."
}
