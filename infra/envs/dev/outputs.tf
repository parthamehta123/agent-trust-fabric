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
