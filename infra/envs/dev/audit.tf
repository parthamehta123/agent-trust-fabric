# Phase 6d-ii (ADR-0026 §27): account audit trail with data events only where a write or an
# invocation is security-relevant.
module "cloudtrail" {
  source               = "../../modules/cloudtrail"
  name                 = local.name
  bucket_name          = var.cloudtrail_bucket_name
  s3_write_bucket_arns = [module.bundles.bucket_arn, module.knowledge_base.source_bucket_arn]
  lambda_arns          = [module.interceptor.function_arn]
  dynamodb_table_arns  = [local.tables["agents"], local.tables["mcp-servers"]]
}
