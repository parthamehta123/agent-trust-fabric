locals {
  name = "atf-${var.environment}"
}

# ADR-0026 §5: the mock IdP is test infrastructure and must never exist outside dev.
check "mock_idp_dev_only" {
  assert {
    condition     = !var.deploy_mock_idp || var.environment == "dev"
    error_message = "The mock IdP may only be deployed in the dev environment."
  }
}

module "kms" {
  source      = "../../modules/kms"
  name        = local.name
  client_keys = ["interceptor", "a2a-gateway", "tool-gateway"]
  # Keys come from the same map as the IAM policies (services.tf: sign_grants). Role references
  # are static (a dynamic module index would create a dependency cycle); check "sign_grants_wired"
  # fails if a grant is added without wiring it here.
  signers = {
    (local.sign_grants["bundle-publisher"]) = [module.svc["bundle-publisher"].task_role_arn]
    (local.sign_grants["mcp-gateway"])      = [module.svc["mcp-gateway"].task_role_arn]
    (local.sign_grants["a2a-gateway"])      = [module.svc["a2a-gateway"].task_role_arn]
    (local.sign_grants["interceptor"])      = [module.interceptor.role_arn]
  }
}

module "network" {
  source           = "../../modules/network"
  name             = local.name
  cidr             = var.vpc_cidr
  azs              = var.azs
  logs_kms_key_arn = module.kms.data_key_arn
}

module "tables" {
  source              = "../../modules/dynamodb"
  name                = local.name
  kms_key_arn         = module.kms.data_key_arn
  deletion_protection = var.deletion_protection
}

module "bundles" {
  source             = "../../modules/bundles"
  bucket_name        = var.bundle_bucket_name
  kms_key_arn        = module.kms.data_key_arn
  publisher_role_arn = module.svc["bundle-publisher"].task_role_arn
}

module "budget" {
  source            = "../../modules/budget"
  name              = local.name
  monthly_limit_usd = var.monthly_budget_usd
  alert_emails      = var.budget_alert_emails
}

check "sign_grants_wired" {
  assert {
    condition     = toset(keys(local.sign_grants)) == toset(["bundle-publisher", "mcp-gateway", "a2a-gateway", "interceptor"])
    error_message = "A signing grant was added or removed: wire its role in module.kms.signers too."
  }
}
