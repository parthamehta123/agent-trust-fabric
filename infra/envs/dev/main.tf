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
  signers = {
    bundle = [aws_iam_role.bundle_publisher.arn] # only the publisher can sign bundles
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
  publisher_role_arn = aws_iam_role.bundle_publisher.arn
}

module "budget" {
  source            = "../../modules/budget"
  name              = local.name
  monthly_limit_usd = var.monthly_budget_usd
  alert_emails      = var.budget_alert_emails
}

# The bundle publisher's task role exists from 6a because two resource policies (the bundle
# key and bucket) name it. Its permissions are attached in 6b with the ECS service.
resource "aws_iam_role" "bundle_publisher" {
  name = "${local.name}-bundle-publisher"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
