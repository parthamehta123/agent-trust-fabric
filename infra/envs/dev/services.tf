# Phase 6b (ADR-0026 §4): every service gets one least-privilege task role, one security group
# that admits only its plane's ALB, and egress to named destinations only. The plane layout
# mirrors the compose networks:
#   data  ALB  <- agents only          : mcp, inference, a2a
#   admin ALB  <- Verified Access only : mcp-admin, registry           (closes RR-7)
#   tools ALB  <- MCP gateway + admin  : knowledge

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  services = ["mcp-gateway", "mcp-admin", "inference-gateway", "a2a-gateway", "agent-registry", "bundle-publisher", "knowledge-server"]

  arn_prefix = "arn:${data.aws_partition.current.partition}"
  acct       = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  bundle_obj = "${module.bundles.bucket_arn}/bundle.jws"
  secret_ns  = "${local.arn_prefix}:secretsmanager:${local.region}:${local.acct}:secret:${local.name}/mcp/*"
  tables     = module.tables.table_arns
  data_key   = module.kms.data_key_arn
  sign_keys  = module.kms.signing_key_arns

  # Single sources of truth: the IAM policies, the KMS key policies and the ALB rules are all
  # generated from these, so they cannot drift apart (asserted in tests).
  sign_grants   = { "bundle-publisher" = "bundle", "mcp-gateway" = "tool-gateway", "a2a-gateway" = "a2a-gateway" }
  tools_clients = ["mcp-gateway", "mcp-admin"]

  read_bundle = [
    { Effect = "Allow", Action = ["s3:GetObject"], Resource = local.bundle_obj },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = local.data_key },
  ]

  # One statement list per service: exact actions on exact ARNs, no wildcards (asserted in tests).
  policies = {
    "mcp-gateway" = concat(local.read_bundle, [
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:Scan"], Resource = local.tables["mcp-servers"] },
      { Effect = "Allow", Action = ["kms:Sign", "kms:GetPublicKey"], Resource = local.sign_keys[local.sign_grants["mcp-gateway"]] },
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = local.secret_ns },
    ])
    "mcp-admin" = [
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan"], Resource = local.tables["mcp-servers"] },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = local.data_key },
    ]
    "inference-gateway" = concat(local.read_bundle, [
      { Effect = "Allow", Action = ["dynamodb:UpdateItem"], Resource = local.tables["budgets"] },
      { Effect = "Allow", Action = ["kms:GenerateDataKey"], Resource = local.data_key },
      ], length(var.allowed_model_arns) == 0 ? [] : [
      { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = var.allowed_model_arns },
    ])
    "a2a-gateway" = concat(local.read_bundle, [
      { Effect = "Allow", Action = ["kms:Sign", "kms:GetPublicKey"], Resource = local.sign_keys[local.sign_grants["a2a-gateway"]] },
    ])
    "agent-registry" = [
      # No DeleteItem: the registry never deletes history (ADR-0021 §3).
      # Transactions are authorized per underlying write (PutItem); there is no separate action.
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan"], Resource = local.tables["agents"] },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = local.data_key },
    ]
    "bundle-publisher" = [
      { Effect = "Allow", Action = ["dynamodb:Query", "dynamodb:Scan", "dynamodb:GetItem", "dynamodb:UpdateItem"], Resource = local.tables["agents"] },
      { Effect = "Allow", Action = ["kms:Sign", "kms:GetPublicKey"], Resource = local.sign_keys[local.sign_grants["bundle-publisher"]] },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = local.bundle_obj },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = local.data_key },
    ]
    "knowledge-server" = local.read_bundle
  }

  plane = {
    "mcp-gateway"       = { alb = "data", host = "mcp", priority = 10 }
    "inference-gateway" = { alb = "data", host = "inference", priority = 20 }
    "a2a-gateway"       = { alb = "data", host = "a2a", priority = 30 }
    "mcp-admin"         = { alb = "admin", host = "mcp-admin", priority = 10 }
    "agent-registry"    = { alb = "admin", host = "registry", priority = 20 }
    "knowledge-server"  = { alb = "tools", host = "knowledge", priority = 10 }
  }

  pl       = module.network.gateway_prefix_list_ids
  base_egr = { vpc-endpoints = module.network.endpoints_security_group_id }

  egress_sg = {
    "mcp-gateway"       = merge(local.base_egr, { tools-alb = module.alb_tools.security_group_id })
    "mcp-admin"         = merge(local.base_egr, { tools-alb = module.alb_tools.security_group_id })
    "inference-gateway" = local.base_egr
    "a2a-gateway"       = local.base_egr
    "agent-registry"    = local.base_egr
    "bundle-publisher"  = local.base_egr
    "knowledge-server"  = local.base_egr
  }
  egress_pl = {
    "mcp-gateway"       = { s3 = local.pl["s3"], dynamodb = local.pl["dynamodb"] }
    "mcp-admin"         = { dynamodb = local.pl["dynamodb"] }
    "inference-gateway" = { s3 = local.pl["s3"], dynamodb = local.pl["dynamodb"] }
    "a2a-gateway"       = { s3 = local.pl["s3"] }
    "agent-registry"    = { dynamodb = local.pl["dynamodb"] }
    "bundle-publisher"  = { s3 = local.pl["s3"], dynamodb = local.pl["dynamodb"] }
    "knowledge-server"  = { s3 = local.pl["s3"] }
  }
  egress_cidr = {
    "mcp-gateway"       = var.idp_egress_cidrs
    "mcp-admin"         = var.idp_egress_cidrs
    "inference-gateway" = var.idp_egress_cidrs
    "a2a-gateway"       = merge(var.idp_egress_cidrs, var.a2a_target_cidrs)
    "agent-registry"    = var.idp_egress_cidrs
    "bundle-publisher"  = {}
    "knowledge-server"  = var.idp_egress_cidrs
  }

  # Specific outputs only (whole module objects would create a dependency cycle through the
  # tools ALB's allowed_sources).
  alb_sg       = { data = module.alb_data.security_group_id, admin = module.alb_admin.security_group_id, tools = module.alb_tools.security_group_id }
  alb_listener = { data = module.alb_data.listener_arn, admin = module.alb_admin.listener_arn, tools = module.alb_tools.listener_arn }
  alb_dns      = { data = module.alb_data.dns_name, admin = module.alb_admin.dns_name, tools = module.alb_tools.dns_name }
  alb_zone     = { data = module.alb_data.zone_id, admin = module.alb_admin.zone_id, tools = module.alb_tools.zone_id }
}

module "ecr" {
  source      = "../../modules/ecr"
  name        = local.name
  services    = local.services
  kms_key_arn = local.data_key
}

module "cluster" {
  source = "../../modules/ecs_cluster"
  name   = local.name
}

module "certs" {
  source         = "../../modules/certs"
  domain         = var.domain
  public_zone_id = var.public_zone_id
  vpc_id         = module.network.vpc_id
}

module "alb_data" {
  source                    = "../../modules/alb"
  name                      = "${local.name}-data"
  vpc_id                    = module.network.vpc_id
  subnet_ids                = module.network.private_subnet_ids
  certificate_arn           = module.certs.certificate_arn
  source_security_group_ids = var.agent_source_security_group_ids
  deletion_protection       = var.deletion_protection
}

module "alb_admin" {
  source                    = "../../modules/alb"
  name                      = "${local.name}-admin"
  vpc_id                    = module.network.vpc_id
  subnet_ids                = module.network.private_subnet_ids
  certificate_arn           = module.certs.certificate_arn
  source_security_group_ids = var.enable_verified_access ? [module.verified_access[0].security_group_id] : []
  deletion_protection       = var.deletion_protection
}

module "alb_tools" {
  source                    = "../../modules/alb"
  name                      = "${local.name}-tools"
  vpc_id                    = module.network.vpc_id
  subnet_ids                = module.network.private_subnet_ids
  certificate_arn           = module.certs.certificate_arn
  source_security_group_ids = [for svc in local.tools_clients : module.svc[svc].security_group_id]
  deletion_protection       = var.deletion_protection
}

module "verified_access" {
  count                       = var.enable_verified_access ? 1 : 0
  source                      = "../../modules/verified_access"
  name                        = local.name
  vpc_id                      = module.network.vpc_id
  subnet_ids                  = module.network.private_subnet_ids
  domain                      = var.domain
  certificate_arn             = module.certs.certificate_arn
  admin_alb_arn               = module.alb_admin.arn
  admin_alb_security_group_id = module.alb_admin.security_group_id
  oidc_issuer                 = var.okta_issuer
  oidc_client_id              = var.verified_access_client_id
  oidc_client_secret          = var.verified_access_client_secret
  admin_groups                = var.admin_groups
}

module "svc" {
  source   = "../../modules/ecs_service"
  for_each = toset(local.services)

  name           = each.key
  name_prefix    = local.name
  cluster_arn    = module.cluster.cluster_arn
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.private_subnet_ids
  repository_url = module.ecr.repository_urls[each.key]
  repository_arn = module.ecr.repository_arns[each.key]
  image_digest   = var.image_digests[each.key]
  kms_key_arn    = local.data_key
  task_policy_json = jsonencode({
    Version   = "2012-10-17"
    Statement = local.policies[each.key]
  })

  listen                = contains(keys(local.plane), each.key)
  alb_security_group_id = try(local.alb_sg[local.plane[each.key].alb], null)
  listener_arn          = try(local.alb_listener[local.plane[each.key].alb], null)
  host_name             = try("${local.plane[each.key].host}.${var.domain}", null)
  rule_priority         = try(local.plane[each.key].priority, null)

  entry_point = each.key == "bundle-publisher" ? ["python", "-m", "atf_agent_registry.publish"] : null
  environment = local.rendered_env[each.key] # config.tf

  egress_security_group_ids = local.egress_sg[each.key]
  egress_prefix_list_ids    = local.egress_pl[each.key]
  egress_cidrs              = local.egress_cidr[each.key]
}

resource "aws_route53_record" "plane" {
  # checkov:skip=CKV2_AWS_23:Every record is an alias to an internal ALB passed via module output (graph not resolved by checkov).
  for_each = local.plane
  zone_id  = module.certs.private_zone_id
  name     = "${each.value.host}.${var.domain}"
  type     = "A"
  alias {
    name                   = local.alb_dns[each.value.alb]
    zone_id                = local.alb_zone[each.value.alb]
    evaluate_target_health = true
  }
}
