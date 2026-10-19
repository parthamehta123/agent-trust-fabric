# Phase 6c-iii (ADR-0026 §15-18, §22): the ingress edge (AgentCore Gateway + interceptor Lambda),
# the Bedrock Guardrail the inference gateway pins, and the knowledge base on S3 Vectors.

locals {
  gateway_name       = "${local.name}-ingress"
  gateway_id_param   = "/${local.name}/interceptor/gateway-id"
  gateway_param_arn  = "${local.arn_prefix}:ssm:${local.region}:${local.acct}:parameter${local.gateway_id_param}"
  interceptor_fn_arn = "${local.arn_prefix}:lambda:${local.region}:${local.acct}:function:${local.name}-interceptor"

  # One ingress profile; its gateway_id is bound at cold start from the SSM parameter.
  ingress_profile = {
    version = 1
    profiles = [{
      profile_id = "${var.ingress_agent.name}-ingress"
      gateway_id = "bound-at-cold-start"
      flow       = "ingress"
      enabled    = true
      idp = {
        issuer                  = local.org.issuer
        jwks_uri                = local.org.jwks_uri
        token_endpoint          = local.org.token_endpoint
        resource_issuer         = "${var.idp.base_url}/oauth2/${var.ingress_agent.authorization_server.id}"
        resource_token_endpoint = "${var.idp.base_url}/oauth2/${var.ingress_agent.authorization_server.id}/v1/token"
        resource_jwks_uri       = "${var.idp.base_url}/oauth2/${var.ingress_agent.authorization_server.id}/v1/keys"
      }
      target          = { audience = var.ingress_agent.authorization_server.audience, scopes = var.ingress_agent.scopes }
      ingress_clients = { (var.idp.clients.frontend) = local.sign_keys["interceptor"] }
      max_auth_age_s  = 43200
      ingress_token = {
        issuer    = local.as_urls["ingress"].issuer
        audiences = [local.as_urls["ingress"].audience]
        jwks_uri  = local.as_urls["ingress"].jwks_uri
      }
    }]
  }

  interceptor_env = {
    ATF_ENV                  = var.environment
    ATF_PROFILES_JSON        = jsonencode(local.ingress_profile)
    ATF_GATEWAY_ID_PARAMETER = local.gateway_id_param
    ATF_ACCESS_TOKEN_PROFILE = var.access_token_profile
  }

  # Ingress only: no bundle (egress isn't served by this Lambda), so no S3 and no data-key grants.
  function_policies = {
    "interceptor" = [
      { Effect = "Allow", Action = ["kms:Sign", "kms:GetPublicKey"], Resource = local.sign_keys[local.sign_grants["interceptor"]] },
      { Effect = "Allow", Action = ["ssm:GetParameter"], Resource = local.gateway_param_arn },
    ]
  }
}

# ------------------------------------------------------------------ guardrail
module "guardrail" {
  source      = "../../modules/guardrail"
  name        = "${local.name}-inference"
  kms_key_arn = local.data_key
}

# ------------------------------------------------------------------ knowledge base
module "knowledge_base" {
  source                = "../../modules/knowledge_base"
  name                  = local.name
  source_bucket_name    = var.kb_source_bucket_name
  kms_key_arn           = local.data_key
  ingest_principal_arns = var.kb_ingest_principal_arns
}

# ------------------------------------------------------------------ interceptor + gateway
# Lambda pulls its image with the service principal, only for this one function.
resource "aws_ecr_repository_policy" "interceptor" {
  repository = module.ecr.repository_names["interceptor"]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "LambdaPullForTheInterceptorOnly"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
      Condition = { StringEquals = { "aws:SourceArn" = local.interceptor_fn_arn } }
    }]
  })
}

module "interceptor" {
  source         = "../../modules/lambda_interceptor"
  name_prefix    = local.name
  repository_url = module.ecr.repository_urls["interceptor"]
  image_digest   = var.image_digests["interceptor"]
  kms_key_arn    = local.data_key
  environment    = local.interceptor_env
  function_policy_json = jsonencode({
    Version   = "2012-10-17"
    Statement = local.function_policies["interceptor"]
  })
  vpc_id                    = module.network.vpc_id
  subnet_ids                = module.network.private_subnet_ids
  egress_security_group_ids = { vpc-endpoints = module.network.endpoints_security_group_id }
  egress_cidrs              = var.idp_egress_cidrs
  depends_on                = [aws_ecr_repository_policy.interceptor]
}

module "gateway" {
  source                    = "../../modules/agentcore_gateway"
  name                      = local.gateway_name
  kms_key_arn               = local.data_key
  discovery_url             = "${local.as_urls["ingress"].issuer}/.well-known/openid-configuration"
  allowed_audiences         = [local.as_urls["ingress"].audience]
  allowed_clients           = [var.idp.clients.frontend]
  interceptor_arn           = module.interceptor.function_arn
  target_name               = var.ingress_agent.name
  target_runtime_arn        = var.ingress_agent.runtime_arn
  gateway_id_parameter_name = local.gateway_id_param
}

# The interceptor's only caller is the gateway: no task role may invoke Lambda (direct invocation
# with a forged client context would select a profile and mint a T2).
check "only_gateway_invokes_interceptor" {
  assert {
    condition = !anytrue(flatten([
      for svc, stmts in merge(local.policies, local.function_policies) : [
        for st in stmts : anytrue([for a in flatten([st.Action]) : startswith(a, "lambda:")])
      ]
    ]))
    error_message = "Only the gateway role may invoke the interceptor."
  }
}
