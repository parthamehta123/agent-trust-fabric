# Phase 6c-ii (ADR-0026 §12-14, §19-20): every service's runtime environment, rendered here and
# nowhere else. Non-secret only. File-shaped documents are inline (*_JSON / *_CEDAR), so every
# change is a new task-definition revision. Clients authenticate with private_key_jwt signed by
# their own KMS key; no client secret exists anywhere in this file.

# The bundle verification key is pinned at deploy; verifiers get no KMS permission on it.
# Read through the alias this configuration manages: provider 6.66.0 rejects every key id and key
# ARN for this data source (aliases validate). Repointing the alias, or any change to the pinned PEM,
# appears in the plan as drift on the alias and on every verifier's task definition.
data "aws_kms_public_key" "bundle" {
  key_id = module.kms.signing_key_aliases["bundle"]
}

locals {
  # ------------------------------------------------------------------ IdP (Okta conventions)
  as_urls = {
    for k, a in var.idp.authorization_servers : k => {
      issuer         = "${var.idp.base_url}/oauth2/${a.id}"
      jwks_uri       = "${var.idp.base_url}/oauth2/${a.id}/v1/keys"
      token_endpoint = "${var.idp.base_url}/oauth2/${a.id}/v1/token"
      audience       = a.audience
    }
  }
  org = {
    issuer         = var.idp.base_url
    jwks_uri       = "${var.idp.base_url}/oauth2/v1/keys"
    token_endpoint = "${var.idp.base_url}/oauth2/v1/token"
  }

  # Delegated-token audience -> its AS (ADR-0025 §8): the knowledge AS plus every tool AS.
  tool_authorities = {
    for k, a in merge(var.idp.tool_authorization_servers, { knowledge = var.idp.authorization_servers["knowledge"] }) :
    a.audience => {
      issuer         = "${var.idp.base_url}/oauth2/${a.id}"
      token_endpoint = "${var.idp.base_url}/oauth2/${a.id}/v1/token"
      jwks_uri       = "${var.idp.base_url}/oauth2/${a.id}/v1/keys"
    }
  }

  workload_inbound = {
    issuer    = local.as_urls["workload"].issuer
    audiences = [local.as_urls["workload"].audience]
    jwks_uri  = local.as_urls["workload"].jwks_uri
  }

  # Egress profile bases. `idp.resource_*` and `target` are replaced per server record (MCP) or per
  # target agent (A2A); the values here only satisfy the schema.
  egress_idp = {
    issuer                  = local.org.issuer
    jwks_uri                = local.org.jwks_uri
    token_endpoint          = local.org.token_endpoint
    resource_issuer         = local.as_urls["knowledge"].issuer
    resource_token_endpoint = local.as_urls["knowledge"].token_endpoint
    resource_jwks_uri       = local.as_urls["knowledge"].jwks_uri
  }
  mcp_egress = {
    profile_id     = "mcp-gateway"
    gateway_id     = "mcp-gateway"
    flow           = "egress"
    enabled        = true
    idp            = local.egress_idp
    target         = { audience = local.as_urls["knowledge"].audience, scopes = ["kb.public.read"] }
    client         = { client_id = var.idp.clients.tool_gateway, signing_key = local.sign_keys[local.sign_grants["mcp-gateway"]] }
    egress_inbound = local.workload_inbound
  }
  a2a_egress = {
    profile_id     = "a2a-gateway"
    gateway_id     = "a2a-gateway"
    flow           = "egress"
    enabled        = true
    idp            = local.egress_idp
    client         = { client_id = var.idp.clients.a2a_gateway, signing_key = local.sign_keys[local.sign_grants["a2a-gateway"]] }
    egress_inbound = local.workload_inbound
  }
  inference_profile = {
    inbound = {
      issuer    = local.as_urls["inference"].issuer
      audiences = [local.as_urls["inference"].audience]
      jwks_uri  = local.as_urls["inference"].jwks_uri
    }
    scanner_failure_mode = "closed"
  }

  # ------------------------------------------------------------------ named internal egress
  # ADR-0026 §19: the tools plane by exact name, confined to the private subnets. Admin-plane
  # names are never listed (asserted in tests).
  private_cidrs  = module.network.private_subnet_cidrs
  tools_internal = { for svc, p in local.plane : "${p.host}.${var.domain}" => local.private_cidrs if p.alb == "tools" }

  # ------------------------------------------------------------------ per-service environment
  bundle_reader = {
    ATF_BUNDLE_ISSUER         = local.bundle_issuer
    ATF_BUNDLE_PUBLIC_KEY_PEM = data.aws_kms_public_key.bundle.public_key_pem
    ATF_BUNDLE_S3_BUCKET      = module.bundles.bucket_name
    ATF_BUNDLE_S3_KEY         = "bundle.jws"
  }
  bundle_issuer = "${local.name}-bundle-publisher"
  table_names   = module.tables.table_names

  service_env = {
    "mcp-gateway" = merge(local.bundle_reader, {
      ATF_DDB_TABLE             = local.table_names["mcp-servers"]
      ATF_EGRESS_PROFILE_JSON   = jsonencode(local.mcp_egress)
      ATF_TOOL_AUTHORITIES_JSON = jsonencode(local.tool_authorities)
      ATF_SSRF_INTERNAL_HOSTS   = jsonencode(local.tools_internal)
    })
    "mcp-admin" = {
      ATF_ADMIN_ISSUER          = local.as_urls["admin"].issuer
      ATF_ADMIN_AUDIENCE        = local.as_urls["admin"].audience
      ATF_ADMIN_JWKS_URI        = local.as_urls["admin"].jwks_uri
      ATF_DDB_TABLE             = local.table_names["mcp-servers"]
      ATF_TOOL_AUTHORITIES_JSON = jsonencode(local.tool_authorities)
      ATF_SSRF_INTERNAL_HOSTS   = jsonencode(local.tools_internal)
    }
    "inference-gateway" = merge(local.bundle_reader, {
      ATF_BUDGET_TABLE           = local.table_names["budgets"]
      ATF_INFERENCE_PROFILE_JSON = jsonencode(local.inference_profile)
      ATF_MODEL_ROUTES_JSON      = jsonencode(var.model_routes)
      ATF_GUARDRAIL_ID           = module.guardrail.guardrail_id
      ATF_GUARDRAIL_VERSION      = module.guardrail.version
    })
    "a2a-gateway" = merge(local.bundle_reader, {
      ATF_A2A_EGRESS_PROFILE_JSON = jsonencode(local.a2a_egress)
      ATF_A2A_PUBLIC_URL          = "https://${local.plane["a2a-gateway"].host}.${var.domain}"
      ATF_A2A_TARGET_SCOPES       = join(" ", var.a2a_target_scopes)
      ATF_SSRF_INTERNAL_HOSTS     = jsonencode(var.a2a_internal_hosts)
    })
    "agent-registry" = {
      ATF_REGISTRY_ISSUER   = local.as_urls["registry"].issuer
      ATF_REGISTRY_AUDIENCE = local.as_urls["registry"].audience
      ATF_REGISTRY_JWKS_URI = local.as_urls["registry"].jwks_uri
      ATF_REGISTRY_TABLE    = local.table_names["agents"]
    }
    "bundle-publisher" = {
      ATF_REGISTRY_TABLE     = local.table_names["agents"]
      ATF_BUNDLE_ISSUER      = local.bundle_issuer
      ATF_BUNDLE_SIGNING_KEY = local.sign_keys[local.sign_grants["bundle-publisher"]]
      ATF_BUNDLE_S3_BUCKET   = module.bundles.bucket_name
      ATF_BUNDLE_S3_KEY      = "bundle.jws"
      ATF_GUARDRAILS_CEDAR   = file("${path.module}/../../../policies/guardrails.cedar")
    }
    "knowledge-server" = merge(local.bundle_reader, {
      ATF_KB_ISSUER     = local.as_urls["knowledge"].issuer
      ATF_KB_AUDIENCE   = local.as_urls["knowledge"].audience
      ATF_KB_JWKS_URI   = local.as_urls["knowledge"].jwks_uri
      ATF_KB_BEDROCK_ID = module.knowledge_base.knowledge_base_id
    })
  }

  # ADR-0028: DPoP at the data plane. ATF_PUBLIC_URL is what agents call (the proof's htu).
  dpop_env = {
    for svc in local.dpop_gateways : svc => {
      ATF_DPOP_MODE                 = var.dpop_mode
      ATF_PUBLIC_URL                = "https://${local.plane[svc].host}.${var.domain}"
      ATF_DPOP_NONCE_KEY_SECRET_ARN = aws_secretsmanager_secret.dpop_nonce.arn
    }
  }

  common_env = {
    ATF_ENV    = var.environment
    AWS_REGION = local.region
  }
  rendered_env = {
    for svc in local.services : svc => merge(local.common_env, local.service_env[svc], lookup(local.dpop_env, svc, {}))
  }
}

# Admin-plane hosts must never become reachable egress targets (ADR-0026 §19, RR-7).
check "no_admin_hosts_in_egress" {
  assert {
    condition = length(setintersection(
      toset(concat(keys(local.tools_internal), keys(var.a2a_internal_hosts))),
      toset([for svc, p in local.plane : "${p.host}.${var.domain}" if p.alb == "admin"]),
    )) == 0
    error_message = "An admin-plane host is listed as an internal egress target."
  }
}
