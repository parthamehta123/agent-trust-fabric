variable "environment" {
  type        = string
  default     = "dev"
  description = "Environment name."
}

variable "region" {
  type        = string
  description = "AWS region."
}

variable "allowed_account_ids" {
  type        = list(string)
  description = "The only account(s) this configuration may touch."
  validation {
    condition     = length(var.allowed_account_ids) > 0 && alltrue([for a in var.allowed_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "List the sandbox account id(s) explicitly."
  }
}

variable "azs" {
  type        = list(string)
  description = "Availability zones."
}

variable "vpc_cidr" {
  type        = string
  default     = "10.40.0.0/16"
  description = "VPC CIDR (RFC 1918 only)."
  validation {
    condition     = startswith(var.vpc_cidr, "10.") || startswith(var.vpc_cidr, "172.") || startswith(var.vpc_cidr, "192.168.")
    error_message = "The VPC CIDR must be RFC 1918 private address space."
  }
}

variable "bundle_bucket_name" {
  type        = string
  description = "Globally unique bundle bucket name."
}

variable "monthly_budget_usd" {
  type        = number
  default     = 50
  description = "Sandbox budget."
}

variable "budget_alert_emails" {
  type        = list(string)
  description = "Budget alert recipients."
}

variable "deploy_mock_idp" {
  type        = bool
  default     = false
  description = "Run the mock IdP as an internal service (demo only)."
}

variable "deletion_protection" {
  type        = bool
  default     = true
  description = "Protect stateful resources; disable only for sandbox teardown."
}

# ---------------------------------------------------------------- 6b: services
variable "domain" {
  type        = string
  description = "Domain you own; planes are <plane>.<domain> (private zone)."
}

variable "public_zone_id" {
  type        = string
  description = "Public Route 53 zone for ACM DNS validation."
}

variable "image_digests" {
  type        = map(string)
  description = "Service -> image digest (sha256:...). Tags are never deployed."
}

variable "agent_source_security_group_ids" {
  type        = list(string)
  default     = []
  description = "Agent runtimes allowed onto the data plane (AgentCore Runtime / agent task SGs)."
}

variable "idp_egress_cidrs" {
  type        = map(string)
  default     = {}
  description = "Named CIDRs of the external IdP (Okta) for JWKS and token calls."
}

variable "a2a_target_cidrs" {
  type        = map(string)
  default     = {}
  description = "Named CIDRs of agent runtimes the A2A gateway may forward to."
}

variable "allowed_model_arns" {
  type        = list(string)
  default     = []
  description = "The only Bedrock models the inference gateway may invoke (union of agent allowlists)."
}

variable "enable_verified_access" {
  type        = bool
  default     = true
  description = "Front the admin plane with Verified Access (off = nobody reaches it)."
}

variable "okta_issuer" {
  type        = string
  default     = "https://example.okta.com/oauth2/default"
  description = "IdP issuer for Verified Access."
}

variable "verified_access_client_id" {
  type        = string
  default     = "atf-verified-access"
  description = "OIDC client for Verified Access."
}

variable "verified_access_client_secret" {
  type        = string
  default     = null
  sensitive   = true
  description = "OIDC client secret (TF_VAR_ only)."
}

variable "admin_groups" {
  type        = list(string)
  default     = ["atf-security-approvers", "atf-registry-approvers"]
  description = "IdP groups allowed onto the admin plane."
}

# ---------------------------------------------------------------- 6c: runtime config
variable "idp" {
  description = <<-EOT
    The IdP (Okta) by convention (ADR-0026 §20): issuer {base_url}/oauth2/{id}, JWKS /v1/keys,
    token /v1/token. authorization_servers needs workload, inference, registry, admin, ingress and
    knowledge; tool_authorization_servers are the tool ASes delegated tokens may be minted at.
  EOT
  type = object({
    base_url                   = string
    authorization_servers      = map(object({ id = string, audience = string }))
    tool_authorization_servers = optional(map(object({ id = string, audience = string })), {})
    clients = object({
      tool_gateway = string
      a2a_gateway  = string
      frontend     = string
    })
  })
  validation {
    condition     = can(regex("^https://[a-z0-9.-]+$", var.idp.base_url))
    error_message = "idp.base_url must be https://<host> with no path or trailing slash."
  }
  validation {
    condition     = length(setsubtract(["workload", "inference", "registry", "admin", "ingress", "knowledge"], keys(var.idp.authorization_servers))) == 0
    error_message = "idp.authorization_servers needs workload, inference, registry, admin, ingress and knowledge."
  }
  validation {
    condition = alltrue([
      for a in concat(values(var.idp.authorization_servers), values(var.idp.tool_authorization_servers)) :
      can(regex("^[A-Za-z0-9-]{1,64}$", a.id)) && can(regex("^api://[a-z0-9-]{1,64}$", a.audience))
    ])
    error_message = "Each AS needs a slug id and an api://<slug> audience."
  }
  validation {
    condition = length(distinct([
      for a in concat(values(var.idp.authorization_servers), values(var.idp.tool_authorization_servers)) : a.audience
    ])) == length(var.idp.authorization_servers) + length(var.idp.tool_authorization_servers)
    error_message = "Every AS keeps its own audience (no cross-tool token replay, ADR-0025 §8)."
  }
}

variable "model_routes" {
  type        = map(object({ provider_model = string }))
  description = "Logical model -> provider model (Bedrock via LiteLLM). api_base is local-only and cannot be set here."
  validation {
    condition     = length(var.model_routes) > 0 && alltrue([for r in values(var.model_routes) : startswith(r.provider_model, "bedrock/")])
    error_message = "In AWS every route goes to Bedrock (bedrock/<model id>)."
  }
}

variable "a2a_target_scopes" {
  type        = list(string)
  default     = ["agent.invoke"]
  description = "Scopes the A2A gateway requests at a target agent's AS."
}

variable "a2a_internal_hosts" {
  type        = map(list(string))
  default     = {}
  description = "Agent runtime FQDN -> private CIDRs its addresses must fall in (ADR-0026 §19)."
  validation {
    condition = alltrue([
      for h, cidrs in var.a2a_internal_hosts :
      can(regex("^([a-z0-9-]{1,63}\\.)+[a-z][a-z0-9-]{0,62}$", h)) && length(cidrs) > 0
    ])
    error_message = "Exact lowercase FQDNs, each with at least one CIDR (no wildcards)."
  }
}

# ---------------------------------------------------------------- 6c-iii: edge + knowledge
variable "ingress_agent" {
  description = "The agent behind the ingress gateway: its AgentCore Runtime and its own AS."
  type = object({
    name                 = string
    runtime_arn          = string
    authorization_server = object({ id = string, audience = string })
    scopes               = list(string)
  })
  validation {
    condition     = can(regex("^[a-z0-9-]{1,48}$", var.ingress_agent.name)) && can(regex("^api://[a-z0-9-]{1,64}$", var.ingress_agent.authorization_server.audience)) && length(var.ingress_agent.scopes) > 0
    error_message = "A slug name, an api://<slug> audience and explicit scopes."
  }
}

variable "kb_source_bucket_name" {
  type        = string
  description = "Globally unique corpus bucket name."
}

variable "kb_ingest_principal_arns" {
  type        = list(string)
  description = "IAM roles that may assume kb-ingest (the 6d CI role; optionally an operator role)."
}
