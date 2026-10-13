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
