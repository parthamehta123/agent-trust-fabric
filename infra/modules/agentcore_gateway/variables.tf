variable "name" {
  type        = string
  description = "Gateway name."
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed key."
}

variable "discovery_url" {
  type        = string
  description = "OIDC discovery URL of the ingress authorization server."
  validation {
    condition     = can(regex("^https://[^/]+/.+/\\.well-known/(openid-configuration|oauth-authorization-server)$", var.discovery_url))
    error_message = "An https OIDC/OAuth discovery URL."
  }
}

variable "allowed_audiences" {
  type        = list(string)
  description = "Accepted audiences (the ingress audience)."
  validation {
    condition     = length(var.allowed_audiences) > 0
    error_message = "Pin at least one audience; an empty list would accept any."
  }
}

variable "allowed_clients" {
  type        = list(string)
  description = "Accepted client ids (the frontend client)."
  validation {
    condition     = length(var.allowed_clients) > 0
    error_message = "Pin at least one client; an empty list would accept any."
  }
}

variable "interceptor_arn" {
  type        = string
  description = "Interceptor Lambda ARN."
}

variable "target_name" {
  type        = string
  description = "Target name (the agent)."
}

variable "target_runtime_arn" {
  type        = string
  description = "AgentCore Runtime ARN of the agent behind this gateway."
  validation {
    condition     = can(regex("^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:[0-9]{12}:runtime/[A-Za-z0-9_-]+$", var.target_runtime_arn))
    error_message = "An AgentCore Runtime ARN."
  }
}

variable "allowed_request_headers" {
  type        = list(string)
  default     = ["x-atf-request-id", "x-atf-decision", "x-atf-scan-verdict"]
  description = "Headers the gateway forwards to the target (ADR-0012 §4)."
  # Mirrors trustkit.policy.check_target_allowlist (a Python test keeps the lists identical).
  validation {
    condition     = length(setintersection(toset([for h in var.allowed_request_headers : lower(h)]), toset(["authorization", "proxy-authorization", "x-subject-token", "cookie", "x-api-key"]))) == 0
    error_message = "Credential-bearing headers must never be forwarded to a target."
  }
  validation {
    condition     = length(setsubtract(toset(["x-atf-request-id", "x-atf-decision", "x-atf-scan-verdict"]), toset([for h in var.allowed_request_headers : lower(h)]))) == 0
    error_message = "Every reserved x-atf-* header must be allowlisted so the interceptor's overwrites reach the target."
  }
  validation {
    condition     = length(distinct([for h in var.allowed_request_headers : lower(h)])) == length(var.allowed_request_headers)
    error_message = "Duplicate header names (case-insensitive)."
  }
}

variable "gateway_id_parameter_name" {
  type        = string
  description = "SSM parameter the interceptor reads its gateway id from."
  validation {
    condition     = can(regex("^/[A-Za-z0-9_./-]+$", var.gateway_id_parameter_name))
    error_message = "A fully qualified SSM parameter name."
  }
}
