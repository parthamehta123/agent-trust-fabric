variable "name" {
  type        = string
  default     = "interceptor"
  description = "Function name suffix."
}

variable "name_prefix" {
  type        = string
  description = "Environment prefix."
}

variable "repository_url" {
  type        = string
  description = "ECR repository URL."
}

variable "image_digest" {
  type        = string
  description = "Image digest (sha256:...). Tags are never deployed."
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "Deploy by digest only."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Key for logs and the function environment."
}

variable "function_policy_json" {
  type        = string
  description = "The function's own permissions (exact actions on exact resources)."
}

variable "environment" {
  type        = map(string)
  description = "Non-secret environment."
}

variable "vpc_id" {
  type        = string
  description = "VPC."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Private subnets."
}

variable "egress_security_group_ids" {
  type        = map(string)
  default     = {}
  description = "Named security groups reachable on 443."
}

variable "egress_prefix_list_ids" {
  type        = map(string)
  default     = {}
  description = "Named prefix lists reachable on 443."
}

variable "egress_cidrs" {
  type        = map(string)
  default     = {}
  description = "Named CIDRs reachable on 443 (the IdP)."
}

variable "timeout_s" {
  type        = number
  default     = 6
  description = "Lambda timeout; the handler's internal deadline (4 s) must stay below it."
  validation {
    condition     = var.timeout_s > 4 && var.timeout_s <= 15
    error_message = "Keep the timeout above the 4 s internal deadline and short (<= 15 s)."
  }
}

variable "memory_mb" {
  type        = number
  default     = 512
  description = "Memory."
}

variable "reserved_concurrency" {
  type        = number
  default     = 50
  description = "Caps blast radius and protects account concurrency."
  validation {
    condition     = var.reserved_concurrency > 0
    error_message = "Reserve a positive concurrency (0 would disable the function)."
  }
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "Audit log retention."
}
