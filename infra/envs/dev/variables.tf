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
