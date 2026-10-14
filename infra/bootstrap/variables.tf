variable "region" {
  type        = string
  description = "Home region."
}

variable "allowed_account_ids" {
  type        = list(string)
  description = "The only account(s) this stack may touch."
  validation {
    condition     = length(var.allowed_account_ids) > 0 && alltrue([for a in var.allowed_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "List the sandbox account id(s) explicitly."
  }
}

variable "name" {
  type        = string
  default     = "atf"
  description = "Name prefix."
}

variable "github_repository" {
  type        = string
  description = "owner/repo whose workflows may assume the CI roles."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "owner/repo, exactly (no wildcards)."
  }
}

variable "state_bucket_name" {
  type        = string
  description = "Globally unique remote-state bucket."
}

variable "cloudtrail_bucket_name" {
  type        = string
  description = "CloudTrail log bucket (created in envs/dev); the apply role may never tamper with it."
}

variable "allowed_regions" {
  type        = list(string)
  description = "Regions the apply role may act in (global services excepted)."
  validation {
    condition     = length(var.allowed_regions) > 0
    error_message = "List at least one region."
  }
}

variable "apply_environment" {
  type        = string
  default     = "sandbox"
  description = "GitHub environment (with required reviewers) that may assume the apply role."
}

variable "ingest_environment" {
  type        = string
  default     = "sandbox-ingest"
  description = "GitHub environment that may assume the ingest-CI role (distinct sub from apply)."
}

variable "kb_ingest_role_name" {
  type        = string
  default     = "atf-dev-kb-ingest"
  description = "The kb-ingest role (envs/dev) the ingest-CI role may assume."
}
