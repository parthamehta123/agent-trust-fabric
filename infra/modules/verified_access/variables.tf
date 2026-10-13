variable "name" {
  type        = string
  description = "Name prefix."
}

variable "vpc_id" {
  type        = string
  description = "VPC."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnets of the admin ALB."
}

variable "domain" {
  type        = string
  description = "Domain for the admin application."
}

variable "certificate_arn" {
  type        = string
  description = "Certificate for admin.<domain>."
}

variable "admin_alb_arn" {
  type        = string
  description = "Admin ALB."
}

variable "admin_alb_security_group_id" {
  type        = string
  description = "Admin ALB security group."
}

variable "oidc_issuer" {
  type        = string
  description = "IdP issuer (e.g. Okta org)."
  validation {
    condition     = startswith(var.oidc_issuer, "https://")
    error_message = "The issuer must be https."
  }
}

variable "oidc_client_id" {
  type        = string
  description = "OIDC client for Verified Access."
}

variable "oidc_client_secret" {
  type        = string
  sensitive   = true
  description = "OIDC client secret (supply via TF_VAR_, never a tfvars file)."
}

variable "admin_groups" {
  type        = list(string)
  description = "IdP groups allowed onto the admin plane."
  validation {
    condition     = length(var.admin_groups) > 0
    error_message = "List at least one admin group."
  }
}
