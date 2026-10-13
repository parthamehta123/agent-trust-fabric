variable "name" {
  type        = string
  description = "Name prefix."
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed key for table encryption."
}

variable "deletion_protection" {
  type        = bool
  default     = true
  description = "Protect tables from deletion (disable only to tear down a sandbox)."
}
