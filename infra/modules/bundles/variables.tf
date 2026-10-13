variable "bucket_name" {
  type        = string
  description = "Bundle bucket name (globally unique)."
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed key for SSE-KMS."
}

variable "publisher_role_arn" {
  type        = string
  description = "The only principal allowed to write bundles (the bundle publisher's task role)."
}

variable "retention_days" {
  type        = number
  default     = 30
  description = "Object-lock governance retention for bundle versions."
}

variable "noncurrent_days" {
  type        = number
  default     = 90
  description = "Keep superseded bundle versions this long for forensics."
}
