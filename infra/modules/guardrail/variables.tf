variable "name" {
  type        = string
  description = "Guardrail name."
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed key for the guardrail."
}
