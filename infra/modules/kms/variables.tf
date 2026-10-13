variable "name" {
  type        = string
  description = "Name prefix."
}

variable "client_keys" {
  type        = list(string)
  default     = []
  description = "OAuth clients that sign private_key_jwt assertions with a KMS key (e.g. interceptor, a2a-gateway)."
}

variable "signers" {
  type        = map(list(string))
  default     = {}
  description = "Key name -> role ARNs allowed kms:Sign. Only the bundle publisher may sign with 'bundle'."
}
