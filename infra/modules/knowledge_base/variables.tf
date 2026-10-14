variable "name" {
  type        = string
  description = "Name prefix."
}

variable "source_bucket_name" {
  type        = string
  description = "Globally unique corpus bucket name."
}

variable "kms_key_arn" {
  type        = string
  description = "Data key for the bucket, vectors, KB and data source."
}

variable "embedding_model_id" {
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
  description = "Embedding model (ADR-0026 §18)."
}

variable "dimensions" {
  type        = number
  default     = 1024
  description = "Embedding dimensions; must match the model configuration."
  validation {
    condition     = contains([256, 512, 1024], var.dimensions)
    error_message = "Titan v2 supports 256, 512 or 1024 dimensions."
  }
}

variable "ingest_principal_arns" {
  type        = list(string)
  description = "The only IAM principals that may assume the kb-ingest role."
  validation {
    condition     = length(var.ingest_principal_arns) > 0 && alltrue([for a in var.ingest_principal_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", a))])
    error_message = "List explicit IAM role ARNs (no wildcards, no account roots)."
  }
}
