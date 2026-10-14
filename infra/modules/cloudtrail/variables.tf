variable "name" {
  type        = string
  description = "Trail name."
}

variable "bucket_name" {
  type        = string
  description = "Globally unique log bucket (bootstrap denies the apply role any tampering with it)."
}

variable "retention_days" {
  type        = number
  default     = 365
  description = "Object-lock retention and expiry."
  validation {
    condition     = var.retention_days >= 90
    error_message = "Keep audit logs at least 90 days."
  }
}

variable "s3_write_bucket_arns" {
  type        = list(string)
  description = "Buckets whose object writes are recorded (bundles, corpus)."
}

variable "lambda_arns" {
  type        = list(string)
  description = "Functions whose invocations are recorded (the interceptor, TM-INT-03)."
}

variable "dynamodb_table_arns" {
  type        = list(string)
  description = "Tables whose writes are recorded (agents, mcp-servers)."
}
