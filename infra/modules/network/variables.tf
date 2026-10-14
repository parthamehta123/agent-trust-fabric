variable "name" {
  type        = string
  description = "Name prefix for every resource."
}

variable "cidr" {
  type        = string
  description = "VPC CIDR (private address space only)."
  validation {
    condition     = can(cidrhost(var.cidr, 0)) && (startswith(var.cidr, "10.") || startswith(var.cidr, "172.") || startswith(var.cidr, "192.168."))
    error_message = "The VPC CIDR must be RFC 1918 private address space."
  }
}

variable "azs" {
  type        = list(string)
  description = "Availability zones for private subnets (at least two)."
  validation {
    condition     = length(var.azs) >= 2
    error_message = "Use at least two availability zones."
  }
}

variable "interface_endpoints" {
  type        = list(string)
  description = "Interface endpoint services (AWS APIs reachable without internet)."
  default = [
    "sts", "kms", "logs", "ecr.api", "ecr.dkr", "secretsmanager",
    "bedrock-runtime", "bedrock-agent-runtime", "ssm",
  ]
}

variable "logs_kms_key_arn" {
  type        = string
  description = "CMK for the flow-log group."
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "Flow-log retention."
}
