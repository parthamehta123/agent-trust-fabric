variable "name" {
  type        = string
  description = "Service name."
}

variable "name_prefix" {
  type        = string
  description = "Environment prefix."
}

variable "cluster_arn" {
  type        = string
  description = "ECS cluster."
}

variable "vpc_id" {
  type        = string
  description = "VPC."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Private subnets."
}

variable "repository_url" {
  type        = string
  description = "ECR repository URL."
}

variable "repository_arn" {
  type        = string
  description = "ECR repository ARN (the only image this service may pull)."
}

variable "image_digest" {
  type        = string
  description = "Image digest (sha256:...); tags are never deployed."
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "Deploy by digest only."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "CMK for logs and image decryption."
}

variable "task_policy_json" {
  type        = string
  default     = null
  description = "The service's least-privilege task policy."
}

variable "environment" {
  type        = map(string)
  default     = {}
  description = "Non-secret environment variables."
}

variable "entry_point" {
  type        = list(string)
  default     = null
  description = "Entrypoint override (e.g. the bundle publisher)."
}

variable "command" {
  type        = list(string)
  default     = null
  description = "Command override."
}

variable "listen" {
  type        = bool
  default     = true
  description = "Serve HTTPS on 8443 behind a load balancer (false for workers)."
}

variable "alb_security_group_id" {
  type        = string
  default     = null
  description = "The load balancer allowed to reach the tasks."
}

variable "listener_arn" {
  type        = string
  default     = null
  description = "Listener for the host rule."
}

variable "host_name" {
  type        = string
  default     = null
  description = "Host header routed to this service."
}

variable "rule_priority" {
  type        = number
  default     = null
  description = "Listener rule priority."
}

variable "egress_security_group_ids" {
  type        = map(string)
  default     = {}
  description = "Named security groups this service may reach on 443."
}

variable "egress_prefix_list_ids" {
  type        = map(string)
  default     = {}
  description = "Named prefix lists (gateway endpoints) this service may reach on 443."
}

variable "egress_cidrs" {
  type        = map(string)
  default     = {}
  description = "Named CIDRs reachable on 443 (e.g. the external IdP)."
}

variable "cpu" {
  type        = number
  default     = 512
  description = "Task CPU units."
}

variable "memory" {
  type        = number
  default     = 1024
  description = "Task memory (MiB)."
}

variable "desired_count" {
  type        = number
  default     = 2
  description = "Tasks (spread across AZs)."
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "Log retention."
}
