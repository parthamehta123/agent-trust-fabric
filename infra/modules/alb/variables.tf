variable "name" {
  type        = string
  description = "ALB name (also the security group prefix)."
}

variable "vpc_id" {
  type        = string
  description = "VPC id."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Private subnets."
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate for the HTTPS listener."
}

variable "source_security_group_ids" {
  type        = list(string)
  description = "The only security groups allowed to reach this ALB."
}

variable "deletion_protection" {
  type        = bool
  default     = true
  description = "Protect the ALB from deletion."
}
