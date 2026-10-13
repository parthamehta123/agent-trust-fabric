variable "domain" {
  type        = string
  description = "Domain you own (e.g. atf.example.com); internal names are <plane>.<domain>."
}

variable "public_zone_id" {
  type        = string
  description = "Public Route 53 zone for ACM DNS validation."
}

variable "vpc_id" {
  type        = string
  description = "VPC associated with the private zone."
}
