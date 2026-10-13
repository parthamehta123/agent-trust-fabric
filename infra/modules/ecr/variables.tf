variable "name" {
  type        = string
  description = "Name prefix."
}

variable "services" {
  type        = list(string)
  description = "Service names, one repository each."
}

variable "kms_key_arn" {
  type        = string
  description = "CMK for image encryption."
}

variable "keep_images" {
  type        = number
  default     = 20
  description = "Images kept per repository."
}
