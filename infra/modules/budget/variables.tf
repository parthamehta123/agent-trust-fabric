variable "name" {
  type        = string
  description = "Name prefix."
}

variable "monthly_limit_usd" {
  type        = number
  description = "Monthly budget in USD."
  validation {
    condition     = var.monthly_limit_usd > 0
    error_message = "The budget must be positive."
  }
}

variable "alert_emails" {
  type        = list(string)
  description = "Who is notified at 50/80% actual and 100% forecast."
  validation {
    condition     = length(var.alert_emails) > 0
    error_message = "At least one alert email is required."
  }
}
