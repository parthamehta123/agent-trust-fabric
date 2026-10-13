output "security_group_id" {
  value       = aws_security_group.endpoint.id
  description = "Verified Access endpoint SG (the only source allowed into the admin ALB)."
}

output "endpoint_domain" {
  value       = aws_verifiedaccess_endpoint.admin.endpoint_domain
  description = "Verified Access endpoint domain."
}
