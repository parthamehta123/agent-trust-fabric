output "certificate_arn" {
  value       = aws_acm_certificate_validation.this.certificate_arn
  description = "Validated wildcard certificate."
}

output "private_zone_id" {
  value       = aws_route53_zone.private.zone_id
  description = "Private zone for internal names."
}
