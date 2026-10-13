output "security_group_id" {
  value       = aws_security_group.this.id
  description = "ALB security group."
}

output "listener_arn" {
  value       = aws_lb_listener.https.arn
  description = "HTTPS listener."
}

output "dns_name" {
  value       = aws_lb.this.dns_name
  description = "Internal DNS name."
}

output "zone_id" {
  value       = aws_lb.this.zone_id
  description = "Hosted zone of the ALB (for aliases)."
}

output "arn" {
  value       = aws_lb.this.arn
  description = "ALB ARN."
}

output "allowed_sources" {
  value       = sort([for r in aws_vpc_security_group_ingress_rule.from_sources : r.referenced_security_group_id])
  description = "Security groups actually admitted (from the ingress rules themselves)."
}
