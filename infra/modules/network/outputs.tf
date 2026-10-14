output "vpc_id" {
  value       = aws_vpc.this.id
  description = "VPC id."
}

output "private_subnet_ids" {
  value       = [for s in aws_subnet.private : s.id]
  description = "Private subnet ids."
}

output "endpoints_security_group_id" {
  value       = aws_security_group.endpoints.id
  description = "Security group attached to interface endpoints."
}

output "gateway_prefix_list_ids" {
  value       = { for k, e in aws_vpc_endpoint.gateway : k => e.prefix_list_id }
  description = "Prefix lists of the S3 and DynamoDB gateway endpoints (for SG egress)."
}

output "private_subnet_cidrs" {
  value       = [for s in aws_subnet.private : s.cidr_block]
  description = "Private subnet CIDRs (named internal egress targets live here, ADR-0026 §19)."
}
