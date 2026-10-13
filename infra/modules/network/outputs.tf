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
