output "gateway_id" {
  value       = aws_bedrockagentcore_gateway.this.gateway_id
  description = "Gateway id."
}

output "gateway_url" {
  value       = aws_bedrockagentcore_gateway.this.gateway_url
  description = "Gateway URL for the frontend."
}

output "role_arn" {
  value       = aws_iam_role.this.arn
  description = "Gateway role (the only principal that may invoke the interceptor)."
}

output "gateway_id_parameter_arn" {
  value       = aws_ssm_parameter.gateway_id.arn
  description = "Parameter the interceptor reads."
}
