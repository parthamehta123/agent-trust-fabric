output "guardrail_id" {
  value       = aws_bedrock_guardrail.this.guardrail_id
  description = "Guardrail id (ATF_GUARDRAIL_ID)."
}

output "guardrail_arn" {
  value       = aws_bedrock_guardrail.this.guardrail_arn
  description = "Guardrail ARN (scopes bedrock:ApplyGuardrail)."
}

output "version" {
  value       = aws_bedrock_guardrail_version.this.version
  description = "Published version the inference gateway pins (ATF_GUARDRAIL_VERSION)."
}
