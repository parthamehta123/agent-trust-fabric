output "table_arns" {
  value       = { for k, t in aws_dynamodb_table.this : k => t.arn }
  description = "Table ARNs by logical name (agents, mcp-servers, budgets)."
}

output "table_names" {
  value       = { for k, t in aws_dynamodb_table.this : k => t.name }
  description = "Table names by logical name."
}
