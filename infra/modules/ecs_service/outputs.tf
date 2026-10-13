output "security_group_id" {
  value       = aws_security_group.task.id
  description = "Task security group."
}

output "task_role_arn" {
  value       = aws_iam_role.task.arn
  description = "Task role."
}
