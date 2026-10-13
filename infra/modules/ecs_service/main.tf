# One hardened Fargate service (ADR-0026 §4): its own task role, its own security group that
# admits only its load balancer, explicit egress, read-only root, non-root, no capabilities,
# no exec, image pinned by digest.

data "aws_region" "current" {}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/${var.name_prefix}/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-${var.name}-task"
  assume_role_policy = local.ecs_trust
}

resource "aws_iam_role_policy" "task" {
  count  = var.task_policy_json == null ? 0 : 1
  name   = "least-privilege"
  role   = aws_iam_role.task.id
  policy = var.task_policy_json
}

resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-${var.name}-exec"
  assume_role_policy = local.ecs_trust
}

# Execution role: pull this service's image and write its own logs. Nothing else.
resource "aws_iam_role_policy" "execution" {
  name = "pull-and-log"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource = var.repository_arn },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.kms_key_arn },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.this.arn}:*" },
    ]
  })
}

locals {
  ecs_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.name_prefix}-${var.name}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  volume {
    name = "tmp" # Fargate has no tmpfs: an ephemeral volume backs /tmp under a read-only root
  }

  container_definitions = jsonencode([{
    name                   = var.name
    image                  = "${var.repository_url}@${var.image_digest}"
    essential              = true
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    privileged             = false
    entryPoint             = var.entry_point
    command                = var.command
    environment            = [for k, v in var.environment : { name = k, value = v }]
    portMappings           = var.listen ? [{ containerPort = 8443, protocol = "tcp" }] : []
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
    linuxParameters = {
      capabilities       = { drop = ["ALL"] }
      initProcessEnabled = true
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = data.aws_region.current.region
        awslogs-stream-prefix = var.name
      }
    }
  }])
}

resource "aws_security_group" "task" {
  name        = "${var.name_prefix}-${var.name}"
  description = "${var.name} tasks"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "from_alb" {
  count                        = var.listen ? 1 : 0
  security_group_id            = aws_security_group.task.id
  referenced_security_group_id = var.alb_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 8443
  to_port                      = 8443
  description                  = "Only from this service's load balancer"
}

resource "aws_vpc_security_group_egress_rule" "to_sg" {
  for_each                     = var.egress_security_group_ids
  security_group_id            = aws_security_group.task.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "To ${each.key}"
}

resource "aws_vpc_security_group_egress_rule" "to_prefix_list" {
  for_each          = var.egress_prefix_list_ids
  security_group_id = aws_security_group.task.id
  prefix_list_id    = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "To ${each.key} (gateway endpoint)"
}

resource "aws_vpc_security_group_egress_rule" "to_cidr" {
  for_each          = var.egress_cidrs
  security_group_id = aws_security_group.task.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "To ${each.key}"
}

resource "aws_lb_target_group" "this" {
  count       = var.listen ? 1 : 0
  name        = substr("${var.name_prefix}-${var.name}", 0, 32)
  port        = 8443
  protocol    = "HTTPS"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    protocol = "HTTPS"
    path     = "/ping"
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "this" {
  count        = var.listen ? 1 : 0
  listener_arn = var.listener_arn
  priority     = var.rule_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[0].arn
  }

  condition {
    host_header {
      values = [var.host_name]
    }
  }
}

resource "aws_ecs_service" "this" {
  name                   = var.name
  cluster                = var.cluster_arn
  task_definition        = aws_ecs_task_definition.this.arn
  desired_count          = var.desired_count
  launch_type            = "FARGATE"
  enable_execute_command = false # nobody shells into a task
  propagate_tags         = "SERVICE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  dynamic "load_balancer" {
    for_each = var.listen ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.this[0].arn
      container_name   = var.name
      container_port   = 8443
    }
  }
}
