# The AgentCore Gateway interceptor (ADR-0012, ADR-0026 §16): an arm64 container image deployed
# by digest, VPC-attached with named egress only, reserved concurrency, KMS-encrypted
# environment. Its only callers are gateways whose role may invoke it (asserted in the env).

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/${var.name_prefix}/lambda/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_iam_role" "this" {
  name = "${var.name_prefix}-${var.name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

# What the function itself may do (bundle, SSM gateway id, its KMS signing key): passed in, exact.
resource "aws_iam_role_policy" "function" {
  name   = "function"
  role   = aws_iam_role.this.id
  policy = var.function_policy_json
}

# Platform plumbing, kept apart from the reviewed function policy. ENI actions have no
# resource-level permissions, so they're scoped by condition to this VPC's subnets instead.
resource "aws_iam_role_policy" "platform" {
  name = "platform"
  role = aws_iam_role.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.this.arn}:*" },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.kms_key_arn },
      {
        Effect   = "Allow"
        Action   = ["ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses"]
        Resource = "*"
        Condition = {
          ArnEqualsIfExists = { "ec2:Vpc" = "arn:${data.aws_partition.current.partition}:ec2:*:${data.aws_caller_identity.current.account_id}:vpc/${var.vpc_id}" }
        }
      },
    ]
  })
}

resource "aws_security_group" "this" {
  name        = "${var.name_prefix}-${var.name}"
  description = "Interceptor Lambda: no ingress; named egress only."
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "to_sg" {
  for_each                     = var.egress_security_group_ids
  security_group_id            = aws_security_group.this.id
  description                  = "to ${each.key}"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = each.value
}

resource "aws_vpc_security_group_egress_rule" "to_prefix_list" {
  for_each          = var.egress_prefix_list_ids
  security_group_id = aws_security_group.this.id
  description       = "to ${each.key}"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = each.value
}

resource "aws_vpc_security_group_egress_rule" "to_cidr" {
  for_each          = var.egress_cidrs
  security_group_id = aws_security_group.this.id
  description       = "to ${each.key}"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_lambda_function" "this" {
  # checkov:skip=CKV_AWS_50:X-Ray off by decision (ADR-0026 §16); audit events go to JSON logs.
  # checkov:skip=CKV_AWS_116:Invoked synchronously by the gateway; a DLQ never receives anything.
  # checkov:skip=CKV_AWS_272:Lambda code signing doesn't apply to container images; digest pinning plus an immutable, scanned ECR repo instead.
  function_name                  = "${var.name_prefix}-${var.name}"
  role                           = aws_iam_role.this.arn
  package_type                   = "Image"
  image_uri                      = "${var.repository_url}@${var.image_digest}"
  architectures                  = ["arm64"]
  timeout                        = var.timeout_s
  memory_size                    = var.memory_mb
  reserved_concurrent_executions = var.reserved_concurrency
  kms_key_arn                    = var.kms_key_arn

  environment {
    variables = var.environment
  }

  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.this.id]
  }

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.this.name
  }

  depends_on = [aws_iam_role_policy.platform]
}
