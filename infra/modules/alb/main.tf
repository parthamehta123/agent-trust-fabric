# Internal ALB for one plane (data, admin, tools). TLS 1.3, invalid headers dropped (header
# smuggling, matching the services' own duplicate-header checks), default 404.
resource "aws_security_group" "this" {
  name        = "${var.name}-alb"
  description = "${var.name} internal ALB"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "from_sources" {
  for_each                     = toset(var.source_security_group_ids)
  security_group_id            = aws_security_group.this.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "HTTPS from an allowed source"
}

resource "aws_lb" "this" {
  # checkov:skip=CKV_AWS_91:Requests are audited by the services' closed-schema audit events and VPC flow logs; ALB logs would duplicate them.
  name                       = var.name
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = var.subnet_ids
  security_groups            = [aws_security_group.this.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = "{\"error\":\"not_found\"}"
      status_code  = "404"
    }
  }
}
