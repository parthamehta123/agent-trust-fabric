mock_provider "aws" {
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/atf/0123456789abcdef", dns_name = "internal-atf.elb.amazonaws.com", zone_id = "Z35SXDOTRQ7X7K" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/atf/0123456789abcdef" }
  }
  mock_resource "aws_acm_certificate" {
    defaults = { arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_verifiedaccess_group" {
    defaults = { id = "vagr-0123456789abcdef0" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", name = "us-east-1" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/atf-test/svc" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/atf-test-svc" }
  }
}

variables {
  name                  = "mcp-gateway"
  name_prefix           = "atf-test"
  cluster_arn           = "arn:aws:ecs:us-east-1:123456789012:cluster/atf-test"
  vpc_id                = "vpc-123"
  subnet_ids            = ["subnet-a", "subnet-b"]
  repository_url        = "123456789012.dkr.ecr.us-east-1.amazonaws.com/atf-test/mcp-gateway"
  repository_arn        = "arn:aws:ecr:us-east-1:123456789012:repository/atf-test/mcp-gateway"
  image_digest          = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  kms_key_arn           = "arn:aws:kms:us-east-1:123456789012:key/k"
  alb_security_group_id = "sg-alb"
  listener_arn          = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/x/y/z"
  host_name             = "mcp.atf.example.com"
  rule_priority         = 10
}

run "task_is_hardened" {
  command = plan
  assert {
    condition     = jsondecode(aws_ecs_task_definition.this.container_definitions)[0].readonlyRootFilesystem
    error_message = "Read-only root filesystem."
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.this.container_definitions)[0].user == "10001:10001"
    error_message = "Non-root user."
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.this.container_definitions)[0].linuxParameters.capabilities.drop == ["ALL"]
    error_message = "All capabilities dropped."
  }
  assert {
    condition     = endswith(jsondecode(aws_ecs_task_definition.this.container_definitions)[0].image, "@${var.image_digest}")
    error_message = "Image pinned by digest."
  }
}

run "service_is_private_and_unexecutable" {
  command = plan
  assert {
    condition     = !aws_ecs_service.this.enable_execute_command
    error_message = "ECS Exec must be disabled."
  }
  assert {
    condition     = !aws_ecs_service.this.network_configuration[0].assign_public_ip
    error_message = "No public IP."
  }
  assert {
    condition     = aws_ecs_service.this.deployment_circuit_breaker[0].rollback
    error_message = "Failed deployments roll back."
  }
}

run "only_its_load_balancer_gets_in" {
  command = plan
  assert {
    condition     = aws_vpc_security_group_ingress_rule.from_alb[0].referenced_security_group_id == "sg-alb" && aws_vpc_security_group_ingress_rule.from_alb[0].from_port == 8443
    error_message = "Ingress only from the service's ALB on 8443."
  }
  assert {
    condition     = length(aws_vpc_security_group_egress_rule.to_cidr) == 0
    error_message = "No CIDR egress unless granted."
  }
}

run "execution_role_scoped_to_its_repo" {
  command = plan
  assert {
    condition     = jsondecode(aws_iam_role_policy.execution.policy).Statement[1].Resource == var.repository_arn
    error_message = "The execution role may pull only this service's repository."
  }
}

run "tags_never_deployed" {
  command = plan
  variables {
    image_digest = "latest"
  }
  expect_failures = [var.image_digest]
}
