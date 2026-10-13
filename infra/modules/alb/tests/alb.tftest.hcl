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
}

variables {
  name                      = "atf-test-admin"
  vpc_id                    = "vpc-1"
  subnet_ids                = ["subnet-a", "subnet-b"]
  certificate_arn           = "arn:aws:acm:us-east-1:123456789012:certificate/c"
  source_security_group_ids = ["sg-va"]
}

run "internal_tls13_and_strict_headers" {
  command = plan
  assert {
    condition     = aws_lb.this.internal && aws_lb.this.drop_invalid_header_fields
    error_message = "Internal, and invalid headers dropped."
  }
  assert {
    condition     = startswith(aws_lb_listener.https.ssl_policy, "ELBSecurityPolicy-TLS13")
    error_message = "TLS 1.3 policy."
  }
  assert {
    condition     = aws_lb_listener.https.default_action[0].fixed_response[0].status_code == "404"
    error_message = "Unrouted hosts get a 404."
  }
}

run "only_listed_sources" {
  command = plan
  assert {
    condition     = keys(aws_vpc_security_group_ingress_rule.from_sources) == ["sg-va"]
    error_message = "Only the listed source security groups may reach the ALB."
  }
}
