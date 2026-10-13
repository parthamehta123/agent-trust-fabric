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
  name                        = "atf-test"
  vpc_id                      = "vpc-1"
  subnet_ids                  = ["subnet-a", "subnet-b"]
  domain                      = "atf.example.com"
  certificate_arn             = "arn:aws:acm:us-east-1:123456789012:certificate/c"
  admin_alb_arn               = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/a/b"
  admin_alb_security_group_id = "sg-admin-alb"
  oidc_issuer                 = "https://example.okta.com/oauth2/default"
  oidc_client_id              = "va-client"
  oidc_client_secret          = "test-secret"
  admin_groups                = ["atf-security-approvers", "atf-registry-approvers"]
}

run "cedar_policy_requires_admin_group" {
  command = plan
  assert {
    condition     = strcontains(aws_verifiedaccess_group.admins.policy_document, "context.okta.groups.containsAny([\"atf-security-approvers\", \"atf-registry-approvers\"])")
    error_message = "Only listed admin groups pass the gate."
  }
}

run "endpoint_reaches_only_admin_alb" {
  command = plan
  assert {
    condition     = aws_vpc_security_group_egress_rule.to_admin_alb.referenced_security_group_id == "sg-admin-alb"
    error_message = "The endpoint may reach only the admin ALB."
  }
}

run "no_admin_groups_refused" {
  command = plan
  variables {
    admin_groups = []
  }
  expect_failures = [var.admin_groups]
}
