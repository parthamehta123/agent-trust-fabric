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
  domain         = "atf.example.com"
  public_zone_id = "Z123"
  vpc_id         = "vpc-1"
}

run "wildcard_dns_validated_private_zone" {
  command = plan
  assert {
    condition     = aws_acm_certificate.this.domain_name == "*.atf.example.com" && aws_acm_certificate.this.validation_method == "DNS"
    error_message = "Wildcard certificate validated by DNS."
  }
  assert {
    condition     = one(aws_route53_zone.private.vpc).vpc_id == "vpc-1"
    error_message = "Internal names resolve only inside the VPC."
  }
}
