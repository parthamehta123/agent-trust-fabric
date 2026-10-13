# Zero-trust front door for the admin plane (ADR-0018 §2, ADR-0026 6b): every request is
# authenticated against the IdP (OIDC) and checked by a Cedar policy before reaching the admin ALB.
resource "aws_verifiedaccess_trust_provider" "oidc" {
  policy_reference_name    = "okta"
  trust_provider_type      = "user"
  user_trust_provider_type = "oidc"

  oidc_options {
    issuer                 = var.oidc_issuer
    authorization_endpoint = "${var.oidc_issuer}/v1/authorize"
    token_endpoint         = "${var.oidc_issuer}/v1/token"
    user_info_endpoint     = "${var.oidc_issuer}/v1/userinfo"
    client_id              = var.oidc_client_id
    client_secret          = var.oidc_client_secret
    scope                  = "openid profile groups"
  }
}

resource "aws_verifiedaccess_instance" "this" {
  description = "${var.name} admin access"
}

resource "aws_verifiedaccess_instance_trust_provider_attachment" "this" {
  verifiedaccess_instance_id       = aws_verifiedaccess_instance.this.id
  verifiedaccess_trust_provider_id = aws_verifiedaccess_trust_provider.oidc.id
}

resource "aws_verifiedaccess_group" "admins" {
  verifiedaccess_instance_id = aws_verifiedaccess_instance.this.id
  description                = "Platform admins"
  policy_document            = local.policy
  depends_on                 = [aws_verifiedaccess_instance_trust_provider_attachment.this]
}

locals {
  # Cedar (the same language as our bundle policies): only listed admin groups get through.
  policy = <<-CEDAR
    permit(principal, action, resource)
    when {
      context.okta.groups.containsAny([${join(", ", [for g in var.admin_groups : "\"${g}\""])}])
    };
  CEDAR
}

resource "aws_security_group" "endpoint" {
  name        = "${var.name}-verified-access"
  description = "Verified Access endpoint for the admin plane"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "to_admin_alb" {
  security_group_id            = aws_security_group.endpoint.id
  referenced_security_group_id = var.admin_alb_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Only to the admin ALB"
}

resource "aws_verifiedaccess_endpoint" "admin" {
  verified_access_group_id = aws_verifiedaccess_group.admins.id
  endpoint_type            = "load-balancer"
  attachment_type          = "vpc"
  application_domain       = "admin.${var.domain}"
  domain_certificate_arn   = var.certificate_arn
  endpoint_domain_prefix   = "atf-admin"
  security_group_ids       = [aws_security_group.endpoint.id]

  load_balancer_options {
    load_balancer_arn = var.admin_alb_arn
    port              = 443
    protocol          = "https"
    subnet_ids        = var.subnet_ids
  }
}
