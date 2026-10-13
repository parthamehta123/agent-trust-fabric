# Wildcard ACM certificate (DNS-validated in your public zone) for internal ALBs, plus a private
# zone so the plane hostnames resolve only inside the VPC (ADR-0026, 6b).
resource "aws_acm_certificate" "this" {
  domain_name       = "*.${var.domain}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for o in aws_acm_certificate.this.domain_validation_options : o.domain_name => o
  }
  zone_id = var.public_zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  ttl     = 300
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

resource "aws_route53_zone" "private" {
  # checkov:skip=CKV2_AWS_38:DNSSEC signing applies to public zones; this zone is private to the VPC.
  # checkov:skip=CKV2_AWS_39:Query logging for the private zone is enabled with the resolver config in 6d.
  name = var.domain
  vpc {
    vpc_id = var.vpc_id
  }
}
