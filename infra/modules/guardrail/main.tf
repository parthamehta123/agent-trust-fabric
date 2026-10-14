# Bedrock Guardrail for the inference gateway (ADR-0026 §17). The gateway pins a published
# version, never DRAFT. PII is anonymised on output (masked, as at retrieval, ADR-0025);
# credential-shaped data is blocked in both directions.

locals {
  content_filters = ["HATE", "INSULTS", "SEXUAL", "VIOLENCE", "MISCONDUCT"]
  pii_anonymise   = ["EMAIL", "PHONE", "NAME", "ADDRESS"]
  pii_block       = ["AWS_ACCESS_KEY", "AWS_SECRET_KEY"]
  secret_regexes = {
    "pem-private-key" = { pattern = "-----BEGIN [A-Z ]*PRIVATE KEY-----", description = "PEM private key header" }
    "jwt"             = { pattern = "eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}", description = "JWT-shaped bearer token" }
  }
}

resource "aws_bedrock_guardrail" "this" {
  name                      = var.name
  description               = "ATF inference gateway guardrail (ADR-0026 §17)."
  kms_key_arn               = var.kms_key_arn
  blocked_input_messaging   = "This request was blocked by policy."
  blocked_outputs_messaging = "This response was blocked by policy."

  content_policy_config {
    dynamic "filters_config" {
      for_each = toset(local.content_filters)
      content {
        type            = filters_config.value
        input_strength  = "MEDIUM"
        output_strength = "MEDIUM"
      }
    }
    # Prompt attacks are judged on input only; the API requires output strength NONE.
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
  }

  sensitive_information_policy_config {
    dynamic "pii_entities_config" {
      for_each = toset(local.pii_anonymise)
      content {
        type           = pii_entities_config.value
        action         = "ANONYMIZE"
        input_enabled  = false # users may name themselves; mask what comes back instead
        output_enabled = true
        output_action  = "ANONYMIZE"
      }
    }
    dynamic "pii_entities_config" {
      for_each = toset(local.pii_block)
      content {
        type           = pii_entities_config.value
        action         = "BLOCK"
        input_enabled  = true
        input_action   = "BLOCK"
        output_enabled = true
        output_action  = "BLOCK"
      }
    }
    dynamic "regexes_config" {
      for_each = local.secret_regexes
      content {
        name           = regexes_config.key
        description    = regexes_config.value.description
        pattern        = regexes_config.value.pattern
        action         = "BLOCK"
        input_enabled  = true
        input_action   = "BLOCK"
        output_enabled = true
        output_action  = "BLOCK"
      }
    }
  }
}

# A published, immutable version: changing the guardrail creates a new version the gateway must be
# repointed at (a reviewed task-definition change), never a silent DRAFT edit.
resource "aws_bedrock_guardrail_version" "this" {
  guardrail_arn = aws_bedrock_guardrail.this.guardrail_arn
  description   = "Pinned by the inference gateway."
  skip_destroy  = true
}
