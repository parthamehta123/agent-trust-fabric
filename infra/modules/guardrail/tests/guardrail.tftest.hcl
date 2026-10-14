mock_provider "aws" {
  mock_resource "aws_bedrock_guardrail" {
    defaults = { guardrail_id = "gr0123456789", guardrail_arn = "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr0123456789" }
  }
  mock_resource "aws_bedrock_guardrail_version" {
    defaults = { version = "1" }
  }
}

variables {
  name        = "atf-dev-inference"
  kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}

run "strict_input_masked_output" {
  command = plan
  assert {
    condition = one([
      for f in aws_bedrock_guardrail.this.content_policy_config[0].filters_config : f
      if f.type == "PROMPT_ATTACK"
    ]).input_strength == "HIGH"
    error_message = "Prompt attacks are filtered at HIGH on input."
  }
  assert {
    condition = alltrue([
      for f in aws_bedrock_guardrail.this.content_policy_config[0].filters_config :
      f.type == "PROMPT_ATTACK" || (f.input_strength == "MEDIUM" && f.output_strength == "MEDIUM")
    ]) && length(aws_bedrock_guardrail.this.content_policy_config[0].filters_config) == 6
    error_message = "Five content filters at MEDIUM both ways, plus the prompt-attack filter."
  }
  assert {
    condition = alltrue([
      for p in aws_bedrock_guardrail.this.sensitive_information_policy_config[0].pii_entities_config :
      contains(["EMAIL", "PHONE", "NAME", "ADDRESS"], p.type) ? (p.output_action == "ANONYMIZE" && p.output_enabled && !p.input_enabled) : (p.input_action == "BLOCK" && p.output_action == "BLOCK")
    ])
    error_message = "Contact PII is masked on output; AWS credentials are blocked both ways."
  }
  assert {
    condition     = toset([for r in aws_bedrock_guardrail.this.sensitive_information_policy_config[0].regexes_config : r.name if r.input_action == "BLOCK" && r.output_action == "BLOCK"]) == toset(["pem-private-key", "jwt"])
    error_message = "Private keys and JWT-shaped tokens are blocked both ways."
  }
  assert {
    condition     = aws_bedrock_guardrail.this.kms_key_arn == var.kms_key_arn
    error_message = "Encrypted with the customer-managed key."
  }
}

run "pins_a_published_version" {
  command = plan
  assert {
    condition     = output.version == "1" && aws_bedrock_guardrail_version.this.skip_destroy
    error_message = "The gateway pins a published version, kept on replacement."
  }
}
