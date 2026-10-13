config {
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "all"
}

# Official ruleset: tflint verifies its signed checksums with the built-in key (ADR-0026 §2).
plugin "aws" {
  enabled = true
  version = "0.49.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}
