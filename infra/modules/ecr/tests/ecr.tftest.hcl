mock_provider "aws" {}

variables {
  name        = "atf-test"
  services    = ["mcp-gateway", "bundle-publisher"]
  kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/k"
}

run "immutable_scanned_encrypted" {
  command = plan
  assert {
    condition     = alltrue([for r in aws_ecr_repository.this : r.image_tag_mutability == "IMMUTABLE" && r.image_scanning_configuration[0].scan_on_push && r.encryption_configuration[0].encryption_type == "KMS"])
    error_message = "Immutable tags, scan on push, CMK encryption."
  }
}
