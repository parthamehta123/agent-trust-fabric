mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", name = "us-east-1" }
  }
}

variables {
  name        = "atf-test"
  client_keys = ["interceptor"]
  signers     = { bundle = ["arn:aws:iam::123456789012:role/atf-dev-bundle-publisher"] }
}

run "bundle_key_es256_only_publisher_signs" {
  command = plan
  assert {
    condition     = aws_kms_key.signing["bundle"].customer_master_key_spec == "ECC_NIST_P256" && aws_kms_key.signing["bundle"].key_usage == "SIGN_VERIFY"
    error_message = "The bundle key must be ES256 signing."
  }
  assert {
    condition     = !contains(jsondecode(aws_kms_key.signing["bundle"].policy).Statement[0].Action, "kms:Sign") && !contains(jsondecode(aws_kms_key.signing["bundle"].policy).Statement[0].Action, "kms:*")
    error_message = "Account admins must not be able to sign."
  }
  assert {
    condition     = jsondecode(aws_kms_key.signing["bundle"].policy).Statement[1].Principal.AWS == var.signers["bundle"]
    error_message = "Only the publisher signs bundles."
  }
}

run "client_keys_have_no_signer_until_granted" {
  command = plan
  assert {
    condition     = length(jsondecode(aws_kms_key.signing["interceptor"].policy).Statement) == 1
    error_message = "No sign permission without an explicit signer."
  }
}

run "data_key_rotates" {
  command = plan
  assert {
    condition     = aws_kms_key.data.enable_key_rotation
    error_message = "The data key must rotate."
  }
}
