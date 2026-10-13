terraform {
  required_version = "~> 1.12.0" # OpenTofu (ADR-0026 §2)

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.66.0" # >= 14 days old at pin time
    }
  }

  # Remote state: S3 with native locking, KMS-encrypted. Bootstrap per docs; `-backend=false`
  # for validation. See backend.hcl.example.
  backend "s3" {}
}
