provider "aws" {
  region              = var.region
  allowed_account_ids = var.allowed_account_ids # refuse to run against any other account

  default_tags {
    tags = {
      project     = "agent-trust-fabric"
      environment = var.environment
      managed-by  = "opentofu"
    }
  }
}
