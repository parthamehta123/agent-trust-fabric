# Bootstrap is applied once, by an administrator, with local state (it creates the remote state
# bucket everything else uses). Keep its state file out of git and in a safe place.
provider "aws" {
  region              = var.region
  allowed_account_ids = var.allowed_account_ids
  default_tags {
    tags = { project = "agent-trust-fabric", stack = "bootstrap", managed_by = "opentofu" }
  }
}
