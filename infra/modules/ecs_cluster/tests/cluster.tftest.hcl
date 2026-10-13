mock_provider "aws" {}

variables {
  name = "atf-test"
}

run "fargate_only" {
  command = plan
  assert {
    condition     = aws_ecs_cluster_capacity_providers.this.capacity_providers == toset(["FARGATE"])
    error_message = "Fargate only: no EC2 hosts to patch or escape to."
  }
}
