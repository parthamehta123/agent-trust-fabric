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
  name              = "atf-test"
  monthly_limit_usd = 50
  alert_emails      = ["owner@example.com"]
}

run "three_alerts" {
  command = plan
  assert {
    condition     = length(aws_budgets_budget.monthly.notification) == 3
    error_message = "Alerts at 50/80 percent actual and 100 percent forecast."
  }
}

run "needs_recipients" {
  command = plan
  variables {
    alert_emails = []
  }
  expect_failures = [var.alert_emails]
}
