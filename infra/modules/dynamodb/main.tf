# Tables (ADR-0018, ADR-0019, ADR-0021): KMS-encrypted with the data CMK, point-in-time
# recovery on, deletion protection on. Key schemas match the services' local tables exactly.

locals {
  tables = {
    agents = {
      hash  = { name = "agent_id", type = "S" }
      range = { name = "version", type = "N" }
    }
    mcp-servers = {
      hash  = { name = "server_id", type = "S" }
      range = null
    }
    budgets = {
      hash  = { name = "pk", type = "S" }
      range = null
    }
  }
}

resource "aws_dynamodb_table" "this" {
  for_each                    = local.tables
  name                        = "${var.name}-${each.key}"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = each.value.hash.name
  range_key                   = each.value.range == null ? null : each.value.range.name
  deletion_protection_enabled = var.deletion_protection

  attribute {
    name = each.value.hash.name
    type = each.value.hash.type
  }

  dynamic "attribute" {
    for_each = each.value.range == null ? [] : [each.value.range]
    content {
      name = attribute.value.name
      type = attribute.value.type
    }
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }
}
