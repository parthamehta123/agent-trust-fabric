# AgentCore Gateway in front of an agent runtime (ADR-0012, ADR-0026 §15/§22).
#   authorizer  : CUSTOM_JWT pinned to the ingress AS (audience + frontend client)
#   interceptor : our Lambda on REQUEST and RESPONSE, with request headers (it binds
#                 Authorization + X-Subject-Token); it is the policy enforcement point
#   policy      : no AgentCore Policy engine; the signed bundle is the only policy source
#   target      : the agent runtime; only reserved x-atf-* headers are allowlisted, never credentials

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

resource "aws_iam_role" "this" {
  name = "${var.name}-gateway"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:bedrock-agentcore:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:gateway/*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "this" {
  role = aws_iam_role.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = var.interceptor_arn },
      { Effect = "Allow", Action = ["bedrock-agentcore:InvokeAgentRuntime"], Resource = [var.target_runtime_arn, "${var.target_runtime_arn}/*"] },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.kms_key_arn },
    ]
  })
}

resource "aws_bedrockagentcore_gateway" "this" {
  name            = var.name
  description     = "ATF ingress gateway (ADR-0026 §15)."
  role_arn        = aws_iam_role.this.arn
  kms_key_arn     = var.kms_key_arn
  authorizer_type = "CUSTOM_JWT"
  # exception_level stays unset: callers never get debug detail.

  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url    = var.discovery_url
      allowed_audience = var.allowed_audiences
      allowed_clients  = var.allowed_clients
    }
  }

  interceptor_configuration {
    interception_points = ["REQUEST", "RESPONSE"]
    input_configuration {
      pass_request_headers = true
    }
    interceptor {
      lambda {
        arn = var.interceptor_arn
      }
    }
  }

  depends_on = [aws_iam_role_policy.this]
}

resource "aws_bedrockagentcore_gateway_target" "runtime" {
  gateway_identifier = aws_bedrockagentcore_gateway.this.gateway_id
  name               = var.target_name
  description        = "Agent runtime behind the interceptor."

  target_configuration {
    http {
      agentcore_runtime {
        arn = var.target_runtime_arn
      }
    }
  }

  # The interceptor's Authorization (the T2) overrides any credential-provider token
  # (ADR-0012); pass-through is the honest description of that.
  credential_provider_configuration {
    jwt_passthrough {}
  }

  metadata_configuration {
    allowed_request_headers = var.allowed_request_headers
  }
}

# ADR-0026 §22: the gateway id is AWS-assigned and the gateway needs the Lambda's ARN, so the
# interceptor reads its gateway id from here once at cold start (exact match, ADR-0012 §2).
resource "aws_ssm_parameter" "gateway_id" {
  # checkov:skip=CKV2_AWS_34:An identifier, not a secret; a plain String keeps the reader free of KMS decrypt on SSM.
  name  = var.gateway_id_parameter_name
  type  = "String"
  value = aws_bedrockagentcore_gateway.this.gateway_id
}
