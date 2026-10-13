# One repository per service: immutable tags (deploy by digest), scan on push, CMK encryption.
resource "aws_ecr_repository" "this" {
  for_each             = toset(var.services)
  name                 = "${var.name}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each   = aws_ecr_repository.this
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the most recent images only"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = var.keep_images }
      action       = { type = "expire" }
    }]
  })
}
