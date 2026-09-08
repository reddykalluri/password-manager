locals {
  name = "vault-${var.environment}"
  # Map generic sizing to App Runner's expected forms ("1" → "1 vCPU", "2Gi" → "2 GB").
  cpu    = "${var.cpu} vCPU"
  memory = replace(var.memory, "Gi", " GB")
}

data "aws_region" "current" {}
data "aws_availability_zones" "available" { state = "available" }

# --- network (private DB + App Runner VPC connector) ---
resource "aws_vpc" "this" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(aws_vpc.this.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "${local.name}-private-${count.index}" }
}

resource "aws_security_group" "connector" {
  name_prefix = "${local.name}-conn-"
  vpc_id      = aws_vpc.this.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name_prefix = "${local.name}-db-"
  vpc_id      = aws_vpc.this.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.connector.id]
  }
}

resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

# --- secrets ---
resource "random_password" "db" {
  length  = 32
  special = false
}
resource "random_password" "token_key" {
  length  = 48
  special = false
}
resource "random_password" "operator_token" {
  length  = 48
  special = false
}

resource "aws_db_instance" "postgres" {
  identifier             = local.name
  engine                 = "postgres"
  engine_version         = "16"
  instance_class         = "db.t4g.micro"
  allocated_storage      = 20
  storage_encrypted      = true
  db_name                = "vault"
  username               = "vault"
  password               = random_password.db.result
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  skip_final_snapshot    = var.environment != "prod"
  deletion_protection    = var.environment == "prod"
}

resource "aws_secretsmanager_secret" "db_url" {
  name = "${local.name}-database-url"
}
resource "aws_secretsmanager_secret_version" "db_url" {
  secret_id     = aws_secretsmanager_secret.db_url.id
  secret_string = "postgres://vault:${random_password.db.result}@${aws_db_instance.postgres.address}:5432/vault"
}
resource "aws_secretsmanager_secret" "token_key" {
  name = "${local.name}-token-key"
}
resource "aws_secretsmanager_secret_version" "token_key" {
  secret_id     = aws_secretsmanager_secret.token_key.id
  secret_string = random_password.token_key.result
}
resource "aws_secretsmanager_secret" "operator_token" {
  name = "${local.name}-operator-token"
}
resource "aws_secretsmanager_secret_version" "operator_token" {
  secret_id     = aws_secretsmanager_secret.operator_token.id
  secret_string = random_password.operator_token.result
}

# --- registry + backup bucket ---
resource "aws_ecr_repository" "this" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_s3_bucket" "backups" {
  bucket = "${local.name}-backups"
}
resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- IAM ---
data "aws_iam_policy_document" "apprunner_build_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["build.apprunner.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "apprunner_access" {
  name               = "${local.name}-apprunner-access"
  assume_role_policy = data.aws_iam_policy_document.apprunner_build_assume.json
}
resource "aws_iam_role_policy_attachment" "ecr_access" {
  role       = aws_iam_role.apprunner_access.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess"
}

data "aws_iam_policy_document" "apprunner_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["tasks.apprunner.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "instance" {
  name               = "${local.name}-apprunner-instance"
  assume_role_policy = data.aws_iam_policy_document.apprunner_tasks_assume.json
}
data "aws_iam_policy_document" "instance" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.db_url.arn,
      aws_secretsmanager_secret.token_key.arn,
      aws_secretsmanager_secret.operator_token.arn,
    ]
  }
  statement {
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.backups.arn, "${aws_s3_bucket.backups.arn}/*"]
  }
}
resource "aws_iam_role_policy" "instance" {
  name   = "runtime"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance.json
}

# --- compute ---
resource "aws_apprunner_vpc_connector" "this" {
  vpc_connector_name = local.name
  subnets            = aws_subnet.private[*].id
  security_groups    = [aws_security_group.connector.id]
}

resource "aws_apprunner_service" "this" {
  service_name = local.name

  source_configuration {
    auto_deployments_enabled = false
    authentication_configuration {
      access_role_arn = aws_iam_role.apprunner_access.arn
    }
    image_repository {
      image_identifier      = var.image
      image_repository_type = "ECR"
      image_configuration {
        port = "8080"
        runtime_environment_variables = {
          VAULT_BIND               = "0.0.0.0:8080"
          VAULT_PUBLIC_ORIGIN      = "https://${var.domain}"
          VAULT_REGISTRATION       = "invite"
          RUST_LOG                 = "info"
          VAULT_LOG_FORMAT         = "json"
          VAULT_BACKUP_S3_BUCKET   = aws_s3_bucket.backups.bucket
          VAULT_BACKUP_S3_REGION   = data.aws_region.current.name
          VAULT_BACKUP_S3_ENDPOINT = "https://s3.${data.aws_region.current.name}.amazonaws.com"
        }
        runtime_environment_secrets = {
          VAULT_DATABASE_URL   = aws_secretsmanager_secret.db_url.arn
          VAULT_TOKEN_KEY      = aws_secretsmanager_secret.token_key.arn
          VAULT_OPERATOR_TOKEN = aws_secretsmanager_secret.operator_token.arn
        }
      }
    }
  }

  instance_configuration {
    cpu               = local.cpu
    memory            = local.memory
    instance_role_arn = aws_iam_role.instance.arn
  }

  network_configuration {
    egress_configuration {
      egress_type       = "VPC"
      vpc_connector_arn = aws_apprunner_vpc_connector.this.arn
    }
  }

  health_check_configuration {
    path     = "/health"
    protocol = "HTTP"
  }
}

resource "aws_apprunner_custom_domain_association" "this" {
  domain_name = var.domain
  service_arn = aws_apprunner_service.this.arn
}
