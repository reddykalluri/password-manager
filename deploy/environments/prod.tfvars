# Production environment. Same shape as staging with production sizing.
cloud       = "aws"
environment = "prod"
image       = "REPLACE_WITH_REGISTRY/vault-server@sha256:REPLACE"
domain      = "vault.example.com"

min_instances = 2
max_instances = 6

# AWS
aws_region = "us-east-1"

# Azure
# azure_subscription_id = "00000000-0000-0000-0000-000000000000"
# azure_location        = "eastus"

# GCP
# gcp_project = "my-project"
# gcp_region  = "us-central1"
