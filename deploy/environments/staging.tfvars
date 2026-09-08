# Staging environment. Set `cloud` to aws | azure | gcp and fill the matching
# provider inputs. `image` must be an immutable digest reference.
cloud       = "aws"
environment = "staging"
image       = "REPLACE_WITH_REGISTRY/vault-server@sha256:REPLACE"
domain      = "vault-staging.example.com"

min_instances = 1
max_instances = 2

# AWS
aws_region = "us-east-1"

# Azure
# azure_subscription_id = "00000000-0000-0000-0000-000000000000"
# azure_location        = "eastus"

# GCP
# gcp_project = "my-project"
# gcp_region  = "us-central1"
