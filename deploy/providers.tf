# All three providers are declared; only the one matching var.cloud is exercised
# (the other modules have count = 0, so their providers are never configured and
# need no credentials).

provider "aws" {
  region = var.aws_region
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}
