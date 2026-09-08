# One `cloud` variable selects the implementation module. Each module honours the
# common contract (see modules/common-contract.md): same inputs, same outputs.

module "aws" {
  count  = var.cloud == "aws" ? 1 : 0
  source = "./modules/aws"

  environment   = var.environment
  image         = var.image
  domain        = var.domain
  cpu           = var.cpu
  memory        = var.memory
  min_instances = var.min_instances
  max_instances = var.max_instances

  providers = { aws = aws }
}

module "azure" {
  count  = var.cloud == "azure" ? 1 : 0
  source = "./modules/azure"

  environment   = var.environment
  image         = var.image
  domain        = var.domain
  location      = var.azure_location
  cpu           = var.cpu
  memory        = var.memory
  min_instances = var.min_instances
  max_instances = var.max_instances

  providers = { azurerm = azurerm }
}

module "gcp" {
  count  = var.cloud == "gcp" ? 1 : 0
  source = "./modules/gcp"

  environment   = var.environment
  image         = var.image
  domain        = var.domain
  region        = var.gcp_region
  cpu           = var.cpu
  memory        = var.memory
  min_instances = var.min_instances
  max_instances = var.max_instances

  providers = { google = google }
}
