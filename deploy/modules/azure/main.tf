locals {
  name = "vault-${var.environment}"
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "this" {
  name     = local.name
  location = var.location
}

# --- network: VNet with delegated subnets for Container Apps and Postgres ---
resource "azurerm_virtual_network" "this" {
  name                = local.name
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  address_space       = ["10.10.0.0/16"]
}

resource "azurerm_subnet" "apps" {
  name                 = "apps"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.10.0.0/23"]
}

resource "azurerm_subnet" "db" {
  name                 = "db"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.10.2.0/24"]
  delegation {
    name = "pg"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_private_dns_zone" "pg" {
  name                = "${local.name}.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.this.name
}
resource "azurerm_private_dns_zone_virtual_network_link" "pg" {
  name                  = "pg"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.pg.name
  virtual_network_id    = azurerm_virtual_network.this.id
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

resource "azurerm_postgresql_flexible_server" "this" {
  name                          = local.name
  resource_group_name           = azurerm_resource_group.this.name
  location                      = azurerm_resource_group.this.location
  version                       = "16"
  administrator_login           = "vault"
  administrator_password        = random_password.db.result
  storage_mb                    = 32768
  sku_name                      = "B_Standard_B1ms"
  delegated_subnet_id           = azurerm_subnet.db.id
  private_dns_zone_id           = azurerm_private_dns_zone.pg.id
  public_network_access_enabled = false
  zone                          = "1"
  depends_on                    = [azurerm_private_dns_zone_virtual_network_link.pg]
}

resource "azurerm_postgresql_flexible_server_database" "vault" {
  name      = "vault"
  server_id = azurerm_postgresql_flexible_server.this.id
}

# --- identity, registry, key vault ---
resource "azurerm_user_assigned_identity" "app" {
  name                = "${local.name}-app"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
}

resource "azurerm_container_registry" "this" {
  name                = replace("${local.name}acr", "-", "")
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  sku                 = "Basic"
}
resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_key_vault" "this" {
  name                = replace("${local.name}kv", "-", "")
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id          = data.azurerm_client_config.current.tenant_id
    object_id          = data.azurerm_client_config.current.object_id
    secret_permissions = ["Get", "List", "Set", "Delete", "Purge"]
  }
  access_policy {
    tenant_id          = data.azurerm_client_config.current.tenant_id
    object_id          = azurerm_user_assigned_identity.app.principal_id
    secret_permissions = ["Get"]
  }
}

resource "azurerm_key_vault_secret" "db_url" {
  name         = "database-url"
  key_vault_id = azurerm_key_vault.this.id
  value        = "postgres://vault:${random_password.db.result}@${azurerm_postgresql_flexible_server.this.fqdn}:5432/vault"
}
resource "azurerm_key_vault_secret" "token_key" {
  name         = "token-key"
  key_vault_id = azurerm_key_vault.this.id
  value        = random_password.token_key.result
}
resource "azurerm_key_vault_secret" "operator_token" {
  name         = "operator-token"
  key_vault_id = azurerm_key_vault.this.id
  value        = random_password.operator_token.result
}

# --- backups ---
resource "azurerm_storage_account" "backups" {
  name                     = replace("${local.name}bk", "-", "")
  resource_group_name      = azurerm_resource_group.this.name
  location                 = azurerm_resource_group.this.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}
resource "azurerm_storage_container" "backups" {
  name                  = "backups"
  storage_account_id    = azurerm_storage_account.backups.id
  container_access_type = "private"
}

# --- compute ---
resource "azurerm_container_app_environment" "this" {
  name                     = local.name
  resource_group_name      = azurerm_resource_group.this.name
  location                 = azurerm_resource_group.this.location
  infrastructure_subnet_id = azurerm_subnet.apps.id
}

resource "azurerm_container_app" "this" {
  name                         = local.name
  resource_group_name          = azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  registry {
    server   = azurerm_container_registry.this.login_server
    identity = azurerm_user_assigned_identity.app.id
  }

  secret {
    name                = "database-url"
    identity            = azurerm_user_assigned_identity.app.id
    key_vault_secret_id = azurerm_key_vault_secret.db_url.id
  }
  secret {
    name                = "token-key"
    identity            = azurerm_user_assigned_identity.app.id
    key_vault_secret_id = azurerm_key_vault_secret.token_key.id
  }
  secret {
    name                = "operator-token"
    identity            = azurerm_user_assigned_identity.app.id
    key_vault_secret_id = azurerm_key_vault_secret.operator_token.id
  }

  template {
    min_replicas = var.min_instances
    max_replicas = var.max_instances
    container {
      name   = "vault-server"
      image  = var.image
      cpu    = tonumber(var.cpu)
      memory = var.memory

      env {
        name  = "VAULT_BIND"
        value = "0.0.0.0:8080"
      }
      env {
        name  = "VAULT_PUBLIC_ORIGIN"
        value = "https://${var.domain}"
      }
      env {
        name  = "VAULT_REGISTRATION"
        value = "invite"
      }
      env {
        name        = "VAULT_DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name        = "VAULT_TOKEN_KEY"
        secret_name = "token-key"
      }
      env {
        name        = "VAULT_OPERATOR_TOKEN"
        secret_name = "operator-token"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}

resource "azurerm_container_app_custom_domain" "this" {
  name                     = var.domain
  container_app_id         = azurerm_container_app.this.id
  certificate_binding_type = "SniEnabled"
}
