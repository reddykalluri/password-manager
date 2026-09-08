output "service_url" {
  value = "https://${var.domain}"
}
output "database_endpoint" {
  value     = azurerm_postgresql_flexible_server.this.fqdn
  sensitive = true
}
output "backup_bucket" {
  value = azurerm_storage_container.backups.name
}
output "registry_url" {
  value = azurerm_container_registry.this.login_server
}
