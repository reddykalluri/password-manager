output "service_url" {
  value = "https://${var.domain}"
}
output "database_endpoint" {
  value     = google_sql_database_instance.this.private_ip_address
  sensitive = true
}
output "backup_bucket" {
  value = google_storage_bucket.backups.name
}
output "registry_url" {
  value = "${var.region}-docker.pkg.dev/${google_artifact_registry_repository.this.project}/${google_artifact_registry_repository.this.repository_id}"
}
