# Uniform outputs regardless of the selected cloud.

output "service_url" {
  description = "Public HTTPS URL of the instance."
  value = coalesce(
    try(module.aws[0].service_url, null),
    try(module.azure[0].service_url, null),
    try(module.gcp[0].service_url, null),
  )
}

output "database_endpoint" {
  description = "Private endpoint of the managed PostgreSQL database."
  value = coalesce(
    try(module.aws[0].database_endpoint, null),
    try(module.azure[0].database_endpoint, null),
    try(module.gcp[0].database_endpoint, null),
  )
  sensitive = true
}

output "backup_bucket" {
  description = "Object-storage bucket/container for backups."
  value = coalesce(
    try(module.aws[0].backup_bucket, null),
    try(module.azure[0].backup_bucket, null),
    try(module.gcp[0].backup_bucket, null),
  )
}

output "registry_url" {
  description = "Container registry the image is pushed to."
  value = coalesce(
    try(module.aws[0].registry_url, null),
    try(module.azure[0].registry_url, null),
    try(module.gcp[0].registry_url, null),
  )
}
