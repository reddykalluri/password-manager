output "service_url" {
  value = "https://${var.domain}"
}
output "database_endpoint" {
  value     = aws_db_instance.postgres.address
  sensitive = true
}
output "backup_bucket" {
  value = aws_s3_bucket.backups.bucket
}
output "registry_url" {
  value = aws_ecr_repository.this.repository_url
}
