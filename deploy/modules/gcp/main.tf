locals {
  name = "vault-${var.environment}"
}

# --- network: private Cloud SQL + serverless VPC connector ---
resource "google_compute_network" "this" {
  name                    = local.name
  auto_create_subnetworks = true
}

resource "google_compute_global_address" "private" {
  name          = "${local.name}-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.this.id
}

resource "google_service_networking_connection" "this" {
  network                 = google_compute_network.this.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private.name]
}

resource "google_vpc_access_connector" "this" {
  name          = local.name
  region        = var.region
  network       = google_compute_network.this.name
  ip_cidr_range = "10.8.0.0/28"
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

resource "google_sql_database_instance" "this" {
  name                = local.name
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = var.environment == "prod"
  depends_on          = [google_service_networking_connection.this]

  settings {
    tier = "db-custom-1-3840"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.this.id
    }
    backup_configuration {
      enabled = true
    }
  }
}

resource "google_sql_database" "vault" {
  name     = "vault"
  instance = google_sql_database_instance.this.name
}

resource "google_sql_user" "vault" {
  name     = "vault"
  instance = google_sql_database_instance.this.name
  password = random_password.db.result
}

resource "google_secret_manager_secret" "db_url" {
  secret_id = "${local.name}-database-url"
  replication {
    auto {}
  }
}
resource "google_secret_manager_secret_version" "db_url" {
  secret      = google_secret_manager_secret.db_url.id
  secret_data = "postgres://vault:${random_password.db.result}@${google_sql_database_instance.this.private_ip_address}:5432/vault"
}
resource "google_secret_manager_secret" "token_key" {
  secret_id = "${local.name}-token-key"
  replication {
    auto {}
  }
}
resource "google_secret_manager_secret_version" "token_key" {
  secret      = google_secret_manager_secret.token_key.id
  secret_data = random_password.token_key.result
}
resource "google_secret_manager_secret" "operator_token" {
  secret_id = "${local.name}-operator-token"
  replication {
    auto {}
  }
}
resource "google_secret_manager_secret_version" "operator_token" {
  secret      = google_secret_manager_secret.operator_token.id
  secret_data = random_password.operator_token.result
}

# --- registry + backups ---
resource "google_artifact_registry_repository" "this" {
  location      = var.region
  repository_id = local.name
  format        = "DOCKER"
}

resource "google_storage_bucket" "backups" {
  name                        = "${local.name}-backups"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning { enabled = true }
}

# --- service account + IAM ---
resource "google_service_account" "run" {
  account_id   = local.name
  display_name = "vault-server ${var.environment}"
}
resource "google_secret_manager_secret_iam_member" "db_url" {
  secret_id = google_secret_manager_secret.db_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}
resource "google_secret_manager_secret_iam_member" "token_key" {
  secret_id = google_secret_manager_secret.token_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}
resource "google_secret_manager_secret_iam_member" "operator_token" {
  secret_id = google_secret_manager_secret.operator_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}
resource "google_storage_bucket_iam_member" "backups" {
  bucket = google_storage_bucket.backups.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.run.email}"
}

# --- compute ---
resource "google_cloud_run_v2_service" "this" {
  name     = local.name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.run.email
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }
    vpc_access {
      connector = google_vpc_access_connector.this.id
      egress    = "PRIVATE_RANGES_ONLY"
    }
    containers {
      image = var.image
      ports { container_port = 8080 }
      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
      }
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
        name  = "VAULT_BACKUP_S3_BUCKET"
        value = google_storage_bucket.backups.name
      }
      env {
        name = "VAULT_DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_url.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "VAULT_TOKEN_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.token_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "VAULT_OPERATOR_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.operator_token.secret_id
            version = "latest"
          }
        }
      }
    }
  }
}

# Public reachability (the app enforces its own auth).
resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.this.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_domain_mapping" "this" {
  name     = var.domain
  location = var.region
  metadata {
    namespace = google_cloud_run_v2_service.this.project
  }
  spec {
    route_name = google_cloud_run_v2_service.this.name
  }
}
