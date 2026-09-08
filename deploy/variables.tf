variable "cloud" {
  description = "Which cloud to deploy to."
  type        = string
  validation {
    condition     = contains(["aws", "azure", "gcp"], var.cloud)
    error_message = "cloud must be one of: aws, azure, gcp."
  }
}

variable "environment" {
  description = "Environment name (e.g. staging, prod); isolates resources."
  type        = string
  default     = "staging"
}

variable "image" {
  description = "Fully-qualified vault-server container image, pinned by digest."
  type        = string
}

variable "domain" {
  description = "Public hostname the instance is served on (operator-owned)."
  type        = string
}

variable "cpu" {
  description = "vCPU for the container service."
  type        = string
  default     = "1"
}

variable "memory" {
  description = "Memory for the container service (e.g. 2Gi / 2048)."
  type        = string
  default     = "2Gi"
}

variable "min_instances" {
  type    = number
  default = 1
}

variable "max_instances" {
  type    = number
  default = 3
}

# --- AWS ---
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

# --- Azure ---
variable "azure_subscription_id" {
  type    = string
  default = ""
}
variable "azure_location" {
  type    = string
  default = "eastus"
}

# --- GCP ---
variable "gcp_project" {
  type    = string
  default = ""
}
variable "gcp_region" {
  type    = string
  default = "us-central1"
}
