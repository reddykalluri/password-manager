# iac-provisioning

Infrastructure-as-Code that provisions a production instance of the self-hosted
server on AWS, Azure, or Google Cloud from one codebase. The cloud stores only
ciphertext and wrapped keys; provisioning must not weaken that boundary.

## ADDED Requirements

### Requirement: Single-variable cloud selection
The IaC SHALL provision an equivalent instance on AWS, Azure, or Google Cloud
selected by a single `cloud` input (`aws` | `azure` | `gcp`), via a
provider-neutral root module that delegates to a per-cloud module implementing a
common contract (inputs: image ref, domain, sizing, backup + secret config;
outputs: service URL, database endpoint, backup bucket, registry URL). Adding a
new cloud SHALL only require implementing that contract.

#### Scenario: Same config, different cloud
- GIVEN a configuration that deploys successfully with `cloud = "aws"`
- WHEN the operator changes only `cloud` to `azure` (and cloud-account inputs)
- THEN the same instance is provisioned on Azure with equivalent topology and the
  root module exposes the same named outputs

### Requirement: Managed compute behind HTTPS
Each cloud module SHALL run the `vault-server` container on a managed container
service (e.g. AWS App Runner/ECS Fargate, Azure Container Apps, GCP Cloud Run)
reachable over operator-supplied-domain HTTPS with a managed certificate, with no
plaintext-HTTP public listener. Compute SHALL be configured from environment
variables/secrets and SHALL scale to at least one healthy instance with liveness
and readiness wired to `/health` and `/ready`.

#### Scenario: Reachable instance
- GIVEN a successful apply on any supported cloud
- WHEN a client requests `https://<domain>/ready`
- THEN it returns 200 over a valid TLS certificate, and the web client is served

### Requirement: Managed datastore and object-storage backups
Each cloud module SHALL provision a managed PostgreSQL database (AWS RDS, Azure
Database for PostgreSQL, GCP Cloud SQL) reachable privately by the server, and an
object-storage bucket (S3, Azure Blob, GCS) as the backup target. The database
SHALL NOT be publicly reachable, and the backup bucket SHALL be private with
encryption at rest. Backups contain ciphertext only.

#### Scenario: Backups land privately
- GIVEN a scheduled or on-demand backup on any supported cloud
- WHEN it runs
- THEN the artifact is written to the private, encrypted bucket, and the database
  has no public ingress

### Requirement: Secrets and credentials never in code or state
Secrets (token-signing key, operator token, database credentials) SHALL be stored
in the cloud's secret manager (AWS Secrets Manager, Azure Key Vault, GCP Secret
Manager) and injected into the container at runtime. No secret value SHALL appear
in the repository, in Terraform state, or in plan/apply output. Terraform state
SHALL be stored in an encrypted, access-controlled remote backend per cloud, with
state locking where the backend supports it.

#### Scenario: State inspection
- GIVEN a completed apply
- WHEN the remote state and CI logs are inspected
- THEN no plaintext secret is present (only secret-manager references/ARNs), and
  the state object is encrypted

### Requirement: Reproducible and destroyable environments
Provisioning SHALL be parameterised by environment (e.g. `staging`, `prod`) so
multiple isolated instances can coexist, pinned to explicit provider and module
versions for reproducibility. A destroy SHALL remove all resources an environment
created, with a documented, opt-in retention path for the backup bucket and
database to prevent accidental data loss.

#### Scenario: Teardown
- GIVEN a provisioned `staging` environment
- WHEN the operator runs destroy for `staging`
- THEN all its cloud resources are removed (subject to the documented retention
  guard), and `prod` is unaffected
