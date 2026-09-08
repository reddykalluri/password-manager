# Tasks: add-iac-deployment

Ordered by dependency. The module contract (1.x) is fixed before per-cloud
modules; the pipeline (3.x) builds on a working `aws` module first, then fans out.

## 1. Contract & shared scaffolding
- [ ] 1.1 Define the per-cloud module contract (inputs: image digest, domain,
      sizing, backup + secret config; outputs: `service_url`, `database_endpoint`,
      `backup_bucket`, `registry_url`) in `deploy/modules/common-contract.md`
- [ ] 1.2 Root module `deploy/main.tf` selecting the module from `var.cloud`
      (`aws`|`azure`|`gcp`) and re-exporting the uniform outputs
- [ ] 1.3 Environment layout (`deploy/environments/{staging,prod}`) with tfvars +
      remote-state backend config; pin provider + module versions
- [ ] 1.4 `deploy/README.md`: prerequisites, `tofu init/plan/apply/destroy`, and
      the destroy retention guard for the bucket + database

## 2. Per-cloud modules
- [ ] 2.1 AWS module: App Runner/ECS Fargate + ACM/HTTPS, RDS PostgreSQL (private),
      S3 backup bucket, Secrets Manager, ECR, S3+DynamoDB state backend
- [ ] 2.2 Azure module: Container Apps + managed cert, Azure Database for
      PostgreSQL (private), Blob backup container, Key Vault, ACR, Storage state
      backend
- [ ] 2.3 GCP module: Cloud Run + managed cert, Cloud SQL PostgreSQL (private),
      GCS backup bucket, Secret Manager, Artifact Registry, GCS state backend
- [ ] 2.4 Cross-module conformance check: same outputs, private DB, private
      encrypted bucket, secrets only by reference (no plaintext in state)

## 3. Automated deployment pipeline
- [ ] 3.1 Image build/publish job: build `vault-server` with `postgres,s3`, tag by
      SHA, sign/attest, push to the selected registry by digest
- [ ] 3.2 Keyless auth: GitHub OIDC → AWS role / Azure federated credential / GCP
      Workload Identity, least-privilege per environment
- [ ] 3.3 `tofu plan` on PRs (surface plan, no changes) and `tofu apply` on the
      protected branch/approved environment
- [ ] 3.4 Deploy + health-gate on `/ready`; pre-deploy backup trigger
- [ ] 3.5 Promotion (`staging`→`prod`) and rollback-to-prior-digest actions

## 4. Verification & docs
- [ ] 4.1 End-to-end apply on each cloud: reachable HTTPS instance, `/ready` 200,
      web client served, a backup object present
- [ ] 4.2 Destroy verification per environment (with retention guard honoured)
- [ ] 4.3 Restore-into-fresh-environment drill (ties into backup/restore runbook)
- [ ] 4.4 Secret/credential audit: no plaintext secret or long-lived cloud key in
      state, CI logs, or the repo
- [ ] 4.5 Operator docs: `docs/cloud-hosting.md` (choose cloud, configure, deploy,
      promote, roll back, tear down) linked from the docs index
