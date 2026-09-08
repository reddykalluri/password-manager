# Design: add-iac-deployment

## Context
The server is a single stateless container that needs a database, object storage
for backups, TLS, secrets, and a registry. We want one IaC codebase that stands
this up on AWS, Azure, or GCP, plus a pipeline that ships it. The dominant force
is *parity with a thin per-cloud seam*: shared intent, provider-specific
implementations behind one contract, so operators learn one workflow.

## Decision 1 — OpenTofu (Terraform-compatible), not per-cloud native
One HCL codebase using OpenTofu (drop-in for Terraform) with the official `aws`,
`azurerm`, and `google` providers.

**Why not** CloudFormation/ARM/Bicep/Deployment-Manager: those are single-cloud,
forcing three separate codebases. **Why not** Pulumi: fine choice, but HCL +
OpenTofu keeps the toolchain small and the state model simple. **Why not** a PaaS
like Fly.io: doesn't satisfy "AWS, Azure, and GCP".

## Decision 2 — Root module + per-cloud modules behind one contract
```
deploy/
  modules/
    common-contract.md        # the input/output interface every cloud implements
    aws/    azure/    gcp/     # each: compute + db + bucket + secrets + registry
  environments/
    staging/  prod/           # tfvars + backend config per environment
  main.tf                     # selects the module from var.cloud
```
`var.cloud` picks the module; the root exposes uniform outputs (`service_url`,
`database_endpoint`, `backup_bucket`, `registry_url`). Adding a cloud = a new
module implementing the contract. This directly satisfies "single-variable cloud
selection".

## Decision 3 — Managed serverless containers (default), managed Postgres
Compute per cloud: **AWS App Runner** (or ECS Fargate), **Azure Container Apps**,
**GCP Cloud Run** — all give managed HTTPS + custom domains + scale-from-low and
run an OCI image directly, honouring the "one container" promise without a
Kubernetes operator.

Because serverless containers have no durable local disk, cloud deployments use
**managed PostgreSQL** (RDS / Azure Database / Cloud SQL) via the server's
existing `postgres` feature — not the SQLite-on-a-volume default used for
local/compose hosting. The DB is private (VPC/VNet peering or the platform's
private egress); the server reaches it over the private network only.

**Alternative considered:** Kubernetes (EKS/AKS/GKE) — deferred; more moving
parts than a single container needs. The module contract leaves room to add a
`k8s` compute variant later.

## Decision 4 — Backups to native object storage
Backups target the cloud's object store: S3, Azure Blob, GCS. The server's `s3`
feature speaks S3 SigV4, which covers S3 and GCS (S3-interop); Azure Blob is
reached via its S3-compatible path or a small sidecar/CronJob using `az`/`azcopy`
where native. Buckets are private, versioned, and encrypted at rest. Restore
follows the existing `docs/backup-restore.md` runbook.

## Decision 5 — Secrets in the cloud secret manager
`VAULT_TOKEN_KEY`, `VAULT_OPERATOR_TOKEN`, and the database URL/credentials live
in AWS Secrets Manager / Azure Key Vault / GCP Secret Manager and are injected as
container secrets. Terraform references them by ARN/ID; values are created out of
band or marked non-persisted. Nothing secret is written to state or logs.

## Decision 6 — Remote, encrypted state per cloud
State backends: S3 + DynamoDB lock (AWS), Azure Storage (Azure), GCS (GCP), all
encrypted with locking. State is per environment (`staging`, `prod`) via backend
`key`/prefix. Provider and module versions are pinned for reproducibility.

## Decision 7 — CD via GitHub Actions with OIDC federation
The pipeline builds the image (with `postgres,s3` features), pushes to the
cloud's registry by immutable digest, runs `plan` on PRs and `apply` on the
protected branch, deploys the revision, and verifies `/ready`. It authenticates
with **workload-identity federation** (GitHub OIDC → AWS role / Azure federated
credential / GCP WIF) — no static cloud keys. Promotion (`staging`→`prod`) and
rollback (redeploy a prior digest) are pipeline actions; a backup is taken before
data-affecting applies.

## Risks
- **Azure Blob is not S3-native** — mitigated by the S3-interop path or a small
  backup sidecar; called out in the Azure module.
- **Serverless cold starts + Argon2 KDF** — auth does server-side OPAQUE only
  (light); the heavy KDF is client-side, so cold starts don't block crypto.
- **Cross-cloud drift** — the contract doc + a conformance checklist per module
  keep the three implementations aligned.

## Open Questions
- [ASSUMPTION] Default compute is managed serverless containers, not Kubernetes.
  Recorded as the default; revisit if HA/multi-region is needed.
- [ASSUMPTION] Cloud deployments use managed PostgreSQL (not SQLite), since
  serverless compute lacks durable local disk.
- [NEEDS CLARIFICATION] DNS: does the operator delegate a zone to the cloud
  (module manages records) or only provide a domain and create the CNAME/alias
  manually? Specs assume operator supplies the domain; record management is
  optional per module.
