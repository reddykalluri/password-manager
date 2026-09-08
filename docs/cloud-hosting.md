# Cloud hosting (AWS / Azure / GCP)

Deploy the server to a public cloud with the Infrastructure-as-Code in `deploy/`
(OpenTofu) and the `Deploy` GitHub Actions workflow. One `cloud` variable
(`aws` | `azure` | `gcp`) selects the target; every cloud gets the same topology:
a managed container behind HTTPS, private managed PostgreSQL, a private encrypted
backup bucket, secrets in the cloud secret manager, a container registry, and
encrypted remote state.

See [`deploy/README.md`](../deploy/README.md) for the module details and
[`deploy/modules/common-contract.md`](../deploy/modules/common-contract.md) for
the per-cloud interface.

## Prerequisites

- OpenTofu 1.6+ and the selected cloud's CLI/credentials for local runs (CI uses
  OIDC — no static keys).
- A domain you control for the instance.
- A remote-state backend (S3 / Azure Storage / GCS) — templates in
  `deploy/environments/backend.<cloud>.hcl.example`.

## Deploy (local)

```bash
cd deploy
# 1. Pick your cloud + fill inputs in environments/staging.tfvars (cloud, image
#    digest, domain, region/subscription/project).
# 2. Configure remote state (add a backend block, then):
tofu init -backend-config=environments/backend.<cloud>.hcl
# 3. Plan and apply:
tofu plan  -var-file=environments/staging.tfvars
tofu apply -var-file=environments/staging.tfvars
# 4. Point your domain's DNS at the printed service, completing any validation
#    records the provider emits, then browse to https://<domain>.
```

`image` must be an immutable digest of the `vault-server` image built with the
`postgres` and `s3` features.

## Deploy (CI/CD)

The `Deploy` workflow:
- **Pull requests** touching `deploy/` run `tofu validate` + `plan` (read-only).
- **`workflow_dispatch`** (choose `cloud` + `environment`) authenticates via OIDC,
  builds and pushes the image by digest, takes a pre-deploy backup, `tofu apply`s,
  and verifies `/ready` before finishing. The `environment` gate lets you require
  reviewers before a `prod` apply.

Configure repository **variables** (not secrets — these are identifiers):
`AWS_DEPLOY_ROLE_ARN`/`AWS_REGION`, or `AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/
`AZURE_SUBSCRIPTION_ID`, or `GCP_WIF_PROVIDER`/`GCP_DEPLOY_SA`. No long-lived cloud
keys are stored.

## Promote & roll back

- **Promote** a verified staging build to prod: dispatch the workflow with
  `environment=prod` and the same image digest.
- **Roll back**: re-apply with a previous image digest
  (`-var="image=<old-digest>"`) — no rebuild. The container service shifts back to
  that revision and `/ready` is re-checked.

## Tear down

```bash
tofu destroy -var-file=environments/staging.tfvars
```

`prod` has deletion protection on the database and retains the backup bucket by
design; remove that protection deliberately before destroying prod. Restoring a
backup into a fresh environment follows
[backup-restore.md](backup-restore.md).

## Security

- Zero-knowledge is unchanged — the cloud stores only ciphertext + wrapped keys.
- Database is private (no public ingress); backup bucket is private + encrypted.
- Secrets live only in the cloud secret manager; CI uses OIDC federation.
