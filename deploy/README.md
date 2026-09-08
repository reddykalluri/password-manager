# Infrastructure as Code (OpenTofu)

Provision a `vault-server` instance on **AWS, Azure, or GCP** from one codebase.
`var.cloud` selects the implementation module; every module honours the same
[contract](modules/common-contract.md) (managed container behind HTTPS, private
managed PostgreSQL, private encrypted backup bucket, secret manager, registry).

## Layout

```
main.tf providers.tf variables.tf outputs.tf   # root: selects the cloud module
modules/{aws,azure,gcp}/                        # per-cloud implementations
environments/{staging,prod}.tfvars              # per-environment inputs
environments/backend.<cloud>.hcl.example        # remote-state templates
```

## Usage

```bash
cd deploy

# Validate (no cloud credentials needed):
tofu init -backend=false && tofu validate

# For a real deploy, configure remote state (recommended). Add a backend block
# for your cloud to a backend.tf, e.g.:  terraform { backend "s3" {} }
# then init with the matching template (replace ENV in the file first):
tofu init -backend-config=environments/backend.aws.hcl

# Plan / apply an environment:
tofu plan  -var-file=environments/staging.tfvars
tofu apply -var-file=environments/staging.tfvars

# Tear an environment down:
tofu destroy -var-file=environments/staging.tfvars
```

Outputs: `service_url`, `database_endpoint` (sensitive), `backup_bucket`,
`registry_url`.

## Notes

- **Secrets** (`VAULT_TOKEN_KEY`, `VAULT_OPERATOR_TOKEN`, database URL) are
  generated and stored in the cloud's secret manager and injected into the
  container at runtime — never written to `tofu` output. Treat the state file as
  sensitive regardless (it can hold generated values); use encrypted remote state.
- **Retention guard**: `prod` sets deletion protection on the database and
  keeps the backup bucket; destroying `prod` requires removing that protection
  first, on purpose.
- **Database**: cloud deployments use managed PostgreSQL (the server's `postgres`
  feature), not the SQLite default used for local/compose hosting.
- **DNS**: you supply `domain`; create the CNAME/alias to the service and, on AWS
  App Runner / Azure Container Apps, complete the domain-validation records the
  provider emits.
