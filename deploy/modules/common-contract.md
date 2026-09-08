# Per-cloud module contract

Every cloud module (`aws`, `azure`, `gcp`) implements the same interface so the
root module can select one with `var.cloud`. Adding a new cloud means satisfying
this contract.

## Inputs

| Variable | Type | Meaning |
|---|---|---|
| `environment` | string | Environment name (isolates all resources). |
| `image` | string | vault-server container image, pinned by digest. |
| `domain` | string | Public hostname (operator-owned). |
| `cpu` | string | vCPU for the container service. |
| `memory` | string | Memory for the container service. |
| `min_instances` | number | Minimum running instances (≥ 1). |
| `max_instances` | number | Autoscale ceiling. |
| _cloud-specific_ | | `location` (Azure), `region` (GCP); AWS uses the provider region. |

## Outputs

| Output | Meaning |
|---|---|
| `service_url` | Public HTTPS URL of the instance. |
| `database_endpoint` | Private managed-PostgreSQL endpoint (sensitive). |
| `backup_bucket` | Private, encrypted object-storage bucket/container for backups. |
| `registry_url` | Container registry the image is pushed to. |

## Invariants every module must uphold

- The container runs behind **managed HTTPS** on `domain`; no public plaintext port.
- PostgreSQL is **not publicly reachable**; the server reaches it privately.
- The backup bucket is **private and encrypted at rest**.
- Secrets (`VAULT_TOKEN_KEY`, `VAULT_OPERATOR_TOKEN`, database URL) come from the
  cloud **secret manager**; no secret value is written to state or logs.
- `VAULT_DATABASE_URL` points at the managed Postgres; `VAULT_PUBLIC_ORIGIN` is
  `https://<domain>`; health/readiness use `/health` and `/ready`.
