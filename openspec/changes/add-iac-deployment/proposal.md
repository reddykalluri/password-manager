# Proposal: add-iac-deployment

## Why
The self-hosted server currently ships as an OCI image with a Docker Compose
example (task 2.8). Operators who want to run it on a public cloud must hand-wire
compute, TLS, a database, object storage, secrets, and a registry — differently
on each provider. This change adds Infrastructure-as-Code so an operator can
stand up (or tear down) a production-grade instance on **AWS, Azure, or Google
Cloud** by setting one variable, and can ship new versions through an **automated
pipeline** — without weakening the zero-knowledge guarantees (the cloud still
only ever stores ciphertext).

## What Changes
Two new capabilities, delivered as code under `deploy/`:

1. **iac-provisioning** — one OpenTofu/Terraform codebase with a provider-neutral
   root module and per-cloud implementation modules (`aws`, `azure`, `gcp`)
   behind a common contract. A single `cloud` input selects the target
   ("dynamic"). Each module provisions: a managed container service running the
   `vault-server` image behind managed HTTPS, a managed PostgreSQL database,
   an object-storage bucket for backups, a secrets store, a container registry,
   and remote Terraform state.
2. **automated-deployment** — a CI/CD pipeline (GitHub Actions) that builds and
   signs the OCI image, pushes it to the selected cloud's registry, runs
   `tofu plan`/`apply`, deploys the new revision, and supports promotion across
   environments and rollback — authenticating to the cloud via OIDC (no
   long-lived cloud keys in CI).

## Scope
- **In scope:** single-instance/household deployment per environment on one of
  the three clouds; managed compute + managed Postgres + object-storage backups +
  managed TLS + secret manager; remote state; a reusable CD pipeline; `plan` on
  PRs and `apply` on protected branches; teardown.
- **Out of scope (future changes):** multi-region/active-active HA, Kubernetes
  operators, on-prem/bare-metal IaC, cost-optimisation autoscaling policies, and
  managing DNS registrars (operator supplies the domain/zone).

## Impact
- New `deploy/` tree; no application code changes required. The server already
  supports PostgreSQL (`--features postgres`) and object-storage backups
  (`--features s3`), which these modules target.
- Establishes the deployment contract every environment uses; future
  cloud/compute additions must implement the same module interface.
- Security posture: secrets live in the cloud secret manager (never in state or
  CI logs); CI uses workload-identity federation; state is encrypted and access-
  controlled. The zero-knowledge boundary is unchanged — cloud infrastructure
  handles only ciphertext + wrapped keys.

## Success Criteria
- `cloud=aws|azure|gcp` + a domain is the only material difference to deploy the
  same instance on any of the three providers from one codebase.
- A green pipeline run builds the image, applies infrastructure, and serves a
  reachable HTTPS instance whose `/ready` returns 200, with backups landing in
  object storage.
- Destroying an environment removes all its cloud resources; restoring a backup
  into a fresh environment resumes service (ties into the backup/restore runbook).
- No plaintext secret or long-lived cloud credential appears in Terraform state,
  CI logs, or the repository.
