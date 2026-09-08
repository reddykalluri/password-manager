# automated-deployment Specification

## Purpose
TBD - created by archiving change add-iac-deployment. Update Purpose after archive.

## Requirements

### Requirement: Build, sign, and publish the image
The pipeline SHALL build the `vault-server` OCI image (with the `postgres` and
`s3` features for cloud hosting), tag it immutably by commit SHA, generate an
updater/signature or attestation, and push it to the selected cloud's registry
(AWS ECR, Azure ACR, GCP Artifact Registry).

#### Scenario: Immutable image on merge
- GIVEN a merge to the release branch
- WHEN the pipeline runs
- THEN an image tagged with the commit SHA is pushed to the target registry and
  the deploy references that exact digest (never a mutable tag)

### Requirement: Keyless cloud authentication
The pipeline SHALL authenticate to the cloud using workload-identity federation
(GitHub OIDC → AWS IAM role / Azure federated credential / GCP Workload Identity),
with no long-lived cloud access keys stored in CI secrets. The federated
identity SHALL be scoped to the minimum permissions needed to push images and
apply the environment's infrastructure.

#### Scenario: No static cloud keys
- GIVEN the pipeline configuration and repository secrets
- WHEN they are inspected
- THEN there are no long-lived cloud access keys; the job assumes a short-lived
  federated identity at run time

### Requirement: Plan on proposal, apply on protected branch
The pipeline SHALL run `tofu plan` (read-only) on pull requests and surface the
plan for review, and SHALL run `tofu apply` only from a protected branch (or a
manually approved environment), gated by required checks. Infrastructure changes
SHALL never be applied directly from an unreviewed PR.

#### Scenario: PR shows a plan but does not apply
- GIVEN a pull request that changes `deploy/`
- WHEN CI runs
- THEN it posts/attaches the `tofu plan` output and makes no changes to any cloud
  environment

### Requirement: Deploy, promote, and roll back
After apply, the pipeline SHALL roll the container service to the new image
revision and verify health via `/ready` before marking the deploy successful. It
SHALL support promoting a verified build from `staging` to `prod` and rolling back
to a previous image digest without a code change.

#### Scenario: Failed health check blocks promotion
- GIVEN a new revision whose `/ready` does not become healthy within the timeout
- WHEN the deploy step runs
- THEN the deploy is marked failed, the previous healthy revision keeps serving
  traffic, and promotion to `prod` is not offered

#### Scenario: Rollback
- GIVEN a `prod` incident on the current revision
- WHEN the operator triggers rollback to a prior image digest
- THEN the service returns to that digest without rebuilding, and `/ready` passes

### Requirement: Pre-deploy backup
The pipeline SHALL trigger (or confirm) a database/blob backup before applying a
change that could affect data, so a failed upgrade can be restored per the
backup/restore runbook.

#### Scenario: Upgrade takes a backup first
- GIVEN a deploy that upgrades the running version
- WHEN it starts
- THEN a backup is taken (or verified fresh) before the new revision receives
  traffic
