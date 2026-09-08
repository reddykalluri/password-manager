# Documentation

| Doc | What it covers |
|---|---|
| [self-hosting.md](self-hosting.md) | **Start here** — build from source, run your own instance (with/without Docker), connect clients, operator tasks (install, upgrade, backup, recovery). |
| [deployment.md](deployment.md) | Container deployment, full env-var reference, reverse-proxy TLS, registration control. |
| [cloud-hosting.md](cloud-hosting.md) | Deploy to AWS/Azure/GCP via the OpenTofu IaC (`deploy/`) and the CD pipeline. |
| [backup-restore.md](backup-restore.md) | Backup/restore runbook, S3 off-site, disaster recovery, recovery-code guidance. |
| [api.md](api.md) | Server HTTP API reference (auth/OPAQUE, 2FA, sync, admin). |
| [web.md](web.md) | Web client build + architecture + session hardening. |
| [desktop.md](desktop.md) | Tauri desktop app: native core, biometric unlock, updater, native messaging. |
| [extension.md](extension.md) | MV3 browser extension: local install, architecture. |
| [mobile.md](mobile.md) | UniFFI bindings and the Android/iOS apps. |
| [development.md](development.md) | Repo layout, per-surface build/test, CI, conventions. |

Design authority and threat model:
[design.md](../openspec/changes/add-password-manager/design.md). Progress:
[tasks.md](../openspec/changes/add-password-manager/tasks.md).
