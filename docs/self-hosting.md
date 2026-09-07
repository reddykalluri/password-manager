# Self-hosting & building from source

This is the end-to-end guide to building the project and running your own
instance — either from source or as a container — and connecting every client to
it. For reverse-proxy TLS and env reference see [deployment.md](deployment.md);
for the backup/restore runbook and recovery-code guidance see
[backup-restore.md](backup-restore.md).

## 1. Prerequisites

| Tool | Version | For |
|---|---|---|
| Rust (rustup) | 1.82+ | server, core, wasm/mobile bindings |
| Node.js + npm | 20+ | web client, browser extension |
| `wasm-pack` | latest | building the WASM vault core |
| Docker (optional) | any | container deployment |

```bash
curl https://sh.rustup.rs -sSf | sh
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
# Node 20+ from your package manager or https://nodejs.org
```

## 2. Build & run the server

### Option A — from source (no Docker)

```bash
# 1. Build the web client the server will serve (WASM crypto + static SPA).
cd web
npm install
npm run build:wasm        # → crates/vault-core-wasm/pkg
npm run build             # → web/build  (static SPA)
cd ..

# 2. Run the server, pointing it at the web build and a local SQLite volume.
mkdir -p data
VAULT_BIND=127.0.0.1:8080 \
VAULT_DATABASE_URL="sqlite://$(pwd)/data/vault.db" \
VAULT_WEB_ROOT="$(pwd)/web/build" \
VAULT_REGISTRATION=open \
VAULT_TOKEN_KEY="$(openssl rand -hex 32)" \
VAULT_PUBLIC_ORIGIN="http://localhost:8080" \
cargo run --release -p vault-server
```

Open <http://localhost:8080>, and create the first account. Because the web
client is served by the instance it talks to it same-origin — no CORS, no extra
configuration.

> `VAULT_REGISTRATION=open` lets anyone sign up; for a locked-down instance leave
> it unset (invite-only) and mint invites (step 5).

### Option B — container (one image, one volume)

```bash
cp .env.example .env      # set VAULT_OPERATOR_TOKEN and VAULT_TOKEN_KEY
docker compose up -d
```

The image bundles the server; mount a web build at `/web` and set
`VAULT_WEB_ROOT=/web` if you want the instance to serve the web client too. See
[deployment.md](deployment.md) for TLS and the full env reference. Verify:

```bash
curl -fsS http://localhost:8080/health     # {"status":"ok"}
curl -fsS http://localhost:8080/ready      # {"status":"ready"}
```

PostgreSQL instead of SQLite: build with `--features postgres` and set
`VAULT_DATABASE_URL=postgres://…`.

## 3. Connect the clients

All clients perform their own crypto and talk to your instance URL.

- **Web** — just browse to the instance URL; it's served by the server.
- **Desktop** (`docs/desktop.md`) — first-run onboarding asks for the instance
  URL; it reaches it via the Tauri HTTP plugin.
- **Browser extension** (`docs/extension.md`) — load unpacked (no store account);
  the popup's unlock screen takes the instance URL.
- **Mobile** (`docs/mobile.md`) — the unlock screen takes the instance URL;
  build the apps in Android Studio / Xcode with the cross-compiled native lib.

## 4. Build everything (verification)

```bash
cargo test --workspace                     # Rust: core, server, wasm, mobile, nmh
cargo clippy --workspace --all-targets
cd web && npm run build && npm run test:a11y && cd ..
cd extension && npm install && npm run build && npm test && cd ..
./scripts/swift-binding-test.sh            # macOS: UniFFI Swift bindings
```

## 5. Operator tasks

### First run & registration control
Registration is **closed by default**. Mint a single-use invite (needs
`VAULT_OPERATOR_TOKEN` set):

```bash
curl -sX POST http://localhost:8080/api/v1/admin/invite \
  -H "x-operator-token: $VAULT_OPERATOR_TOKEN"
# → {"code":"…"}  — share it; the client supplies it during enrolment.
```

### Backups & restore
Set `VAULT_BACKUP_DIR` (+ `VAULT_BACKUP_INTERVAL_SECS` for a schedule), or trigger
on demand via `POST /api/v1/admin/backup`. Off-site to S3 by building with
`--features s3` and setting the `VAULT_BACKUP_S3_*` vars. Full procedure and
disaster recovery: [backup-restore.md](backup-restore.md).

### Upgrade
Backups are ciphertext-only and the schema migrates forward automatically on
start, so upgrades are low-risk:

1. **Back up first** (`POST /api/v1/admin/backup` or take a copy of the volume).
2. Pull the new version:
   - container: `docker compose pull && docker compose up -d` (migrations run on
     boot);
   - from source: `git pull`, rebuild (`cargo build --release -p vault-server`,
     and rebuild `web/` if serving it), restart.
3. Verify `GET /ready` returns 200 and clients still sync.
4. Roll back by restoring the pre-upgrade backup onto the previous version — keep
   `VAULT_TOKEN_KEY` stable so existing sessions survive (otherwise clients just
   re-authenticate).

Client apps (desktop) check for updates against the release feed configured in
`desktop/src-tauri/tauri.conf.json`; the web client updates whenever the served
build is replaced.

### Recovery codes (share with users)
Each account's 128-bit recovery code is shown **once** at enrolment and
independently unwraps the account key. There is deliberately **no server-side
password reset** — losing both the master password and the recovery code means
the data is unrecoverable. Users should store the recovery code offline; it can
be regenerated from Settings while unlocked. See
[backup-restore.md](backup-restore.md#recovery-code-guidance-for-account-owners).

## 6. Security notes

- The server is zero-knowledge: it stores only ciphertext, wrapped keys, and
  sync metadata (see [design.md](../openspec/changes/add-password-manager/design.md)).
- Always run behind TLS in production (reverse proxy or the container's own TLS);
  only expose `127.0.0.1` to the proxy.
- Keep `VAULT_TOKEN_KEY` and `VAULT_OPERATOR_TOKEN` secret and stable.
