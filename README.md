# Zero-knowledge password manager

A self-hosted, zero-knowledge password manager. This repository currently
implements the two foundational capabilities from the
[`add-password-manager`](openspec/changes/add-password-manager/proposal.md)
change:

- **`vault-core`** — the Rust library shared by every client and the server:
  cryptography, key hierarchy, item model, encrypted store, search, history,
  password generation, the client side of sync, and import/export.
- **`vault-server`** — the self-hosted sync service: OPAQUE authentication,
  delta-sync API, multi-account isolation, audit log, and backup — shipped as an
  OCI container.

The web, desktop, browser-extension, and mobile clients are later sections of
the change and are not built here yet.

## Security model (summary)

The server is untrusted with respect to secret content. It stores only OPAQUE
registration records, wrapped keys, item **ciphertext**, and sync metadata. The
master password never leaves the device (OPAQUE PAKE); item content is encrypted
client-side with XChaCha20-Poly1305 under a key hierarchy rooted in Argon2id. See
[`design.md`](openspec/changes/add-password-manager/design.md) for the full
threat model.

## Layout

```
crates/vault-core     # shared vault library (native + WASM + UniFFI targets)
crates/vault-server   # axum sync server (SQLite default, Postgres feature)
docs/                 # deployment, backup/restore runbook
Dockerfile            # multi-stage build → slim runtime image
docker-compose.yml    # one-container, one-volume self-host example
scripts/first-run-test.sh  # 60-second first-run check
```

## Build & test

```bash
cargo test --workspace           # all unit + integration tests
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

`vault-core` also cross-compiles to `wasm32-unknown-unknown`,
`aarch64-apple-ios`, and `aarch64-linux-android` (see CI).

## Run the server

```bash
cp .env.example .env             # set VAULT_OPERATOR_TOKEN and VAULT_TOKEN_KEY
docker compose up -d
```

Then open the instance and create the first account. See
[`docs/deployment.md`](docs/deployment.md) for reverse-proxy TLS and
[`docs/backup-restore.md`](docs/backup-restore.md) for the backup/restore runbook.

## Crypto test vectors

Canonical known-answer vectors that every client re-implementation must match
live in
[`crates/vault-core/tests/vectors/crypto_vectors.json`](crates/vault-core/tests/vectors/crypto_vectors.json)
and are verified by `crates/vault-core/tests/crypto_vectors.rs`.

## Status vs the change

Section 1 (vault-core) **1.1–1.9** and Section 2 (server) **2.1–2.8** are
implemented and tested (OPAQUE, sync, multi-account isolation, TOTP + WebAuthn
second factors, audit, backup, container). The only outstanding item in this
scope is:

- **1.10** external cryptography review — a human, out-of-band activity.

Later sections (web/desktop/extension/mobile clients) are future work.
