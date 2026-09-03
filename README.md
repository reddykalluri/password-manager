# Zero-knowledge password manager

A self-hosted, zero-knowledge password manager with clients across web, desktop,
browser, and mobile — all sharing one audited Rust core (`vault-core`). Tracks
the [`add-password-manager`](openspec/changes/add-password-manager/proposal.md)
OpenSpec change.

## Security model (summary)

The server is untrusted with respect to secret content. It stores only OPAQUE
registration records, wrapped keys, item **ciphertext**, and sync metadata. The
master password never leaves the device (OPAQUE PAKE); item content is encrypted
client-side with XChaCha20-Poly1305 under a key hierarchy rooted in Argon2id.
Every client links the same `vault-core`, so there is one implementation of the
cryptography and vault logic. See
[`design.md`](openspec/changes/add-password-manager/design.md) for the full
threat model.

## Components

| Path | What it is |
|---|---|
| `crates/vault-core` | Shared Rust vault: crypto, key hierarchy, item model, encrypted store, search, history, generator, client-side sync, import/export. |
| `crates/vault-server` | Self-hosted axum sync server: OPAQUE auth, delta-sync API, multi-account isolation, TOTP + WebAuthn 2FA, audit log, backup. Ships as an OCI container. |
| `crates/vault-core-wasm` | WASM + TypeScript bindings of `vault-core` (web client and browser extension) with an OPAQUE client. |
| `crates/vault-mobile` | UniFFI bindings of `vault-core` for Kotlin (Android) and Swift (iOS). |
| `crates/vault-nmh` | Native-messaging host bridging browser extensions to the desktop app (allowlisted). |
| `web/` | SvelteKit web client (WASM crypto in the browser). |
| `desktop/` | Tauri 2 desktop app reusing the web UI with **native** `vault-core` (macOS focus). |
| `extension/` | One MV3 WebExtension for Chrome/Edge/Firefox. |
| `docs/` | Deployment, backup/restore, desktop, mobile, and extension guides. |

## Build & test

```bash
# Rust workspace (core, server, wasm, mobile, native-messaging host)
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check

# Web client
cd web && npm install && npm run build:wasm && npm run build && npm run test:a11y

# Browser extension (Chrome/Edge + Firefox, loadable unpacked)
cd extension && npm install && npm run build && npm test

# Desktop app (macOS)
cd desktop && npm install && npm run tauri build

# Swift UniFFI binding test (macOS)
./scripts/swift-binding-test.sh
```

`vault-core` also cross-compiles to `wasm32-unknown-unknown`,
`aarch64-apple-ios`, and `aarch64-linux-android` (see CI).

## Running each surface

- **Server** — `cp .env.example .env` (set `VAULT_OPERATOR_TOKEN`,
  `VAULT_TOKEN_KEY`) then `docker compose up -d`. See
  [`docs/deployment.md`](docs/deployment.md) (reverse-proxy TLS) and
  [`docs/backup-restore.md`](docs/backup-restore.md) (runbook).
- **Web** — served by the instance; `web/npm run build` produces the static SPA.
- **Desktop** — [`docs/desktop.md`](docs/desktop.md).
- **Extension** — installs locally with no store account (Load unpacked /
  temporary add-on): [`docs/extension.md`](docs/extension.md).
- **Mobile** — UniFFI bindings and how the apps consume them:
  [`docs/mobile.md`](docs/mobile.md).

## Crypto test vectors

Canonical known-answer vectors every client re-implementation must reproduce
bit-for-bit live in
[`crates/vault-core/tests/vectors/crypto_vectors.json`](crates/vault-core/tests/vectors/crypto_vectors.json),
verified by `crates/vault-core/tests/crypto_vectors.rs`.

## Status vs the change

Progress is tracked in
[`tasks.md`](openspec/changes/add-password-manager/tasks.md). Summary:

| Section | State |
|---|---|
| **1. vault-core** | ✅ 1.1–1.9 done & tested. `1.10` external crypto review is a human, out-of-band activity. |
| **2. server** | ✅ 2.1–2.8 done & tested (OPAQUE, sync, isolation, TOTP + WebAuthn, audit, backup, container). |
| **3. web-client** | ✅ 3.1–3.5 done (WASM bindings, SvelteKit shell, session hardening, responsive, import/export). axe WCAG gate green on public pages. |
| **4. desktop** | ✅ 4.1, 4.3, 4.4, 4.5, 4.6 done (shell + native core, Touch ID unlock code + updater/signing config, native messaging, tray/shortcut, hygiene). ⬜ **4.2 Windows** needs a Windows host + cert. |
| **5. browser-extensions** | ✅ 5.1–5.6 done (MV3 build, popup, detection/fill, save-capture, PSL matching + phishing suite, native-messaging delegation). ⬜ **5.7** passkeys partial; **5.8** Safari/store needs Xcode + accounts. |
| **6. mobile-clients** | ✅ 6.1 UniFFI bindings done (Swift binding test green). ⬜ **6.2–6.7** apps need Android SDK / Xcode / store accounts. |
| **7. accessibility & hardening gates** | ⬜ not started (release-blocking manual audits, pen test, scenario runs, operator docs). |

### Verification boundaries (honest)

- The Rust workspace, the web build + axe gate, the extension build + unit tests,
  the desktop backend compile, and the Swift binding test are all **run and
  green** in this repo.
- Not verified in this environment: signed/notarised desktop builds, biometric
  prompts on real hardware, the extension running in a live browser, and the
  mobile apps (no Android SDK / Xcode). Those need the respective platform
  toolchains, certificates, or hardware.
