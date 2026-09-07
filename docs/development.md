# Development guide

## Repository layout

```
crates/
  vault-core        Rust vault library (crypto, keys, store, search, sync, import/export)
  vault-core-wasm   WASM + TypeScript bindings (web, extension) + OPAQUE client
  vault-mobile      UniFFI bindings (Kotlin/Swift) + OPAQUE client
  vault-nmh         native-messaging host (browser ↔ desktop)
  vault-server      axum sync server (SQLite default, Postgres feature)
web/                SvelteKit web client
desktop/            Tauri 2 desktop app (own workspace under src-tauri/)
extension/          MV3 browser extension
mobile/             Android (Kotlin/Compose) + iOS (Swift/SwiftUI) apps
docs/               these documents
openspec/           the change spec, design, and task tracker
scripts/            helper scripts (binding generation, tests, first-run)
```

The Rust workspace is `crates/*`. `desktop/src-tauri` is a **separate** workspace
(its own lockfile/target) so Tauri's deps don't affect the main one.

## Prerequisites

Rust 1.82+ (rustup), Node 20+, `wasm-pack`; optional Docker, and Android
Studio/Xcode for the mobile apps. See [self-hosting.md](self-hosting.md#1-prerequisites).

## Build & test each surface

```bash
# Rust workspace
cargo test --workspace
cargo clippy --workspace --all-targets      # CI runs with -D warnings
cargo fmt --all -- --check

# Extra feature/target coverage (as CI does)
cargo clippy -p vault-server --all-targets --features s3
cargo build -p vault-core --target wasm32-unknown-unknown

# Web client
cd web && npm install && npm run build && npm run test:a11y && cd ..

# Browser extension
cd extension && npm install && npm run build && npm test && cd ..

# UniFFI Swift binding test (macOS)
./scripts/swift-binding-test.sh
```

## Generated code

- **WASM bindings**: `web/npm run build:wasm` → `crates/vault-core-wasm/pkg`
  (gitignored; regenerated).
- **UniFFI bindings**: `./scripts/mobile-bindings.sh` → Kotlin into
  `mobile/android/.../uniffi/`, Swift into `mobile/ios/VaultCore/` (gitignored).

## The shared facade

`vault-core-wasm`, `vault-mobile`, and the desktop Tauri commands each expose the
**same JSON-string facade** over `vault-core` (enrol/unlock, CRUD, search,
history, generator, import/export, OPAQUE client). Keep them in sync when the
core API changes. The OPAQUE `CipherSuite` **must be identical** across the wasm,
mobile, and server crates or auth breaks.

## CI

`.github/workflows/ci.yml` runs on self-hosted runners: rustfmt, clippy,
cargo-audit (prebuilt, with `RUSTSEC-2023-0071` ignored — see `.cargo/audit.toml`),
the test suite, wasm/iOS/Android cross-builds of `vault-core`, and the web build +
axe accessibility gate.

## Environment gotchas

- `rust-toolchain.toml` pins the toolchain to avoid a rustup auto-update that can
  fail on some machines; CI installs cross-targets per job.
- If `cargo`/`rustc` aren't found in a shell, add the toolchain bin to `PATH`
  (e.g. `~/.rustup/toolchains/<channel>/bin`).
- Harmless `failed to write cache … Permission denied` warnings from cargo's
  registry index do not affect builds.

## Coding conventions

- Rust: workspace lints forbid `unsafe` (except the wasm/mobile binding crates,
  which need it for FFI); run `cargo fmt`. Secrets use zeroizing types
  (`SecretBytes`/`SecretVec`) and are never logged (server has a redaction layer).
- TypeScript: `svelte-check`/`tsc --noEmit` must pass; no external origins in the
  web client or extension.
