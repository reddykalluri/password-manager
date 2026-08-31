# Project: Self-Hosted Password Manager ("Vault")

## Purpose
A self-hosted, zero-knowledge password manager. The operator runs the server on their own infrastructure; all secrets are encrypted client-side and the server never holds plaintext credentials or the master password.

## Tech Stack
- **Core + server:** Rust (single workspace). Core crypto/vault logic in a shared crate (`vault-core`); server binary built on axum/tokio.
- **Storage:** SQLite by default (single-family self-host), PostgreSQL optional. Server stores ciphertext blobs only.
- **Crypto:** Argon2id (KDF), XChaCha20-Poly1305 (AEAD), HKDF-SHA256 (key derivation), X25519 (key exchange for future sharing), OPAQUE (password-authenticated key exchange — master password never leaves the device).
- **Web client:** TypeScript + SvelteKit; crypto via `vault-core` compiled to WASM.
- **Desktop (Windows/macOS):** Tauri 2 apps sharing `vault-core` natively and the web UI layer.
- **Mobile (Android/iOS/iPadOS):** Native shells — Kotlin/Jetpack Compose and Swift/SwiftUI — over `vault-core` via UniFFI bindings.
- **Browser extensions:** Single WebExtension (Manifest V3) codebase for Chrome, Edge, Firefox; Safari via safari-web-extension packaging. Core via WASM; optional native messaging to the desktop app.

## Conventions
- Offline-first clients; server is a sync and backup target, never required for read access to an unlocked local vault.
- All client UIs meet WCAG 2.2 AA and are responsive from 320 px up.
- Memory holding secrets is zeroised on lock (Rust `zeroize`); plaintext never written to disk, logs, or crash dumps.
- Semantic versioning; protocol versions negotiated at sync time.

## Structure
- `openspec/specs/` — canonical capability specs (empty at project start; populated when changes are archived)
- `openspec/changes/` — change proposals (active: `add-password-manager`)
