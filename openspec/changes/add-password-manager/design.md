# Design: add-password-manager

## Context
Zero-knowledge self-hosted password manager across server, web, two desktop OSs, two mobile OSs, and four browsers. The dominant design force is that one correct, audited implementation of the cryptography and vault logic must serve every surface — divergent per-platform reimplementations are the main historical source of password-manager vulnerabilities.

## Decision 1 — Rust core shared everywhere
`vault-core` is a Rust crate compiled to:
- native (server, Tauri desktop apps),
- UniFFI bindings (Kotlin, Swift for mobile),
- WASM (web client, browser extensions).

**Why Rust over C++:** memory safety without a GC (secrets zeroised deterministically via `zeroize`), first-class WASM and FFI tooling (wasm-bindgen, UniFFI), mature audited crypto crates (RustCrypto, `opaque-ke`), single toolchain across all targets. C++ offers no offsetting advantage here.

**Trade-off:** WASM crypto in the web client is slower than native and constrained by browser memory-protection limits; accepted, with Argon2id parameters tuned per target (see Decision 3).

## Decision 2 — Zero-knowledge key hierarchy
```
master password ──Argon2id──► master key (never leaves device, never sent)
master key ──HKDF──► master unlock key (MUK)
account key (random 256-bit, generated at enrolment) ─ encrypted by MUK
vault key (random, per vault) ─ encrypted by account key
item ciphertext ─ XChaCha20-Poly1305 under vault key, per-item random nonce
```
- Server stores: OPAQUE registration record, encrypted account key, encrypted vault keys, item ciphertexts, and unencrypted sync metadata (item UUIDs, version counters, timestamps) only.
- Authentication is OPAQUE (PAKE): the server can verify the user without ever receiving the master password or a password-equivalent hash. Losing the server database does not enable offline guessing against a strong-parameter Argon2id + OPAQUE record pairing.
- Master-password change re-wraps the account key only — no re-encryption of items.
- Recovery: 128-bit recovery code generated at enrolment, shown once; wraps the account key independently. No recovery code + no password = data loss, stated plainly to the user. There is deliberately no server-side reset.

## Decision 3 — KDF parameters per target
Argon2id: 64 MiB / t=3 / p=4 minimum on native; 48 MiB / t=3 on WASM and older mobile devices, renegotiated upward automatically when the client detects capable hardware. Parameters stored alongside the ciphertext; upgrades applied at next unlock.

## Decision 4 — Server: axum + SQLite default
Single static binary + SQLite file keeps the self-host promise honest (one container, one volume). `sqlx` abstracts the store so PostgreSQL is a config option, not a fork. Blob-oriented schema: the server never parses item content, so schema churn is confined to metadata.

## Decision 5 — Sync protocol
Offline-first, state-based sync:
- Every item carries `(uuid, version, modified_at, tombstone)`.
- Client pushes local changes with the base version; server accepts fast-forwards, rejects stale writes with the current ciphertext so the client can merge.
- Conflicts resolve client-side: last-writer-wins per item by default, with the losing revision preserved in item history (encrypted) — no silent data loss.
- Deletes are tombstones, purged after 90 days.

## Decision 6 — Desktop via Tauri 2
Shares the SvelteKit UI layer with the web client and links `vault-core` natively (no WASM penalty). Native pieces per OS: Windows Hello / Touch ID unlock via OS keystore-wrapped session key, tray/menu-bar quick access, and the native-messaging host binary that browser extensions call for unlock state and biometric-gated fills.

**Alternative considered:** fully native (WinUI/AppKit) — rejected for this change; doubles UI effort for marginal gain, revisit if webview accessibility proves insufficient (accessibility spec is the gate).

## Decision 7 — Mobile native shells, platform autofill
- Android: Kotlin/Compose app + `AutofillService` implementation; Credential Manager API for passkeys.
- iOS/iPadOS: SwiftUI app + AutoFill Credential Provider extension (`ASCredentialProviderViewController`); passkeys via Authentication Services. iPad gets multi-column adaptive layout, not a scaled phone UI.
- Both use UniFFI bindings; the credential-provider extensions share the same core and unlock via biometric-gated keys in Keystore/Secure Enclave.

## Decision 8 — Extensions: one MV3 codebase
Chrome/Edge/Firefox from one WebExtension build (Firefox MV3 with an event-page fallback where needed); Safari via `safari-web-extension-converter`, distributed inside the macOS app. Content scripts handle field detection and fill; the service worker holds no secrets — the unlocked vault lives in extension memory only while unlocked, or is delegated to the desktop app over native messaging when present. Passkey (WebAuthn) requests intercepted and satisfied from the vault where the browser exposes the hooks.

## Decision 9 — Fill/save architecture (requirement 9)
Three paths, in preference order per platform:
1. OS-level autofill (Android AutofillService, iOS Credential Provider) — covers native apps and mobile browsers.
2. Browser extension content-script fill — covers desktop browsers, with heuristic + curated-rules field matching and explicit user gesture for autofill-on-page-load disabled by default (credential-scraping defence).
3. Save capture: extension and OS services detect submitted credentials and offer to save/update, deduplicating against existing items by domain + username.
Domain matching uses the Public Suffix List; fills across origins require explicit confirmation.

## Risks
- **Safari extension + Apple review friction** — mitigated by shipping Safari support inside the notarised macOS app rather than standalone.
- **WASM side-channels in web client** — documented as the weakest surface; desktop/extension-with-native-host is the recommended path, web client positioned for access-anywhere.
- **Field-detection quality** drives perceived product quality — curated rules shipped as updatable data, not code.

## Open Questions
- [NEEDS CLARIFICATION] Single-user only at v1, or multiple independent accounts on one server (family) from day one? Specs below assume multiple accounts, no sharing.
- [NEEDS CLARIFICATION] TOTP storage in the same vault: include at v1 (specced in) or defer?
- [NEEDS CLARIFICATION] Target distribution channels: public app stores vs sideload/TestFlight for personal use — affects signing and review timelines, not architecture.
