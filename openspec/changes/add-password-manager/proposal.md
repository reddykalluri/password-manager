# Proposal: add-password-manager

## Why
Commercial password managers require trusting a third-party cloud with the most sensitive data a household or small team holds. A self-hosted, zero-knowledge alternative keeps custody of secrets with the operator while matching the daily-use ergonomics people expect: autofill in browsers and apps, native clients on every platform, and reliable sync.

## What Changes
Greenfield build. This change establishes eight capabilities:

1. **vault-core** — Rust library implementing the encrypted vault: key hierarchy, item model, CRUD, search, import/export, and the sync engine. Shared by every client and the server.
2. **server** — self-hosted Rust service: OPAQUE authentication, encrypted-blob sync API, WebAuthn second factor, backup, and operator administration.
3. **web-client** — browser-based client (WASM crypto) served by the self-hosted instance.
4. **desktop-clients** — Windows and macOS apps (Tauri 2) with OS keychain/biometric unlock and native-messaging host for extensions.
5. **mobile-clients** — Android and iOS/iPadOS apps with biometric unlock and platform autofill services.
6. **browser-extensions** — Chrome, Edge, Firefox, Safari extensions: detect, fill, and capture credentials; passkey support.
7. **autofill-integration** — cross-cutting fill/save behaviour: in-browser form fill, Android Autofill Framework, iOS Credential Provider (AutoFill), inline save prompts.
8. **accessibility** — WCAG 2.2 AA and responsive-design requirements binding on every client surface.

## Scope
- **In scope:** single-operator/household deployment, passwords, passkeys, secure notes, TOTP; offline-first sync; import from common competitors (CSV, Bitwarden JSON, 1Password 1PUX).
- **Out of scope (future changes):** multi-user organisations and item sharing, emergency access, CLI client, SSH-key agent, breach-monitoring integrations.

## Impact
- New repository, no existing specs affected. All requirement deltas are ADDED.
- Establishes the security architecture (zero-knowledge, OPAQUE, client-side encryption) that every future change must preserve. Any future change touching the key hierarchy or wire protocol MUST reference the threat model in `design.md`.

## Success Criteria
- A user can deploy the server with one container, enrol on all six client surfaces, and fill a credential in a browser and a native mobile app within 15 minutes of first launch.
- Server database leak alone yields nothing decryptable without a user's master password (verified by design review and test vectors).
- p95 unlock-to-fill under 500 ms on desktop; item list render under 100 ms for 5,000 items.
