# Tasks: add-password-manager

Ordered by dependency. Each numbered group is independently reviewable; nothing in 3+ starts until 1 is test-vector-complete.

## 1. vault-core foundation
- [x] 1.1 Workspace scaffolding: `vault-core`, `vault-server`, CI (fmt, clippy, audit, test matrix incl. wasm32 and iOS/Android cross-targets)
- [x] 1.2 Crypto layer: Argon2id KDF with per-target parameters, HKDF, XChaCha20-Poly1305 AEAD, zeroize integration; published test vectors
- [x] 1.3 Key hierarchy: enrolment, unlock, master-password change (account-key re-wrap), recovery-code wrap/unwrap
- [x] 1.4 Item model + encrypted local store: CRUD, soft delete/bin, folders/tags, URI match rules
- [x] 1.5 Search index (encrypted-at-rest) meeting latency targets; benchmark harness at 5,000 items
- [x] 1.6 Item history (20 revisions) and restore
- [x] 1.7 Password/passphrase generator + strength rating
- [x] 1.8 Sync engine (client side): change queue, cursor fetch, conflict resolution with history preservation
- [x] 1.9 Import (CSV, Bitwarden JSON, 1PUX) and export (encrypted JSON, gated CSV)
- [ ] 1.10 External cryptography review of 1.2–1.3 before any client ships

## 2. server
- [x] 2.1 axum service skeleton, config, health/readiness, structured logging with secret-redaction tests
- [x] 2.2 OPAQUE registration/login (`opaque-ke`), token issuance/rotation, device records, rate limiting
- [x] 2.3 WebAuthn + TOTP second factor; enforcement points for sensitive operations
- [x] 2.4 Sync API: cursor deltas, versioned writes, 409 stale-write path; sqlx over SQLite with Postgres feature
- [x] 2.5 Multi-account isolation + invite-gated registration; cross-tenant access tests
- [x] 2.6 Audit log (user- and operator-scoped views)
- [x] 2.7 Backup/restore (local + S3-compatible), restore runbook, tested end to end
- [x] 2.8 OCI image, compose example, reverse-proxy TLS docs; 60-second first-run test

## 3. web-client
- [x] 3.1 vault-core WASM build + TS bindings; KDF benchmark/parameter negotiation in browser
- [x] 3.2 SvelteKit shell: enrolment, unlock, list/detail, CRUD, search, generator, settings
- [x] 3.3 Session hardening: auto-lock, clipboard timed clear, strict CSP, zero external origins
- [x] 3.4 Responsive layouts (320 px→desktop); axe CI gate live from this task onward
- [x] 3.5 Import/export UI; security-activity view

## 4. desktop-clients
- [x] 4.1 Tauri 2 shell reusing web UI with native vault-core; instance-URL onboarding
- [ ] 4.2 Windows: Hello unlock via TPM-wrapped session key; signed MSI/MSIX; updater
- [ ] 4.3 macOS: Touch ID unlock via Secure Enclave; signed + notarised DMG; updater
- [x] 4.4 Native-messaging host (allowlisted extension IDs) + install/registration per browser
- [x] 4.5 Tray/menu-bar quick access with global shortcut
- [x] 4.6 Memory/disk hygiene pass: non-swappable secret pages, crash-report scrubbing, disk-inspection test

## 5. browser-extensions
- [ ] 5.1 MV3 scaffold (Chrome/Edge/Firefox from one build), WASM core, standalone unlock + direct sync
- [ ] 5.2 Popup: matched-items-first, search, copy, generator, inline new item
- [ ] 5.3 Content scripts: form detection (heuristics + updatable curated rules), fill on user gesture, multi-step flows, iframe origin checks
- [ ] 5.4 Save/update capture with dedupe and never-ask lists
- [ ] 5.5 PSL-based domain matching + phishing warnings; hostile-page test suite
- [ ] 5.6 Native-messaging delegation to desktop app
- [ ] 5.7 Passkey create/assert where hooks exist
- [ ] 5.8 Safari packaging inside macOS app; per-store submission pipelines

## 6. mobile-clients
- [ ] 6.1 UniFFI bindings + Kotlin/Swift wrapper libraries with binding tests
- [ ] 6.2 Android app: Compose UI (phone + large-screen), biometric unlock, offline cache, sync status
- [ ] 6.3 Android AutofillService + Credential Manager passkeys; save capture; Digital Asset Links handling
- [ ] 6.4 iOS app: SwiftUI adaptive UI (iPhone/iPad), Face ID/Touch ID unlock, offline cache
- [ ] 6.5 iOS Credential Provider extension: password + passkey fill, save/update routing
- [ ] 6.6 App privacy: switcher masking, FLAG_SECURE, backup exclusions; TOTP surfacing post-fill
- [ ] 6.7 Store/TestFlight distribution per resolved distribution question

## 7. accessibility and hardening gates (release-blocking)
- [ ] 7.1 Manual WCAG 2.2 AA audit per surface (screen readers per platform, keyboard-only runs)
- [ ] 7.2 Contrast/scaling/reduced-motion verification incl. 200% text and largest OS text sizes
- [ ] 7.3 Threat-model review vs design.md; penetration test of server + extension fill paths
- [ ] 7.4 End-to-end scenario runs: 15-minute deploy-to-fill, disaster restore, concurrent-edit conflict, phishing lookalike
- [ ] 7.5 Operator docs: install, backup/restore, upgrade, recovery-code guidance
