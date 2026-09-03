# Browser extension

One MV3 WebExtension (`extension/`) for Chrome, Edge, and Firefox, built from a
single codebase and backed by `vault-core` compiled to WASM. Safari is packaged
via the macOS app (not built here — needs Xcode).

## Build & test

```bash
cd extension
npm install
npm run build      # → dist/ (load unpacked in the browser)
npm test           # vitest: matching/phishing, form detection, capture
npm run typecheck
```

`npm run build:wasm` in `web/` (or the desktop docs) must have produced
`crates/vault-core-wasm/pkg` first; the build copies `vault_core_wasm_bg.wasm`
into `dist/`.

## Architecture

- **Service worker** (`src/background.ts`) — holds the unlocked vault in
  extension-private WASM memory, syncs directly with the server (standalone), or
  **delegates to the desktop app** over native messaging (`vault-nmh`) when it is
  installed. No long-lived plaintext secrets are persisted.
- **Popup** (`src/popup/`) — matched-items-first, full-vault search, copy
  username/password, generator, and an inline new-item form pre-filled with the
  current site; shows save/update prompts.
- **Content script** (`src/content.ts`) — form detection (heuristics +
  `src/lib/curatedRules.ts`), fill **only on a user gesture** (shortcut or popup
  selection; no auto-fill), cross-origin iframe confirmation, and submission
  capture for save/update.
- **Logic (unit-tested)** — PSL domain matching + phishing/typosquat resistance
  (`src/lib/matching.ts`), form detection (`src/lib/formDetection.ts`), and
  save-capture dedupe + never-ask lists (`src/lib/capture.ts`).

## Status

- Implemented and unit-tested: 5.1 scaffold + WASM + standalone sync, 5.2 popup,
  5.3 detection/fill/iframe, 5.4 save/update capture, 5.5 PSL matching + phishing
  (hostile-page suite), 5.6 native-messaging delegation.
- **5.7 passkeys** — a non-interfering page-world hook observes WebAuthn calls
  and delegates to the platform; completing assertions *from* vault passkeys is
  not yet implemented.
- **5.8 Safari + per-store pipelines** — Safari packaging needs Xcode and store
  submission needs developer accounts (out of this environment).

Runtime browser behaviour (fill, native messaging, WASM in the service worker)
is not automatically tested here; load `dist/` unpacked to exercise it.
