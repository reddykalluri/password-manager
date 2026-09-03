# Browser extension

One MV3 WebExtension (`extension/`) for Chrome, Edge, and Firefox, built from a
single codebase and backed by `vault-core` compiled to WASM. Safari is packaged
via the macOS app (not built here — needs Xcode).

## Build & test

```bash
cd extension
npm install
npm run build      # → dist/ (Chrome/Edge), dist-firefox/ (Firefox), + zips
npm test           # vitest: matching/phishing, form detection, capture
npm run typecheck
```

`crates/vault-core-wasm/pkg` must exist first (build it with
`wasm-pack build crates/vault-core-wasm --target web --out-dir pkg --release`);
the build copies `vault_core_wasm_bg.wasm` into each output folder.

## Install locally (no store / developer account needed)

The build emits ready-to-load, unpacked extensions and sideload zips:

- `dist/` — Chrome / Edge
- `dist-firefox/` — Firefox
- `vault-extension-chrome.zip`, `vault-extension-firefox.zip`

**Chrome / Edge**
1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select `extension/dist`.
4. It persists across restarts. After `npm run build`, hit the extension's
   **Reload** button to update.

**Firefox** (temporary — until Firefox restarts)
1. Open `about:debugging#/runtime/this-firefox`.
2. **Load Temporary Add-on…** → pick `extension/dist-firefox/manifest.json`.
   For a persistent install, sign the zip with your own Mozilla account
   (`web-ext sign`) or use Developer/ESR Firefox with signature enforcement off.

**Native-messaging host (optional — delegate to the desktop app)**
A locally-loaded Chrome extension gets a generated ID (shown on the extensions
page). Add it to `crates/vault-nmh/src/allowlist.rs`, then:

```bash
cargo build -p vault-nmh --release
./target/release/vault-native-messaging-host install
```

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
