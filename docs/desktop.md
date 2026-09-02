# Desktop app (Tauri 2)

The desktop app (`desktop/`) reuses the SvelteKit web UI (`web/`) and links
**vault-core natively** — all crypto runs in Rust, not WASM. The frontend picks
its backend at runtime (`web/src/lib/backend.ts`): native Tauri commands on the
desktop, WASM in a browser.

## Build

```bash
cd desktop
npm install                 # installs the Tauri CLI
npm run build:wasm 2>/dev/null || true   # not needed for native, only browser
npm run tauri build         # builds web/, then the native app + DMG (macOS)
# or: npm run dev           # live-reload against the web dev server
```

> Signing and notarisation (macOS) and MSI/MSIX signing (Windows) require the
> respective developer certificates and are **not** configured here. Unsigned
> builds run locally but Gatekeeper/SmartScreen will warn end users.

## Features

- **Tray / menu-bar** quick actions and a **global shortcut** (⌘/Ctrl+Shift+Space)
  that opens a frameless quick-search window (`/quick`). The quick window shares
  the desktop's native vault and never renders secrets while locked.
- **Instance onboarding**: first run prompts for the self-hosted instance URL
  (`/onboard`); API calls use the Tauri HTTP plugin to reach it cross-origin.
- **Memory/disk hygiene**: `mlockall` keeps secret pages out of swap where the
  OS permits; a scrubbing panic hook keeps secrets out of crash output; the
  on-disk cache is ciphertext only (verified by
  `crates/vault-core/tests/vault_core.rs::on_disk_cache_contains_no_plaintext`).

## Native-messaging host (browser extensions)

`crates/vault-nmh` is a standalone host that bridges browser extensions to the
desktop app over an allowlisted stdio channel, forwarding to the app via a
per-user Unix socket.

Install the host manifests (points browsers at the built binary):

```bash
cargo build -p vault-nmh --release
./target/release/vault-native-messaging-host install
```

This writes `au.com.rodoskosmos.vault.json` into the Chrome, Edge, and Firefox
NativeMessagingHosts directories. Only allowlisted extension IDs
(`crates/vault-nmh/src/allowlist.rs`) may talk to the host; replace the
placeholder IDs with the real published store IDs at packaging time.

## Not yet implemented

- **Windows** app (Hello/TPM unlock, MSI/MSIX, updater) — needs a Windows host.
- **Biometric unlock** (Touch ID / Secure Enclave, Windows Hello) — needs app
  signing + entitlements and real hardware to implement and verify.
