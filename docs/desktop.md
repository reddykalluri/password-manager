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

## Biometric unlock & updates

- **Touch ID unlock (macOS)** is implemented: on unlock the account key is
  exported (`vault_core::keys::KeyRing::export_account_key`) and stored in the
  Keychain (`src-tauri/src/biometric.rs`); `open_with_account_key` reconstructs
  the vault without the master password. A reboot invalidates the session (a
  master-password unlock is required again). Making retrieval actually **prompt
  Touch ID** and invalidate on biometric-enrolment change needs a
  `SecAccessControl` biometry flag + the app's biometric entitlement in a
  **signed, notarised** build (`entitlements.plist`).
- **Auto-update** is wired via `tauri-plugin-updater`; the updater public key and
  release endpoint are in `tauri.conf.json`. Set `TAURI_SIGNING_PRIVATE_KEY` at
  release time to sign update artifacts.
- **Signing/notarisation (macOS)**: set `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
  `APPLE_PASSWORD`, `APPLE_TEAM_ID` for `tauri build` to sign + notarise the DMG.

## Not finished in this environment

- **Signed + notarised DMG** (4.3) — code and config are in place, but producing
  one needs an Apple Developer certificate + notarisation, and verifying the
  Touch ID prompt needs a signed app on real hardware.
- **Windows** (4.2) — MSI/NSIS bundle targets are configured, but **Windows
  Hello / TPM unlock is not implemented** (needs a Windows host to write and
  test) and signing needs a Windows code-signing certificate.
