# desktop-clients

Windows and macOS applications (Tauri 2, native vault-core, shared UI layer). Inherit all vault-core and accessibility requirements.

## ADDED Requirements

### Requirement: Platform coverage and distribution
The system SHALL provide a Windows app (Windows 10 22H2+, x64 and ARM64, signed MSI/MSIX) and a macOS app (macOS 13+, universal binary, signed and notarised DMG), each with in-app update checks against the operator's instance or the public release feed.

#### Scenario: macOS install
- GIVEN a downloaded release DMG
- WHEN the user installs and launches it on macOS 14
- THEN Gatekeeper accepts the notarised app and first-run setup connects to the user's instance URL

### Requirement: Biometric and OS-credential unlock
The desktop apps SHALL offer unlock via Windows Hello and Touch ID/Apple Watch respectively, implemented by wrapping a vault session key in the OS keystore (TPM-backed on Windows, Secure Enclave on macOS), gated so that master-password unlock is still required after reboot, biometric change, or a configurable interval (default 30 days).

#### Scenario: Touch ID unlock
- GIVEN biometric unlock enabled and a prior master-password unlock this boot
- WHEN the user opens the locked app and authenticates with Touch ID
- THEN the vault unlocks without the master password
- AND after a reboot the master password is required once before biometrics resume

### Requirement: Native messaging host for extensions
The desktop apps SHALL install and register a native-messaging host for Chrome, Edge, and Firefox (and the Safari app extension on macOS) so browser extensions can query unlock state, request fills, and trigger biometric-gated unlock. The host SHALL verify the calling extension ID against an allowlist.

#### Scenario: Extension unlock delegation
- GIVEN the desktop app unlocked and the extension locked
- WHEN the user invokes the extension in Chrome
- THEN the extension obtains its session from the desktop app over native messaging without a second master-password entry

### Requirement: Quick access and global shortcut
The desktop apps SHALL provide a tray (Windows) / menu-bar (macOS) quick-search window on a configurable global shortcut, supporting search, copy username/password/TOTP, and open-URL, dismissing on focus loss and never rendering secrets while locked.

#### Scenario: Fill into a non-browser app
- GIVEN a native application login form and an unlocked vault
- WHEN the user hits the global shortcut, finds the item, and copies the password
- THEN the credential is available on the clipboard with the timed clear applied

### Requirement: Local data protection
The desktop apps SHALL store only the encrypted vault cache and settings on disk under per-user OS paths, mark secret-bearing memory non-swappable where the OS permits, and exclude secrets from crash reports.

#### Scenario: Disk inspection
- GIVEN a powered-off machine
- WHEN its disk is examined
- THEN no plaintext vault content is present in app data, temp files, or logs
