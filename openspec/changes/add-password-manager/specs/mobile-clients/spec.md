# mobile-clients

Android (Kotlin/Compose) and iOS/iPadOS (Swift/SwiftUI) apps over vault-core UniFFI bindings. Inherit all vault-core and accessibility requirements. Platform autofill behaviour is specified in autofill-integration.

## ADDED Requirements

### Requirement: Platform coverage
The system SHALL provide an Android app (Android 10+, arm64-v8a primary) and an iOS app (iOS/iPadOS 16+) built as a single target with adaptive layouts: compact single-column on phones, multi-column list/detail on iPad and large-screen Android, with full support for split view and rotation.

#### Scenario: iPad layout
- GIVEN the app on a 13-inch iPad in landscape
- WHEN the user browses the vault
- THEN list and item detail render side by side, and the same app on an iPhone renders a navigable single column

### Requirement: Biometric unlock
The mobile apps SHALL offer unlock via Android BiometricPrompt (Class 3) and Face ID/Touch ID, implemented with a session key wrapped by a Keystore/Secure Enclave key requiring user authentication, with master-password fallback and re-entry required after device restart or biometric enrolment change.

#### Scenario: Biometric invalidation
- GIVEN biometric unlock enabled
- WHEN a new fingerprint is enrolled on the device
- THEN the wrapped session key is invalidated and the master password is required before biometrics can be re-enabled

### Requirement: Offline access
The mobile apps SHALL open the local encrypted cache after unlock with no network available, queueing edits for later sync, and SHALL indicate sync state (synced, pending, error) without interrupting use.

#### Scenario: Aeroplane mode
- GIVEN a device offline
- WHEN the user unlocks and edits an item
- THEN the edit succeeds locally and syncs automatically when connectivity returns

### Requirement: TOTP convenience
The mobile apps SHALL display live TOTP codes with remaining validity, copy on tap, and — where an autofill flow just filled a login with an attached TOTP secret — offer the current code for immediate paste.

#### Scenario: Two-step login
- GIVEN a login item with a TOTP secret filled via autofill
- WHEN the site prompts for the one-time code
- THEN the app surfaces the current code for copy/paste or autofill without reopening the vault

### Requirement: App-level privacy
The mobile apps SHALL mask app-switcher previews, block screenshots on secret-revealing screens on Android (FLAG_SECURE) and obscure them on iOS, and never include vault content in OS backups in plaintext (encrypted cache only, excluded from cloud backup where keys cannot be protected).

#### Scenario: App switcher
- GIVEN an unlocked vault showing a password
- WHEN the user swipes to the app switcher
- THEN the preview is masked and no secret is visible
