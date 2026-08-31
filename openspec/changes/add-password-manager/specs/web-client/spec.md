# web-client

Browser-based client served by the self-hosted instance. All cryptography runs client-side via vault-core WASM. Inherits all vault-core requirements and all accessibility requirements.

## ADDED Requirements

### Requirement: Full vault management in the browser
The web client SHALL provide enrolment, unlock, item CRUD, search, folders/tags, item history, password generator, import/export, and account security settings (2FA, devices, recovery code) — feature parity with desktop apps except OS-integration features (biometric unlock, native messaging, tray).

#### Scenario: Access from a borrowed machine
- GIVEN a user on a machine with no software installed
- WHEN they browse to their instance URL and authenticate with master password + second factor
- THEN they can retrieve, create, and edit items with all crypto performed in-browser

### Requirement: Client-side crypto via WASM
The web client SHALL perform all key derivation and item encryption/decryption in vault-core WASM. The master password and derived keys SHALL never be sent to the server or persisted; the encrypted vault cache MAY be held in memory only, with session state not surviving a hard reload beyond an encrypted service-worker cache that still requires unlock.

#### Scenario: Network inspection
- GIVEN a user unlocking and editing items
- WHEN all HTTPS request payloads are inspected
- THEN no plaintext secret or password-derived key material appears in any request

### Requirement: Session hardening
The web client SHALL auto-lock per vault-core policy, clear clipboard copies of secrets after a configurable interval (default 60 seconds) where the Clipboard API permits, set strict CSP with no third-party origins, and load no external resources — fully self-contained from the self-hosted origin.

#### Scenario: Copy password
- GIVEN a user copies a password to the clipboard
- WHEN 60 seconds elapse
- THEN the client clears the clipboard if the platform API allows, and indicates the timed clear in the UI

### Requirement: Responsive layout
The web client SHALL be usable from 320 px width upward: single-column list/detail on small screens, two-pane on ≥768 px, with all functions reachable on touch and pointer input alike.

#### Scenario: Phone browser
- GIVEN a 360 px-wide mobile browser
- WHEN the user searches and opens an item
- THEN list, detail, and actions are operable without horizontal scrolling
