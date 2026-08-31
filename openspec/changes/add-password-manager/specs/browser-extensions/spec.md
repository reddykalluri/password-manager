# browser-extensions

Single WebExtension (MV3) codebase for Chrome, Edge, and Firefox; Safari packaged via the macOS app. Fill/save behaviour is specified in autofill-integration; this capability covers the extension platform itself.

## ADDED Requirements

### Requirement: Browser coverage
The system SHALL ship extensions for Chrome (current −2), Edge (current −2), Firefox (current ESR and release), and Safari 17+, built from one codebase with per-browser packaging, delivering the same fill, save, search, and generator features on each.

#### Scenario: Feature parity check
- GIVEN the same release version on all four browsers
- WHEN the user fills a login, saves a captured credential, and generates a password
- THEN behaviour and UI are equivalent within platform constraints, and any browser-specific gap is documented in release notes

### Requirement: Standalone and delegated operation
The extension SHALL operate standalone (direct server sync, in-extension unlock) and, when the desktop app is installed, delegate unlock state and session handling to it over native messaging, verified by app/extension ID allowlists on both ends.

#### Scenario: No desktop app installed
- GIVEN a machine with only the browser extension
- WHEN the user unlocks with their master password
- THEN the extension syncs directly with the server and functions fully

### Requirement: Secret handling within extension architecture
Decrypted vault data SHALL exist only in extension-private memory while unlocked; the MV3 service worker SHALL hold no long-lived plaintext secrets, content scripts SHALL receive only the specific credential being filled after a user gesture, and no vault data SHALL be exposed to page JavaScript beyond the values written into form fields.

#### Scenario: Malicious page probing
- GIVEN a page containing hostile JavaScript
- WHEN the extension is present but the user has not initiated a fill
- THEN the page can read no vault data, item metadata, or unlock state

### Requirement: Popup vault access
The extension popup SHALL show items matched to the active tab first, with full-vault search, copy username/password/TOTP, password generator, and an inline new-item form pre-populated with the current site.

#### Scenario: Matched items first
- GIVEN 3 items matching the active tab's domain
- WHEN the user opens the popup
- THEN those 3 items appear at the top, with search over the full vault below

### Requirement: Passkey support
The extension SHALL offer to create, store, and use passkeys for WebAuthn requests in browsers that expose the necessary hooks, presenting a chooser when both platform and vault passkeys are available; where hooks are unavailable, it SHALL not interfere with platform passkey flows.

#### Scenario: Passkey login
- GIVEN a stored passkey for example.com
- WHEN the site issues a WebAuthn assertion request
- THEN the extension offers the vault passkey and completes the assertion after user confirmation
