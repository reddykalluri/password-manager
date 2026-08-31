# autofill-integration

Cross-cutting fill and capture behaviour (high-level requirement 9): loading credentials into browsers and apps, and saving credentials submitted in them. Binds browser-extensions, mobile-clients, and desktop-clients.

## ADDED Requirements

### Requirement: In-browser form fill
Browser extensions SHALL detect login, registration, and password-change forms — including multi-step username-then-password flows and forms inside same-site iframes — and fill username, password, and TOTP fields on explicit user action (popup selection, in-field menu, or configurable keyboard shortcut). Automatic fill without a user gesture SHALL be off by default.

#### Scenario: Multi-step login
- GIVEN a site that asks for username on page one and password on page two
- WHEN the user fills on page one and proceeds
- THEN the extension offers the same item's password on page two without re-searching

#### Scenario: Cross-origin iframe defence
- GIVEN a login form inside an iframe whose origin differs from the top-level page
- WHEN a fill is requested
- THEN the extension warns and requires explicit confirmation naming both origins before filling

### Requirement: Domain matching and phishing resistance
Credential candidates SHALL be matched using the item's URI match rules against the page's actual origin, with base-domain matching computed via the Public Suffix List. Lookalike or non-matching origins SHALL never receive silent fills; offering a credential to a non-matching origin SHALL require an explicit, per-event user override.

#### Scenario: Phishing lookalike
- GIVEN an item for example.com
- WHEN the user visits examp1e.com with a visually similar login form
- THEN no credential is offered for fill, and searching manually shows a non-matching-site warning before any fill

### Requirement: Save and update capture in browsers
Extensions SHALL detect submitted credentials (including via password-change forms and JS-driven submissions where observable) and offer to save new items or update existing ones, deduplicating by base domain + username, with per-site and global never-ask options.

#### Scenario: Password change detected
- GIVEN an existing item for example.com and a password-change form submission
- WHEN submission is detected with a new password for the stored username
- THEN the extension offers "update existing item", and accepting records the old password in item history

### Requirement: Android system autofill
The Android app SHALL implement an AutofillService providing inline fill suggestions in native apps and browsers, keyed by app package/website association (Digital Asset Links honoured; unverified app-to-domain links flagged), biometric-gated when the vault is locked, and offering save when apps submit new credentials. It SHALL register with the Credential Manager API for passkey creation and assertion.

#### Scenario: Fill in a native app
- GIVEN the banking app's login screen and the service enabled
- WHEN the user focuses the username field
- THEN matching credentials appear as inline suggestions and selection fills both fields after biometric confirmation

### Requirement: iOS credential provider
The iOS app SHALL implement an AutoFill Credential Provider extension supplying password and passkey suggestions above the QuickType keyboard in Safari and native apps, using associated-domain matching with an explicit-search fallback for unmatched apps, biometric-gated, and supporting iOS save/update prompts routing new credentials into the vault.

#### Scenario: Safari on iPhone
- GIVEN the provider enabled in iOS Settings and a stored login for the visited site
- WHEN the user taps the username field in Safari
- THEN the credential appears above the keyboard and fills after Face ID confirmation

### Requirement: Fill telemetry stays local
Fill and save events MAY be counted locally for the user's own statistics (e.g. last-used ordering) but SHALL never be transmitted anywhere, including the self-hosted server, except as encrypted item metadata (last-used timestamp) within normal sync.

#### Scenario: Server-side inspection
- GIVEN a user filling credentials daily
- WHEN server traffic and storage are inspected
- THEN no per-site browsing or fill activity is visible beyond encrypted item updates
