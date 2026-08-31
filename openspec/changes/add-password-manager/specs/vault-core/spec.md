# vault-core

Rust library providing the encrypted vault: cryptography, item model, CRUD, search, history, import/export, and the client side of sync. Compiled natively, to UniFFI bindings, and to WASM. Every requirement here binds all client surfaces, since they all link this crate.

## ADDED Requirements

### Requirement: Client-side encryption
The system SHALL encrypt all vault item content on the client using XChaCha20-Poly1305 under a vault key, with a unique random nonce per encryption, before any persistence or transmission. Plaintext item content SHALL never leave the client process.

#### Scenario: Item saved
- GIVEN an unlocked vault
- WHEN the user saves a login item
- THEN the item content is encrypted with the vault key and a fresh nonce
- AND only ciphertext and sync metadata (UUID, version, timestamp) are written to storage or sent to the server

### Requirement: Key hierarchy and derivation
The system SHALL derive the master key from the master password using Argon2id with parameters at or above the per-target minimums defined in design.md, and SHALL implement the master key → MUK → account key → vault key hierarchy such that a master-password change re-wraps the account key without re-encrypting items.

#### Scenario: Master password change
- GIVEN a vault of 5,000 items
- WHEN the user changes their master password
- THEN only the account-key wrapping is recomputed and uploaded
- AND no item ciphertext changes

### Requirement: Vault lock and memory hygiene
The system SHALL support explicit lock, auto-lock after a configurable idle timeout (default 5 minutes; configurable 30 seconds to never per client policy), and lock on OS sleep/screen-lock signals. On lock, all key material and decrypted content SHALL be zeroised in memory.

#### Scenario: Idle timeout
- GIVEN an unlocked vault with a 5-minute timeout
- WHEN 5 minutes pass without user interaction
- THEN the vault locks and derived keys are zeroised
- AND the next access requires master password or an enabled biometric unlock

### Requirement: Item model
The system SHALL support item types: login (username, password, URIs, TOTP secret, custom fields), secure note, passkey, and identity/card; plus per-item fields for folder, favourite flag, and tags. URIs SHALL carry a match rule (base domain, host, exact, never).

#### Scenario: Login with multiple URIs
- GIVEN a login item with URIs example.com (base domain) and app.example.com (host)
- WHEN a client requests candidates for https://app.example.com/signin
- THEN the item is offered, matched by the most specific rule

### Requirement: CRUD and search performance
The system SHALL provide create, read, update, soft-delete (bin with 30-day retention), and restore operations, and case-insensitive search across item titles, usernames, and URIs. Search over 5,000 items SHALL return in under 50 ms on reference desktop hardware and under 150 ms on reference mobile hardware.

#### Scenario: Search while typing
- GIVEN an unlocked vault of 5,000 items
- WHEN the user types a 3-character query
- THEN matching results render within the target latency without blocking the UI thread

### Requirement: Item history
The system SHALL retain the previous 20 revisions of each item's encrypted content, including revisions displaced by sync conflict resolution, and allow the user to view and restore a prior revision.

#### Scenario: Restore overwritten password
- GIVEN an item whose password was changed yesterday
- WHEN the user opens item history and restores the prior revision
- THEN the prior content becomes the current revision and the change is itself recorded in history

### Requirement: Password generator
The system SHALL generate passwords (length 8–128, character-class toggles, ambiguous-character exclusion) and passphrases (3–10 words, EFF wordlist, configurable separator) using a CSPRNG, and SHALL rate generated and stored passwords for strength (zxcvbn or equivalent).

#### Scenario: Generate on new item
- GIVEN the new-login form
- WHEN the user invokes the generator with defaults
- THEN a 20-character mixed-class password is produced and its strength rating shown

### Requirement: Offline-first sync engine
The system SHALL queue local changes while offline and synchronise per the protocol in design.md when connectivity returns, resolving conflicts last-writer-wins per item with the losing revision preserved in item history. A locked or offline client SHALL still open its local encrypted cache after unlock.

#### Scenario: Concurrent edit on two devices
- GIVEN the same item edited on phone (offline) and desktop (online)
- WHEN the phone reconnects and syncs
- THEN one revision wins by modification time
- AND the other revision appears in the item's history on both devices after next sync

### Requirement: Import and export
The system SHALL import from generic CSV, Bitwarden JSON, and 1Password 1PUX with a preview and per-row error reporting, and SHALL export the vault as encrypted JSON (password-protected) or plaintext CSV gated by master-password re-entry and an explicit warning.

#### Scenario: Plaintext export gate
- GIVEN an unlocked vault
- WHEN the user requests CSV export
- THEN the app requires master-password re-entry and displays a plaintext-risk warning before writing the file
