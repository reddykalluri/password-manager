# server

Self-hosted Rust service (axum/tokio): authentication, sync API, account lifecycle, backup, and operator administration. The server is untrusted with respect to secret content: it stores and serves ciphertext and verifies identity, nothing more.

## ADDED Requirements

### Requirement: Zero-knowledge storage boundary
The server SHALL persist only: OPAQUE registration records, wrapped keys, item ciphertexts, sync metadata, and account/device records. The server SHALL have no code path that receives, logs, or derives a master password, master key, or plaintext item content.

#### Scenario: Database exfiltration
- GIVEN an attacker obtains a full copy of the server database
- WHEN they attempt to recover credentials without a user's master password or recovery code
- THEN no item plaintext is recoverable and no password-equivalent verifier is available for offline guessing beyond the OPAQUE record's designed resistance

### Requirement: OPAQUE authentication
The server SHALL authenticate users via OPAQUE, issuing short-lived access tokens (≤15 minutes) and rotating refresh tokens bound to a registered device. Failed authentication SHALL be rate-limited per account and per source IP with exponential backoff.

#### Scenario: Online guessing
- GIVEN 10 consecutive failed login attempts for an account
- WHEN an 11th attempt arrives
- THEN the server delays the response per backoff policy and emits a security event to the audit log

### Requirement: WebAuthn second factor
The server SHALL support WebAuthn/FIDO2 security keys and platform authenticators as a second factor, and TOTP as a fallback second factor, enforced at login and before sensitive account operations (new-device enrolment, recovery-code regeneration, account deletion).

#### Scenario: New device enrolment
- GIVEN an account with 2FA enabled
- WHEN a sync request arrives from an unrecognised device after OPAQUE success
- THEN the server requires second-factor completion before issuing tokens, and notifies existing devices

### Requirement: Sync API
The server SHALL expose a versioned HTTPS API for delta sync per the protocol in design.md: clients fetch changes since a cursor, and push writes carrying the base version; stale writes are rejected with the current ciphertext. p95 latency for a delta-sync round trip with ≤100 changed items SHALL be under 300 ms excluding network.

#### Scenario: Stale write
- GIVEN a client pushing an item update based on version 7
- WHEN the server holds version 9
- THEN the write is rejected with a 409 carrying version 9's ciphertext and metadata for client-side merge

### Requirement: Multi-account tenancy
The server SHALL support multiple independent user accounts with strict data isolation. Registration SHALL be operator-controlled: closed by default, opened via invite links or a config flag.

#### Scenario: Cross-account access attempt
- GIVEN a valid session for account A
- WHEN it requests an item UUID belonging to account B
- THEN the server returns 404 without confirming the item exists

### Requirement: Deployment and operability
The server SHALL ship as a single OCI container (and bare static binary) configured by environment variables/file, using SQLite on a single mounted volume by default with PostgreSQL as a config option. It SHALL expose health and readiness endpoints and structured logs free of secret material, and SHALL run behind operator-supplied TLS (reverse proxy) or terminate TLS itself via config.

#### Scenario: First run
- GIVEN a fresh container with one mounted volume and minimal config
- WHEN the operator starts it and opens the web client
- THEN the instance initialises its database, serves the web client, and offers first-account creation within 60 seconds

### Requirement: Backup and restore
The server SHALL support online backup (consistent snapshot of the database and blobs to a local path or S3-compatible target on a schedule) and documented restore. Backups contain ciphertext only and SHALL be restorable to a new instance where clients resume sync after re-authentication.

#### Scenario: Disaster restore
- GIVEN a nightly backup and a destroyed host
- WHEN the operator restores the backup on a new host at the same URL
- THEN users authenticate and resume sync with no data loss beyond the backup horizon

### Requirement: Audit log
The server SHALL record security events (logins, failures, 2FA changes, device enrolments, exports of account data, admin actions) with timestamp, account, device, and source IP, viewable by the account owner for their own events and by the operator for instance-level events.

#### Scenario: User reviews activity
- GIVEN a user suspicious of account misuse
- WHEN they open security activity in any client
- THEN they see recent logins and device enrolments with time, device name, and coarse location/IP
