-- Initial schema for the zero-knowledge sync server.
-- The server stores only ciphertext, wrapped keys, and sync metadata.

-- Server-wide singletons (e.g. the persistent OPAQUE ServerSetup).
CREATE TABLE IF NOT EXISTS server_config (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id                 TEXT PRIMARY KEY,
    username           TEXT NOT NULL UNIQUE,
    -- OPAQUE registration record (opaque bytes, base64).
    opaque_record      TEXT NOT NULL,
    -- AccountCrypto: salts, KDF params, wrapped account/vault keys (no plaintext).
    account_crypto     TEXT NOT NULL,
    -- Per-account monotonic change sequence powering delta sync cursors.
    change_seq         INTEGER NOT NULL DEFAULT 0,
    -- Failed-login accounting for per-account backoff.
    failed_logins      INTEGER NOT NULL DEFAULT 0,
    lock_until         TEXT,
    registration_via   TEXT NOT NULL,
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id                 TEXT PRIMARY KEY,
    account_id         TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    -- SHA-256 of the current refresh token (never the token itself).
    refresh_token_hash TEXT,
    refresh_expires_at TEXT,
    created_at         TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_account ON devices(account_id);

-- One row per item; content is opaque ciphertext.
CREATE TABLE IF NOT EXISTS items (
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    item_id      TEXT NOT NULL,
    vault_id     TEXT NOT NULL,
    version      INTEGER NOT NULL,
    modified_at  TEXT NOT NULL,
    deleted      INTEGER NOT NULL DEFAULT 0,
    -- Sealed current content (JSON of SealedBlob) or NULL for a tombstone.
    sealed_json  TEXT,
    -- Sealed prior revisions (JSON array).
    history_json TEXT NOT NULL DEFAULT '[]',
    -- Account-scoped change sequence for this row's latest write.
    change_seq   INTEGER NOT NULL,
    PRIMARY KEY (account_id, item_id)
);
CREATE INDEX IF NOT EXISTS idx_items_cursor ON items(account_id, change_seq);

-- Second factors: TOTP secrets and WebAuthn credentials (opaque JSON).
CREATE TABLE IF NOT EXISTS second_factors (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,          -- 'totp' | 'webauthn'
    material    TEXT NOT NULL,          -- encrypted/opaque per-kind payload
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_2fa_account ON second_factors(account_id);

CREATE TABLE IF NOT EXISTS invites (
    code        TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    used_by     TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    account_id  TEXT,                   -- NULL for instance-level operator events
    device_id   TEXT,
    event       TEXT NOT NULL,
    ip          TEXT,
    detail      TEXT,                   -- redacted JSON detail
    scope       TEXT NOT NULL,          -- 'user' | 'operator'
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_log(account_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_scope ON audit_log(scope, created_at);
