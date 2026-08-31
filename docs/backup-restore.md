# Backup and restore runbook

Backups are **consistent SQLite snapshots** produced with `VACUUM INTO`, which
serialises against writers without blocking readers. Every artifact contains
only ciphertext and wrapped keys — **no plaintext and no password-equivalent
verifier** — so it is safe to store off-host.

## What is backed up

- The entire database: accounts (OPAQUE records, wrapped keys), item
  ciphertext + history, devices, second factors, invites, and the audit log.
- Nothing decryptable without a user's master password or recovery code.

## Taking a backup

**Scheduled** — set `VAULT_BACKUP_INTERVAL_SECS` (e.g. `86400` for nightly).
Artifacts land in `VAULT_BACKUP_DIR` (default `/data/backups`) as
`vault-<timestamp>.db`.

**On demand** — operator endpoint:

```bash
curl -sX POST https://vault.example.com/api/v1/admin/backup \
  -H "x-operator-token: $VAULT_OPERATOR_TOKEN"
# => {"backup":"/data/backups/vault-2026-...-.db"}
```

**Off-site (S3-compatible)** — build the server with `--features s3` and set:

```
VAULT_BACKUP_S3_ENDPOINT=https://s3.us-west-1.amazonaws.com
VAULT_BACKUP_S3_BUCKET=my-vault-backups
VAULT_BACKUP_S3_REGION=us-west-1
VAULT_BACKUP_S3_ACCESS_KEY=...
VAULT_BACKUP_S3_SECRET_KEY=...
```

Each backup is then uploaded via a SigV4-signed PUT after it is written locally.
Works with AWS S3, MinIO, Backblaze B2, Wasabi, etc.

## Restoring (disaster recovery)

Restoring to a new host at the **same URL** lets clients resume sync after
re-authentication, with no data loss beyond the backup horizon.

1. Provision the new host and install the same server version.
2. Stop the service (so nothing writes the database):
   ```bash
   docker compose down
   ```
3. Place the chosen backup artifact as the live database file on the volume:
   ```bash
   # Copy the artifact into the vault-data volume as vault.db
   docker run --rm -v vault-data:/data -v "$PWD:/restore" debian:bookworm-slim \
     cp /restore/vault-2026-...-.db /data/vault.db
   ```
4. Ensure `VAULT_TOKEN_KEY` matches the previous deployment if you want existing
   access tokens to remain valid (otherwise clients simply re-authenticate).
5. Start the service and verify:
   ```bash
   docker compose up -d
   curl -fsS https://vault.example.com/ready
   ```
6. Clients re-authenticate (OPAQUE) and resume delta sync from their last cursor.

## Verifying a backup

Because artifacts are plain SQLite files, integrity can be checked offline:

```bash
sqlite3 vault-<timestamp>.db "PRAGMA integrity_check;"   # expect: ok
sqlite3 vault-<timestamp>.db "SELECT count(*) FROM accounts;"
```

## Recovery-code guidance (for account owners)

The server has **no password reset** — this is deliberate and the core of the
zero-knowledge guarantee. Each account's 128-bit recovery code (shown once at
enrolment) independently wraps the account key. Store it offline. Losing both
the master password and the recovery code means the data is unrecoverable, by
design; an operator restore cannot recover an individual's forgotten password.
