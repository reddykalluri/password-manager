# Server HTTP API

Base path `/api/v1` (health probes are at the root). All bodies are JSON. The
server is zero-knowledge: it only ever receives OPAQUE messages, wrapped keys,
and item **ciphertext** — never a master password, derived key, or plaintext.

Authenticated endpoints require `Authorization: Bearer <access_token>`.

## Health

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | — | Liveness: `{"status":"ok"}`. |
| GET | `/ready` | — | Readiness (DB reachable): `{"status":"ready"}` or 503. |

## Authentication (OPAQUE)

Registration and login are two-round OPAQUE exchanges; the client runs the OPAQUE
math (via `vault-core-wasm` / `vault-mobile`) and sends only opaque base64
messages.

| Method | Path | Auth | Body → Response |
|---|---|---|---|
| POST | `/auth/register/start` | — | `{username, registration_request}` → `{registration_response}` |
| POST | `/auth/register/finish` | — | `{username, registration_upload, account_crypto, invite_code?, device_name}` → `AuthTokens` |
| POST | `/auth/login/start` | — | `{username, credential_request}` → `{flow_id, credential_response}` |
| POST | `/auth/login/finish` | — | `{flow_id, credential_finalization, device_name, totp_code?}` → `AuthTokens` **or** `{second_factor:{webauthn_flow_id, webauthn_challenge}}` |
| POST | `/auth/login/webauthn/finish` | — | `{webauthn_flow_id, credential, device_name}` → `AuthTokens` |
| POST | `/auth/refresh` | — | `{refresh_token}` → `AuthTokens` (rotates the refresh token) |

`AuthTokens = {account_id, device_id, access_token, refresh_token}`. Access tokens
are ≤15 min; refresh tokens are single-use and rotate.

**Login with 2FA:** if the account has TOTP, resend `login/finish` with
`totp_code`. If it has a security key, `login/finish` returns a `second_factor`
challenge — complete the WebAuthn assertion and call `login/webauthn/finish`.

**Errors:** `401 unauthorized`, `401 second_factor_required`, `403
registration_closed`, `429 rate_limited {retry_after_secs}`.

## Account & second factors

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/account/2fa/totp` | ✔ | `{secret, code}` — enrol TOTP after verifying a code. |
| POST | `/account/2fa/webauthn/register/start` | ✔ | Begin security-key registration → `{flow_id, challenge}`. |
| POST | `/account/2fa/webauthn/register/finish` | ✔ | `{flow_id, credential}` — store the credential. |
| POST | `/account/2fa/webauthn/stepup/start` | ✔ | Begin a step-up assertion → `{flow_id, challenge}`. |
| POST | `/account/2fa/webauthn/stepup/finish` | ✔ | `{flow_id, credential}` → `{stepup_token}` for a sensitive op. |
| GET | `/account/crypto` | ✔ | The account's wrapped-key material (to unlock). |
| PUT | `/account/crypto` | ✔ | `{account_crypto, totp_code?, stepup_token?}` — update wrapped keys (master-password change / new vault). Second factor enforced when enabled. |
| GET | `/account/activity` | ✔ | Recent security events for the caller. |
| GET | `/account/devices` | ✔ | The caller's registered devices. |

## Sync

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/sync?cursor=N` | ✔ | Records changed since cursor `N` → `{records, cursor}`. |
| POST | `/sync/push` | ✔ | `{record, base_version}` → `{new_version, cursor}`, or **409** `{error:"stale_write", current}` with the server's current record for client-side merge. |
| GET | `/sync/item/:id` | ✔ | One item scoped to the account (cross-tenant → 404). |

An `ItemRecord` is `{id, vault_id, version, modified_at, deleted, sealed?, history}`
where `sealed`/`history` are ciphertext (`{nonce, ciphertext}` base64).

## Operator (admin)

Gated by the `X-Operator-Token` header matching `VAULT_OPERATOR_TOKEN` (unset ⇒
admin disabled).

| Method | Path | Description |
|---|---|---|
| POST | `/admin/invite` | Mint a single-use invite → `{code}`. |
| GET | `/admin/activity` | Instance-level audit log. |
| POST | `/admin/backup` | Trigger an on-demand backup → `{backup: path}`. |

## Notes

- The client IP for rate limiting and audit logs is taken from
  `X-Forwarded-For` / `X-Real-IP` — set these only from a trusted reverse proxy.
- Cross-account access returns **404** (never confirms existence across tenants).
