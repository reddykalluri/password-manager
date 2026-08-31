//! Persistence over sqlx/SQLite (PostgreSQL available via the `postgres`
//! feature). All access goes through [`Db`]; the server treats item content as
//! opaque ciphertext.

use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use vault_core::store::{ItemRecord, Revision};

use crate::error::{AppError, AppResult};
use crate::time_util::{now_rfc3339, parse_rfc3339, to_rfc3339};

/// An account row (server-visible fields only; no plaintext secrets).
#[derive(Debug, Clone)]
pub struct Account {
    pub id: Uuid,
    pub username: String,
    pub opaque_record: String,
    pub account_crypto: String,
    pub change_seq: i64,
    pub failed_logins: i64,
    pub lock_until: Option<OffsetDateTime>,
}

/// A registered device with its (hashed) refresh token.
#[derive(Debug, Clone)]
pub struct Device {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub refresh_token_hash: Option<String>,
    pub refresh_expires_at: Option<OffsetDateTime>,
}

/// Result of a versioned item write.
#[derive(Debug)]
pub enum WriteOutcome {
    Accepted { new_version: i64, cursor: i64 },
    Conflict { current: ItemRecord },
}

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Db")
    }
}

impl Db {
    /// Open (creating if missing) and migrate the database.
    pub async fn connect(database_url: &str) -> AppResult<Self> {
        // Ensure the SQLite parent directory exists for a fresh container volume.
        if let Some(path) = database_url.strip_prefix("sqlite://") {
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
        }
        let opts = SqliteConnectOptions::from_str(database_url)
            .map_err(|e| AppError::Config(format!("bad database url: {e}")))?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("migration failed: {e}")))?;
        Ok(Self { pool })
    }

    /// Cheap connectivity probe for the readiness endpoint.
    pub async fn ping(&self) -> AppResult<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    // --- accounts ----------------------------------------------------------

    pub async fn create_account(
        &self,
        username: &str,
        opaque_record: &str,
        account_crypto: &str,
        registration_via: &str,
    ) -> AppResult<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO accounts (id, username, opaque_record, account_crypto, registration_via, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(username)
        .bind(opaque_record)
        .bind(account_crypto)
        .bind(registration_via)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(dbe) if dbe.is_unique_violation() => {
                AppError::BadRequest("username already taken".into())
            }
            other => AppError::Db(other),
        })?;
        Ok(id)
    }

    pub async fn account_by_username(&self, username: &str) -> AppResult<Option<Account>> {
        let row = sqlx::query(
            "SELECT id, username, opaque_record, account_crypto, change_seq, failed_logins, lock_until
             FROM accounts WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        row.map(map_account).transpose()
    }

    pub async fn account_by_id(&self, id: Uuid) -> AppResult<Option<Account>> {
        let row = sqlx::query(
            "SELECT id, username, opaque_record, account_crypto, change_seq, failed_logins, lock_until
             FROM accounts WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(map_account).transpose()
    }

    pub async fn update_account_crypto(&self, id: Uuid, account_crypto: &str) -> AppResult<()> {
        sqlx::query("UPDATE accounts SET account_crypto = ? WHERE id = ?")
            .bind(account_crypto)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_login_failure(
        &self,
        id: Uuid,
        lock_until: Option<OffsetDateTime>,
    ) -> AppResult<i64> {
        let row = sqlx::query(
            "UPDATE accounts SET failed_logins = failed_logins + 1, lock_until = ?
             WHERE id = ? RETURNING failed_logins",
        )
        .bind(lock_until.map(to_rfc3339))
        .bind(id.to_string())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("failed_logins"))
    }

    pub async fn reset_login_failures(&self, id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE accounts SET failed_logins = 0, lock_until = NULL WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // --- devices -----------------------------------------------------------

    pub async fn create_device(&self, account_id: Uuid, name: &str) -> AppResult<Uuid> {
        let id = Uuid::new_v4();
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO devices (id, account_id, name, created_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(account_id.to_string())
        .bind(name)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn set_device_refresh(
        &self,
        device_id: Uuid,
        token_hash: &str,
        expires_at: OffsetDateTime,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE devices SET refresh_token_hash = ?, refresh_expires_at = ?, last_seen_at = ?
             WHERE id = ?",
        )
        .bind(token_hash)
        .bind(to_rfc3339(expires_at))
        .bind(now_rfc3339())
        .bind(device_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn device_by_refresh_hash(&self, token_hash: &str) -> AppResult<Option<Device>> {
        let row = sqlx::query(
            "SELECT id, account_id, name, refresh_token_hash, refresh_expires_at
             FROM devices WHERE refresh_token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(map_device).transpose()
    }

    pub async fn device_by_id(&self, device_id: Uuid) -> AppResult<Option<Device>> {
        let row = sqlx::query(
            "SELECT id, account_id, name, refresh_token_hash, refresh_expires_at
             FROM devices WHERE id = ?",
        )
        .bind(device_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(map_device).transpose()
    }

    pub async fn list_devices(&self, account_id: Uuid) -> AppResult<Vec<Device>> {
        let rows = sqlx::query(
            "SELECT id, account_id, name, refresh_token_hash, refresh_expires_at
             FROM devices WHERE account_id = ? ORDER BY created_at",
        )
        .bind(account_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(map_device).collect()
    }

    // --- items / sync ------------------------------------------------------

    /// Records changed after `cursor`, with the account's current cursor.
    pub async fn pull_since(
        &self,
        account_id: Uuid,
        cursor: i64,
    ) -> AppResult<(Vec<ItemRecord>, i64)> {
        let rows = sqlx::query(
            "SELECT item_id, vault_id, version, modified_at, deleted, sealed_json, history_json
             FROM items WHERE account_id = ? AND change_seq > ? ORDER BY change_seq",
        )
        .bind(account_id.to_string())
        .bind(cursor)
        .fetch_all(&self.pool)
        .await?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            records.push(map_item(&row)?);
        }
        let seq = self.account_cursor(account_id).await?;
        Ok((records, seq))
    }

    /// Fetch a single item scoped to its account. Returns `None` (→ 404) if the
    /// item does not exist *for this account*, so cross-tenant probes cannot
    /// distinguish "missing" from "belongs to someone else".
    pub async fn get_item(&self, account_id: Uuid, item_id: Uuid) -> AppResult<Option<ItemRecord>> {
        let row = sqlx::query(
            "SELECT item_id, vault_id, version, modified_at, deleted, sealed_json, history_json
             FROM items WHERE account_id = ? AND item_id = ?",
        )
        .bind(account_id.to_string())
        .bind(item_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(map_item).transpose()
    }

    pub async fn account_cursor(&self, account_id: Uuid) -> AppResult<i64> {
        let row = sqlx::query("SELECT change_seq FROM accounts WHERE id = ?")
            .bind(account_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("change_seq"))
    }

    /// Versioned write: accept a fast-forward (base_version == current), else
    /// return the current record for client-side merge (409).
    pub async fn push_item(
        &self,
        account_id: Uuid,
        record: &ItemRecord,
        base_version: i64,
    ) -> AppResult<WriteOutcome> {
        let mut tx = self.pool.begin().await?;

        let current: Option<(i64,)> =
            sqlx::query_as("SELECT version FROM items WHERE account_id = ? AND item_id = ?")
                .bind(account_id.to_string())
                .bind(record.id.to_string())
                .fetch_optional(&mut *tx)
                .await?;

        let current_version = current.map(|c| c.0).unwrap_or(0);
        if base_version != current_version {
            // Stale write: return the server's current record.
            let row = sqlx::query(
                "SELECT item_id, vault_id, version, modified_at, deleted, sealed_json, history_json
                 FROM items WHERE account_id = ? AND item_id = ?",
            )
            .bind(account_id.to_string())
            .bind(record.id.to_string())
            .fetch_one(&mut *tx)
            .await?;
            let current = map_item(&row)?;
            tx.rollback().await?;
            return Ok(WriteOutcome::Conflict { current });
        }

        // Fast-forward: bump the account cursor and upsert the row.
        let cursor_row = sqlx::query(
            "UPDATE accounts SET change_seq = change_seq + 1 WHERE id = ? RETURNING change_seq",
        )
        .bind(account_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        let cursor: i64 = cursor_row.get("change_seq");
        let new_version = current_version + 1;

        let sealed_json = match &record.sealed {
            Some(s) => {
                Some(serde_json::to_string(s).map_err(|e| AppError::Internal(e.to_string()))?)
            }
            None => None,
        };
        let history_json = serde_json::to_string(&record.history)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        sqlx::query(
            "INSERT INTO items (account_id, item_id, vault_id, version, modified_at, deleted, sealed_json, history_json, change_seq)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(account_id, item_id) DO UPDATE SET
                vault_id = excluded.vault_id,
                version = excluded.version,
                modified_at = excluded.modified_at,
                deleted = excluded.deleted,
                sealed_json = excluded.sealed_json,
                history_json = excluded.history_json,
                change_seq = excluded.change_seq",
        )
        .bind(account_id.to_string())
        .bind(record.id.to_string())
        .bind(record.vault_id.to_string())
        .bind(new_version)
        .bind(to_rfc3339(record.modified_at))
        .bind(record.deleted as i64)
        .bind(sealed_json)
        .bind(history_json)
        .bind(cursor)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(WriteOutcome::Accepted {
            new_version,
            cursor,
        })
    }

    // --- invites -----------------------------------------------------------

    pub async fn create_invite(
        &self,
        code: &str,
        expires_at: Option<OffsetDateTime>,
    ) -> AppResult<()> {
        sqlx::query("INSERT INTO invites (code, created_at, expires_at) VALUES (?, ?, ?)")
            .bind(code)
            .bind(now_rfc3339())
            .bind(expires_at.map(to_rfc3339))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Atomically consume an unused, unexpired invite. Returns true on success.
    pub async fn consume_invite(&self, code: &str, used_by: &str) -> AppResult<bool> {
        let res = sqlx::query(
            "UPDATE invites SET used_by = ? WHERE code = ? AND used_by IS NULL
               AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(used_by)
        .bind(code)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    // --- second factors ----------------------------------------------------

    pub async fn add_second_factor(
        &self,
        account_id: Uuid,
        kind: &str,
        material: &str,
    ) -> AppResult<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO second_factors (id, account_id, kind, material, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(account_id.to_string())
        .bind(kind)
        .bind(material)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn second_factors(&self, account_id: Uuid) -> AppResult<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT kind, material FROM second_factors WHERE account_id = ?")
            .bind(account_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get::<String, _>("kind"), r.get::<String, _>("material")))
            .collect())
    }

    // --- audit -------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn audit(
        &self,
        account_id: Option<Uuid>,
        device_id: Option<Uuid>,
        event: &str,
        ip: Option<&str>,
        detail: Option<&str>,
        scope: &str,
    ) -> AppResult<()> {
        sqlx::query(
            "INSERT INTO audit_log (id, account_id, device_id, event, ip, detail, scope, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(account_id.map(|a| a.to_string()))
        .bind(device_id.map(|d| d.to_string()))
        .bind(event)
        .bind(ip)
        .bind(detail)
        .bind(scope)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn audit_for_account(
        &self,
        account_id: Uuid,
        limit: i64,
    ) -> AppResult<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT event, ip, detail, created_at FROM audit_log
             WHERE account_id = ? AND scope = 'user' ORDER BY created_at DESC LIMIT ?",
        )
        .bind(account_id.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(map_audit).collect())
    }

    pub async fn audit_operator(&self, limit: i64) -> AppResult<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT event, ip, detail, created_at FROM audit_log
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(map_audit).collect())
    }

    // --- server config (singletons) ---------------------------------------

    pub async fn get_config(&self, key: &str) -> AppResult<Option<String>> {
        let row = sqlx::query("SELECT value FROM server_config WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("value")))
    }

    pub async fn set_config(&self, key: &str, value: &str) -> AppResult<()> {
        sqlx::query(
            "INSERT INTO server_config (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Raw pool access for backup (consistent snapshot).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

/// A redacted audit entry surfaced to clients/operators.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub event: String,
    pub ip: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

fn map_account(row: sqlx::sqlite::SqliteRow) -> AppResult<Account> {
    Ok(Account {
        id: parse_uuid(&row.get::<String, _>("id"))?,
        username: row.get("username"),
        opaque_record: row.get("opaque_record"),
        account_crypto: row.get("account_crypto"),
        change_seq: row.get("change_seq"),
        failed_logins: row.get("failed_logins"),
        lock_until: row
            .get::<Option<String>, _>("lock_until")
            .map(|s| parse_rfc3339(&s))
            .transpose()?,
    })
}

fn map_device(row: sqlx::sqlite::SqliteRow) -> AppResult<Device> {
    Ok(Device {
        id: parse_uuid(&row.get::<String, _>("id"))?,
        account_id: parse_uuid(&row.get::<String, _>("account_id"))?,
        name: row.get("name"),
        refresh_token_hash: row.get("refresh_token_hash"),
        refresh_expires_at: row
            .get::<Option<String>, _>("refresh_expires_at")
            .map(|s| parse_rfc3339(&s))
            .transpose()?,
    })
}

fn map_item(row: &sqlx::sqlite::SqliteRow) -> AppResult<ItemRecord> {
    let sealed = row
        .get::<Option<String>, _>("sealed_json")
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let history: Vec<Revision> = serde_json::from_str(&row.get::<String, _>("history_json"))
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(ItemRecord {
        id: parse_uuid(&row.get::<String, _>("item_id"))?,
        vault_id: parse_uuid(&row.get::<String, _>("vault_id"))?,
        version: row.get::<i64, _>("version") as u64,
        modified_at: parse_rfc3339(&row.get::<String, _>("modified_at"))?,
        deleted: row.get::<i64, _>("deleted") != 0,
        sealed,
        history,
    })
}

fn map_audit(row: sqlx::sqlite::SqliteRow) -> AuditEntry {
    AuditEntry {
        event: row.get("event"),
        ip: row.get("ip"),
        detail: row.get("detail"),
        created_at: row.get("created_at"),
    }
}

fn parse_uuid(s: &str) -> AppResult<Uuid> {
    Uuid::parse_str(s).map_err(|e| AppError::Internal(format!("bad uuid: {e}")))
}
