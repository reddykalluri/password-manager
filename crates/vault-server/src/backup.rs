//! Backup and restore (spec: Backup and restore).
//!
//! Backups are consistent SQLite snapshots produced with `VACUUM INTO`, which
//! serialises against writers without blocking readers. Artifacts contain only
//! ciphertext and wrapped keys, so they are safe to store off-host. Targets:
//! a local directory (always available) and, behind the `s3` cargo feature, any
//! S3-compatible object store. Restore is an operator action documented in the
//! runbook (`docs/backup-restore.md`): stop the service, drop the artifact in
//! place as the database file, and start.

use time::OffsetDateTime;

use crate::error::{AppError, AppResult};
use crate::state::SharedState;
use crate::time_util::to_rfc3339;

/// Produce a consistent backup artifact and return its local path. If an S3
/// target is configured (and the `s3` feature is built), the artifact is also
/// uploaded.
pub async fn run_backup(state: &SharedState) -> AppResult<String> {
    let dir = std::env::var("VAULT_BACKUP_DIR").unwrap_or_else(|_| "data/backups".into());
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Internal(format!("cannot create backup dir: {e}")))?;

    let stamp = to_rfc3339(OffsetDateTime::now_utc()).replace([':'], "-");
    let path = format!("{dir}/vault-{stamp}.db");

    // VACUUM INTO writes a transactionally-consistent copy.
    sqlx::query("VACUUM INTO ?")
        .bind(&path)
        .execute(state.db.pool())
        .await
        .map_err(|e| AppError::Internal(format!("backup failed: {e}")))?;

    tracing::info!(path = %path, "backup written");

    #[cfg(feature = "s3")]
    {
        if let Some(target) = s3::S3Target::from_env() {
            let key = format!("vault-{stamp}.db",);
            s3::upload(&target, &path, &key).await?;
            tracing::info!(bucket = %target.bucket, key = %key, "backup uploaded to S3");
        }
    }

    Ok(path)
}

/// Spawn a periodic backup task if `VAULT_BACKUP_INTERVAL_SECS` is set and a
/// target directory is configured.
pub fn spawn_scheduled(state: SharedState) {
    let interval = match std::env::var("VAULT_BACKUP_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(s) if s > 0 => s,
        _ => return,
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
        // Skip the immediate first tick.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(e) = run_backup(&state).await {
                tracing::error!(error = %e, "scheduled backup failed");
            }
        }
    });
}

#[cfg(feature = "s3")]
pub mod s3 {
    //! Minimal S3-compatible upload via AWS SigV4 (no heavyweight SDK).

    use crate::error::{AppError, AppResult};

    pub struct S3Target {
        pub endpoint: String,
        pub bucket: String,
        pub region: String,
        pub access_key: String,
        pub secret_key: String,
    }

    impl std::fmt::Debug for S3Target {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Never render the S3 secret key.
            f.debug_struct("S3Target")
                .field("endpoint", &self.endpoint)
                .field("bucket", &self.bucket)
                .field("region", &self.region)
                .finish_non_exhaustive()
        }
    }

    impl S3Target {
        pub fn from_env() -> Option<Self> {
            Some(Self {
                endpoint: std::env::var("VAULT_BACKUP_S3_ENDPOINT").ok()?,
                bucket: std::env::var("VAULT_BACKUP_S3_BUCKET").ok()?,
                region: std::env::var("VAULT_BACKUP_S3_REGION")
                    .unwrap_or_else(|_| "us-east-1".into()),
                access_key: std::env::var("VAULT_BACKUP_S3_ACCESS_KEY").ok()?,
                secret_key: std::env::var("VAULT_BACKUP_S3_SECRET_KEY").ok()?,
            })
        }
    }

    /// Upload a file with a SigV4-signed PUT. Implemented in `s3_sigv4`.
    pub async fn upload(target: &S3Target, path: &str, key: &str) -> AppResult<()> {
        let body = tokio::fs::read(path)
            .await
            .map_err(|e| AppError::Internal(format!("read backup: {e}")))?;
        crate::s3_sigv4::put_object(target, key, &body).await
    }
}
