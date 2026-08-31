//! Delta-sync API (spec: Sync API) and account crypto material.
//!
//! All access is scoped to the authenticated account, giving strict multi-tenant
//! isolation: an item id belonging to another account is indistinguishable from
//! a missing one (both 404).

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use vault_core::store::ItemRecord;

use crate::db::WriteOutcome;
use crate::error::{AppError, AppResult};
use crate::extract::{AuthUser, ClientIp};
use crate::handlers::auth::require_second_factor;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    pub cursor: i64,
}

#[derive(Debug, Serialize)]
pub struct PullResp {
    pub records: Vec<ItemRecord>,
    pub cursor: i64,
}

/// Fetch changes since the client's cursor.
pub async fn pull(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<PullQuery>,
) -> AppResult<Json<PullResp>> {
    let (records, cursor) = state.db.pull_since(user.account_id, q.cursor).await?;
    Ok(Json(PullResp { records, cursor }))
}

#[derive(Debug, Deserialize)]
pub struct PushReq {
    pub record: ItemRecord,
    pub base_version: u64,
}

#[derive(Debug, Serialize)]
pub struct PushResp {
    pub new_version: u64,
    pub cursor: i64,
}

/// Versioned write. Fast-forwards succeed; stale writes return 409 with the
/// server's current record for client-side merge.
pub async fn push(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<PushReq>,
) -> AppResult<Json<PushResp>> {
    match state
        .db
        .push_item(user.account_id, &req.record, req.base_version as i64)
        .await?
    {
        WriteOutcome::Accepted {
            new_version,
            cursor,
        } => Ok(Json(PushResp {
            new_version: new_version as u64,
            cursor,
        })),
        WriteOutcome::Conflict { current } => Err(AppError::Conflict {
            current: serde_json::to_value(&current)
                .map_err(|e| AppError::Internal(e.to_string()))?,
        }),
    }
}

/// Fetch a single item, scoped to the account (cross-tenant → 404).
pub async fn get_item(
    State(state): State<SharedState>,
    user: AuthUser,
    Path(item_id): Path<Uuid>,
) -> AppResult<Json<ItemRecord>> {
    let record = state
        .db
        .get_item(user.account_id, item_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(record))
}

// --- account crypto (wrapped keys) -----------------------------------------

/// Return the account's crypto material (wrapped keys, salts, KDF params) so a
/// client can unlock. Contains no plaintext secrets.
pub async fn get_account_crypto(
    State(state): State<SharedState>,
    user: AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let account = state
        .db
        .account_by_id(user.account_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let value: serde_json::Value = serde_json::from_str(&account.account_crypto)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(value))
}

#[derive(Debug, Deserialize)]
pub struct UpdateCryptoReq {
    /// New AccountCrypto (e.g. after a master-password change re-wraps the
    /// account key, or a new vault is added).
    pub account_crypto: serde_json::Value,
    /// Required if a second factor is enabled (sensitive operation). Provide a
    /// TOTP code or a WebAuthn step-up token.
    pub totp_code: Option<String>,
    pub stepup_token: Option<String>,
}

/// Update account crypto material. This is a sensitive operation: it re-wraps
/// keys, so a second factor is enforced when enabled.
pub async fn update_account_crypto(
    State(state): State<SharedState>,
    user: AuthUser,
    ip: ClientIp,
    Json(req): Json<UpdateCryptoReq>,
) -> AppResult<Json<serde_json::Value>> {
    require_second_factor(
        &state,
        user.account_id,
        req.totp_code.as_deref(),
        req.stepup_token.as_deref(),
    )
    .await?;
    let serialized = serde_json::to_string(&req.account_crypto)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    state
        .db
        .update_account_crypto(user.account_id, &serialized)
        .await?;
    state
        .db
        .audit(
            Some(user.account_id),
            Some(user.device_id),
            "account_crypto_updated",
            ip.0.as_deref(),
            None,
            "user",
        )
        .await?;
    Ok(Json(json!({"status": "updated"})))
}
