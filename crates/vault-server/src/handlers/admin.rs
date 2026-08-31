//! Operator administration: invite creation and instance-level audit view.
//!
//! Gated by the `X-Operator-Token` header matching `VAULT_OPERATOR_TOKEN`. If
//! that env var is unset, operator endpoints are disabled (403).

use axum::async_trait;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Serialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

use crate::db::AuditEntry;
use crate::error::{AppError, AppResult};
use crate::extract::ClientIp;
use crate::state::SharedState;

/// Marker extractor proving the request carried a valid operator token.
#[derive(Debug)]
pub struct OperatorAuth;

#[async_trait]
impl FromRequestParts<SharedState> for OperatorAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &SharedState) -> Result<Self, AppError> {
        let configured = std::env::var("VAULT_OPERATOR_TOKEN")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or(AppError::Forbidden)?;
        let presented = parts
            .headers
            .get("x-operator-token")
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Forbidden)?;
        if presented
            .as_bytes()
            .ct_eq(configured.as_bytes())
            .unwrap_u8()
            == 1
        {
            Ok(OperatorAuth)
        } else {
            Err(AppError::Forbidden)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InviteResp {
    pub code: String,
}

/// Create a single-use invite valid for 7 days.
pub async fn create_invite(
    State(state): State<SharedState>,
    _op: OperatorAuth,
    ip: ClientIp,
) -> AppResult<Json<InviteResp>> {
    let mut raw = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let code = URL_SAFE_NO_PAD.encode(raw);
    let expires = OffsetDateTime::now_utc() + Duration::days(7);
    state.db.create_invite(&code, Some(expires)).await?;
    state
        .db
        .audit(
            None,
            None,
            "invite_created",
            ip.0.as_deref(),
            None,
            "operator",
        )
        .await?;
    Ok(Json(InviteResp { code }))
}

/// Instance-level audit view for the operator.
pub async fn operator_activity(
    State(state): State<SharedState>,
    _op: OperatorAuth,
) -> AppResult<Json<Vec<AuditEntry>>> {
    let entries = state.db.audit_operator(200).await?;
    Ok(Json(entries))
}

/// Trigger an on-demand backup to the configured target.
pub async fn trigger_backup(
    State(state): State<SharedState>,
    _op: OperatorAuth,
) -> AppResult<Json<serde_json::Value>> {
    let path = crate::backup::run_backup(&state).await?;
    Ok(Json(json!({ "backup": path })))
}
