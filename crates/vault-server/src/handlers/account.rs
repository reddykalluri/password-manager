//! Account self-service: security activity and device list (spec: audit log,
//! user-scoped view).

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::db::AuditEntry;
use crate::error::AppResult;
use crate::extract::AuthUser;
use crate::state::SharedState;

/// Recent security events for the caller's own account.
pub async fn security_activity(
    State(state): State<SharedState>,
    user: AuthUser,
) -> AppResult<Json<Vec<AuditEntry>>> {
    let entries = state.db.audit_for_account(user.account_id, 100).await?;
    Ok(Json(entries))
}

#[derive(Debug, Serialize)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
}

/// The caller's registered devices.
pub async fn list_devices(
    State(state): State<SharedState>,
    user: AuthUser,
) -> AppResult<Json<Vec<DeviceView>>> {
    let devices = state.db.list_devices(user.account_id).await?;
    Ok(Json(
        devices
            .into_iter()
            .map(|d| DeviceView {
                id: d.id.to_string(),
                name: d.name,
            })
            .collect(),
    ))
}
