//! WebAuthn second-factor handlers: credential enrolment and step-up assertion
//! for sensitive operations. Login-time assertion lives in `handlers::auth`.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::webauthn;
use crate::error::{AppError, AppResult};
use crate::extract::{AuthUser, ClientIp};
use crate::handlers::auth::load_passkeys;
use crate::state::SharedState;

#[derive(Debug, Serialize)]
pub struct ChallengeResp {
    pub flow_id: Uuid,
    pub challenge: serde_json::Value,
}

/// Begin enrolling a WebAuthn credential (security key / platform authenticator).
pub async fn register_start(
    State(state): State<SharedState>,
    user: AuthUser,
) -> AppResult<Json<ChallengeResp>> {
    let account = state
        .db
        .account_by_id(user.account_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let factors = state.db.second_factors(user.account_id).await?;
    let existing = load_passkeys(&factors)?;
    let (challenge, reg_state) = webauthn::start_registration(
        &state.webauthn,
        user.account_id,
        &account.username,
        &existing,
    )?;
    let flow_id = state.put_pending_webauthn_reg(user.account_id, reg_state);
    Ok(Json(ChallengeResp {
        flow_id,
        challenge: serde_json::to_value(&challenge)
            .map_err(|e| AppError::Internal(e.to_string()))?,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RegisterFinishReq {
    pub flow_id: Uuid,
    /// RegisterPublicKeyCredential JSON from the authenticator.
    pub credential: serde_json::Value,
}

/// Finish enrolment, persisting the credential as a second factor.
pub async fn register_finish(
    State(state): State<SharedState>,
    user: AuthUser,
    ip: ClientIp,
    Json(req): Json<RegisterFinishReq>,
) -> AppResult<Json<serde_json::Value>> {
    let pending = state
        .take_pending_webauthn_reg(req.flow_id)
        .ok_or(AppError::Unauthorized)?;
    // Bind the ceremony to the caller.
    if pending.account_id != user.account_id {
        return Err(AppError::Forbidden);
    }
    let credential = serde_json::from_value(req.credential)
        .map_err(|_| AppError::BadRequest("invalid WebAuthn credential".into()))?;
    let passkey = webauthn::finish_registration(&state.webauthn, &credential, &pending.state)?;
    let material = webauthn::serialize_passkey(&passkey)?;
    state
        .db
        .add_second_factor(user.account_id, "webauthn", &material)
        .await?;
    state
        .db
        .audit(
            Some(user.account_id),
            Some(user.device_id),
            "second_factor_enrolled",
            ip.0.as_deref(),
            Some("kind=webauthn"),
            "user",
        )
        .await?;
    Ok(Json(json!({"status": "enrolled"})))
}

/// Begin a step-up assertion (for a sensitive operation) using the account's
/// enrolled credentials.
pub async fn stepup_start(
    State(state): State<SharedState>,
    user: AuthUser,
) -> AppResult<Json<ChallengeResp>> {
    let factors = state.db.second_factors(user.account_id).await?;
    let passkeys = load_passkeys(&factors)?;
    if passkeys.is_empty() {
        return Err(AppError::BadRequest(
            "no WebAuthn credential enrolled".into(),
        ));
    }
    let (challenge, auth_state) = webauthn::start_authentication(&state.webauthn, &passkeys)?;
    let flow_id = state.put_pending_webauthn_auth(user.account_id, auth_state);
    Ok(Json(ChallengeResp {
        flow_id,
        challenge: serde_json::to_value(&challenge)
            .map_err(|e| AppError::Internal(e.to_string()))?,
    }))
}

#[derive(Debug, Deserialize)]
pub struct StepUpFinishReq {
    pub flow_id: Uuid,
    /// PublicKeyCredential JSON assertion.
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct StepUpResp {
    /// Short-lived token proving the second factor was satisfied.
    pub stepup_token: String,
}

/// Finish a step-up assertion, returning a short-lived step-up token to present
/// on the sensitive operation.
pub async fn stepup_finish(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<StepUpFinishReq>,
) -> AppResult<Json<StepUpResp>> {
    let pending = state
        .take_pending_webauthn_auth(req.flow_id)
        .ok_or(AppError::Unauthorized)?;
    if pending.account_id != user.account_id {
        return Err(AppError::Forbidden);
    }
    let credential = serde_json::from_value(req.credential)
        .map_err(|_| AppError::BadRequest("invalid WebAuthn credential".into()))?;
    webauthn::finish_authentication(&state.webauthn, &credential, &pending.state)?;

    // Step-up tokens are valid briefly, just long enough to chain into the op.
    let token = state
        .token_key
        .issue_stepup(user.account_id, std::time::Duration::from_secs(120))?;
    Ok(Json(StepUpResp {
        stepup_token: token,
    }))
}
