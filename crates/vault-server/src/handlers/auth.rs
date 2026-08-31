//! Authentication handlers: OPAQUE registration/login, token refresh, and TOTP
//! second-factor enrolment.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::auth::{opaque, tokens, totp};
use crate::config::Registration;
use crate::error::{AppError, AppResult};
use crate::extract::{AuthUser, ClientIp};
use crate::state::SharedState;
use crate::time_util::to_rfc3339;

// --- registration ----------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterStartReq {
    pub username: String,
    /// base64 OPAQUE RegistrationRequest.
    pub registration_request: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterStartResp {
    pub registration_response: String,
}

pub async fn register_start(
    State(state): State<SharedState>,
    Json(req): Json<RegisterStartReq>,
) -> AppResult<Json<RegisterStartResp>> {
    let response = opaque::register_start(
        &state.opaque_setup,
        req.username.as_bytes(),
        &req.registration_request,
    )?;
    Ok(Json(RegisterStartResp {
        registration_response: response,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RegisterFinishReq {
    pub username: String,
    /// base64 OPAQUE RegistrationUpload.
    pub registration_upload: String,
    /// AccountCrypto JSON (wrapped keys, salts, KDF params) — no plaintext.
    pub account_crypto: serde_json::Value,
    /// Required when the instance is invite-only.
    pub invite_code: Option<String>,
    pub device_name: String,
}

#[derive(Debug, Serialize)]
pub struct AuthTokens {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn register_finish(
    State(state): State<SharedState>,
    ip: ClientIp,
    Json(req): Json<RegisterFinishReq>,
) -> AppResult<Json<AuthTokens>> {
    // Registration gating (spec: closed by default, invite/flag opened).
    let via = match state.config.registration {
        Registration::Open => "open".to_string(),
        Registration::InviteOnly => {
            let code = req
                .invite_code
                .as_deref()
                .ok_or(AppError::RegistrationClosed)?;
            if !state.db.consume_invite(code, &req.username).await? {
                return Err(AppError::RegistrationClosed);
            }
            format!("invite:{code}")
        }
    };

    let password_file = opaque::register_finish(&req.registration_upload)?;
    let account_crypto = serde_json::to_string(&req.account_crypto)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let account_id = state
        .db
        .create_account(&req.username, &password_file, &account_crypto, &via)
        .await?;
    let device_id = state.db.create_device(account_id, &req.device_name).await?;

    state
        .db
        .audit(
            Some(account_id),
            Some(device_id),
            "account_created",
            ip.0.as_deref(),
            Some(&format!("device={}", req.device_name)),
            "user",
        )
        .await?;

    let tokens = issue_tokens(&state, account_id, device_id).await?;
    Ok(Json(tokens))
}

// --- login -----------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginStartReq {
    pub username: String,
    /// base64 OPAQUE CredentialRequest.
    pub credential_request: String,
}

#[derive(Debug, Serialize)]
pub struct LoginStartResp {
    pub flow_id: Uuid,
    pub credential_response: String,
}

pub async fn login_start(
    State(state): State<SharedState>,
    ip: ClientIp,
    Json(req): Json<LoginStartReq>,
) -> AppResult<Json<LoginStartResp>> {
    // Per-IP throttling to blunt spraying across accounts.
    let ip_key = format!("ip:{}", ip.0.as_deref().unwrap_or("unknown"));
    if let Some(retry) = state.limiter.check(&ip_key) {
        return Err(AppError::RateLimited {
            retry_after_secs: retry,
        });
    }

    let account = state.db.account_by_username(&req.username).await?;
    // Account lockout (persistent per-account backoff).
    if let Some(acct) = &account {
        if let Some(lock_until) = acct.lock_until {
            if lock_until > OffsetDateTime::now_utc() {
                return Err(AppError::RateLimited {
                    retry_after_secs: (lock_until - OffsetDateTime::now_utc())
                        .whole_seconds()
                        .max(1) as u64,
                });
            }
        }
    }

    // Unknown user → None password file (decoy response, no enumeration).
    let password_file = account.as_ref().map(|a| a.opaque_record.clone());
    let (login_state, credential_response) = opaque::login_start(
        &state.opaque_setup,
        password_file.as_deref(),
        req.username.as_bytes(),
        &req.credential_request,
    )?;

    let account_id = account.as_ref().map(|a| a.id).unwrap_or_else(Uuid::nil);
    let flow_id = state.put_pending_login(login_state, account_id);
    Ok(Json(LoginStartResp {
        flow_id,
        credential_response,
    }))
}

#[derive(Debug, Deserialize)]
pub struct LoginFinishReq {
    pub flow_id: Uuid,
    /// base64 OPAQUE CredentialFinalization.
    pub credential_finalization: String,
    pub device_name: String,
    /// TOTP code, required when the account has a second factor enabled.
    pub totp_code: Option<String>,
}

/// A WebAuthn assertion challenge returned when a security key is the enabled
/// second factor.
#[derive(Debug, Serialize)]
pub struct SecondFactorChallenge {
    pub webauthn_flow_id: Uuid,
    pub webauthn_challenge: serde_json::Value,
}

/// Login outcome: either tokens (no/failed-through 2FA satisfied) or a WebAuthn
/// challenge to complete. Untagged so the tokens shape is unchanged.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginOutcome {
    Tokens(AuthTokens),
    SecondFactor {
        second_factor: SecondFactorChallenge,
    },
}

pub async fn login_finish(
    State(state): State<SharedState>,
    ip: ClientIp,
    Json(req): Json<LoginFinishReq>,
) -> AppResult<Json<LoginOutcome>> {
    let ip_key = format!("ip:{}", ip.0.as_deref().unwrap_or("unknown"));
    let pending = state
        .take_pending_login(req.flow_id)
        .ok_or(AppError::Unauthorized)?;

    // Verify the OPAQUE finalization. Failure = wrong password (or decoy).
    let opaque_ok = opaque::login_finish(pending.state, &req.credential_finalization).is_ok();
    if !opaque_ok || pending.account_id.is_nil() {
        record_failure(&state, &ip_key, pending.account_id, ip.0.as_deref()).await?;
        return Err(AppError::Unauthorized);
    }
    let account_id = pending.account_id;

    // Password verified: clear password-guessing throttles.
    state.limiter.reset(&ip_key);
    state.db.reset_login_failures(account_id).await?;

    // Second-factor enforcement (spec: enforced at login when enabled).
    let factors = state.db.second_factors(account_id).await?;
    if factors.is_empty() {
        let tokens = complete_login(&state, account_id, ip.0.as_deref(), &req.device_name).await?;
        return Ok(Json(LoginOutcome::Tokens(tokens)));
    }

    let has_totp = factors.iter().any(|(k, _)| k == "totp");
    let has_webauthn = factors.iter().any(|(k, _)| k == "webauthn");

    // TOTP satisfies it directly if a valid code was supplied.
    if has_totp {
        if let Some(code) = req.totp_code.as_deref() {
            let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
            let ok = factors
                .iter()
                .filter(|(k, _)| k == "totp")
                .any(|(_, secret)| totp::verify(secret, code, now));
            if ok {
                let tokens =
                    complete_login(&state, account_id, ip.0.as_deref(), &req.device_name).await?;
                return Ok(Json(LoginOutcome::Tokens(tokens)));
            }
        }
    }

    // Otherwise, if a security key is enrolled, issue a WebAuthn challenge.
    if has_webauthn {
        let passkeys = load_passkeys(&factors)?;
        let (challenge, auth_state) =
            crate::auth::webauthn::start_authentication(&state.webauthn, &passkeys)?;
        let flow_id = state.put_pending_webauthn_auth(account_id, auth_state);
        return Ok(Json(LoginOutcome::SecondFactor {
            second_factor: SecondFactorChallenge {
                webauthn_flow_id: flow_id,
                webauthn_challenge: serde_json::to_value(&challenge)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
            },
        }));
    }

    // TOTP is enrolled but no valid code was supplied.
    Err(AppError::SecondFactorRequired)
}

#[derive(Debug, Deserialize)]
pub struct LoginWebauthnFinishReq {
    pub webauthn_flow_id: Uuid,
    /// The WebAuthn assertion (PublicKeyCredential JSON).
    pub credential: serde_json::Value,
    pub device_name: String,
}

/// Complete a login whose second factor is a WebAuthn assertion.
pub async fn login_webauthn_finish(
    State(state): State<SharedState>,
    ip: ClientIp,
    Json(req): Json<LoginWebauthnFinishReq>,
) -> AppResult<Json<AuthTokens>> {
    let pending = state
        .take_pending_webauthn_auth(req.webauthn_flow_id)
        .ok_or(AppError::Unauthorized)?;
    let credential = serde_json::from_value(req.credential)
        .map_err(|_| AppError::BadRequest("invalid WebAuthn credential".into()))?;
    crate::auth::webauthn::finish_authentication(&state.webauthn, &credential, &pending.state)?;

    let tokens = complete_login(
        &state,
        pending.account_id,
        ip.0.as_deref(),
        &req.device_name,
    )
    .await?;
    Ok(Json(tokens))
}

// --- refresh ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RefreshReq {
    pub refresh_token: String,
}

pub async fn refresh(
    State(state): State<SharedState>,
    Json(req): Json<RefreshReq>,
) -> AppResult<Json<AuthTokens>> {
    let hash = tokens::hash_refresh(&req.refresh_token);
    let device = state
        .db
        .device_by_refresh_hash(&hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // Reject expired refresh tokens.
    if let Some(exp) = device.refresh_expires_at {
        if exp < OffsetDateTime::now_utc() {
            return Err(AppError::Unauthorized);
        }
    } else {
        return Err(AppError::Unauthorized);
    }

    // Rotate: a new refresh token replaces the old one (single-use).
    let tokens = issue_tokens(&state, device.account_id, device.id).await?;
    Ok(Json(tokens))
}

// --- TOTP enrolment --------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EnrollTotpReq {
    /// base32 TOTP secret generated by the client.
    pub secret: String,
    /// Current code proving the secret was set up correctly.
    pub code: String,
}

pub async fn enroll_totp(
    State(state): State<SharedState>,
    user: AuthUser,
    ip: ClientIp,
    Json(req): Json<EnrollTotpReq>,
) -> AppResult<Json<serde_json::Value>> {
    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    if !totp::verify(&req.secret, &req.code, now) {
        return Err(AppError::BadRequest("TOTP code did not verify".into()));
    }
    state
        .db
        .add_second_factor(user.account_id, "totp", &req.secret)
        .await?;
    state
        .db
        .audit(
            Some(user.account_id),
            Some(user.device_id),
            "second_factor_enrolled",
            ip.0.as_deref(),
            Some("kind=totp"),
            "user",
        )
        .await?;
    Ok(Json(json!({"status": "enrolled"})))
}

// --- helpers ---------------------------------------------------------------

async fn issue_tokens(
    state: &SharedState,
    account_id: Uuid,
    device_id: Uuid,
) -> AppResult<AuthTokens> {
    let access = state
        .token_key
        .issue(account_id, device_id, state.config.access_token_ttl)?;
    let refresh = tokens::new_refresh_token();
    let expires = OffsetDateTime::now_utc()
        + Duration::seconds(state.config.refresh_token_ttl.as_secs() as i64);
    state
        .db
        .set_device_refresh(device_id, &refresh.hash, expires)
        .await?;
    let _ = to_rfc3339; // referenced for clarity of expiry handling
    Ok(AuthTokens {
        account_id,
        device_id,
        access_token: access,
        refresh_token: refresh.plaintext,
    })
}

/// Register a device and issue tokens after all factors are satisfied. Shared by
/// the no-2FA, TOTP, and WebAuthn login paths.
async fn complete_login(
    state: &SharedState,
    account_id: Uuid,
    ip: Option<&str>,
    device_name: &str,
) -> AppResult<AuthTokens> {
    let device_id = state.db.create_device(account_id, device_name).await?;
    state
        .db
        .audit(
            Some(account_id),
            Some(device_id),
            "login",
            ip,
            Some(&format!("device={device_name}")),
            "user",
        )
        .await?;
    issue_tokens(state, account_id, device_id).await
}

/// Decode all WebAuthn passkeys from an account's second-factor rows.
pub fn load_passkeys(
    factors: &[(String, String)],
) -> AppResult<Vec<webauthn_rs::prelude::Passkey>> {
    factors
        .iter()
        .filter(|(k, _)| k == "webauthn")
        .map(|(_, material)| crate::auth::webauthn::deserialize_passkey(material))
        .collect()
}

/// Enforce the second factor for a sensitive operation. Satisfied by a valid
/// TOTP code or a step-up token (from a prior WebAuthn assertion). Returns
/// `SecondFactorRequired` when 2FA is enabled but nothing was supplied.
pub async fn require_second_factor(
    state: &SharedState,
    account_id: Uuid,
    totp_code: Option<&str>,
    stepup_token: Option<&str>,
) -> AppResult<()> {
    let factors = state.db.second_factors(account_id).await?;
    if factors.is_empty() {
        return Ok(()); // no 2FA configured
    }
    // WebAuthn step-up token.
    if let Some(token) = stepup_token {
        if state.token_key.verify_stepup(token, account_id) {
            return Ok(());
        }
    }
    // TOTP code.
    if let Some(code) = totp_code {
        let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let ok = factors
            .iter()
            .filter(|(kind, _)| kind == "totp")
            .any(|(_, secret)| totp::verify(secret, code, now));
        if ok {
            return Ok(());
        }
        return Err(AppError::Unauthorized);
    }
    Err(AppError::SecondFactorRequired)
}

async fn record_failure(
    state: &SharedState,
    ip_key: &str,
    account_id: Uuid,
    ip: Option<&str>,
) -> AppResult<()> {
    let wait = state
        .limiter
        .record_failure(ip_key, state.config.login_backoff_threshold);
    if !account_id.is_nil() {
        let lock_until =
            (wait > 0).then(|| OffsetDateTime::now_utc() + Duration::seconds(wait as i64));
        let failures = state
            .db
            .record_login_failure(account_id, lock_until)
            .await?;
        // Emit a security event once backoff engages (spec: online-guessing).
        if failures >= state.config.login_backoff_threshold as i64 {
            state
                .db
                .audit(
                    Some(account_id),
                    None,
                    "login_failed_backoff",
                    ip,
                    Some(&format!("failures={failures}")),
                    "user",
                )
                .await?;
        }
    }
    Ok(())
}
