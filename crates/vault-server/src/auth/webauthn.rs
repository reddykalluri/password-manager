//! WebAuthn/FIDO2 second factor via `webauthn-rs`.
//!
//! Security keys and platform authenticators register a credential and later
//! satisfy an assertion challenge. Ceremony state (`PasskeyRegistration`,
//! `PasskeyAuthentication`) is held briefly in memory (see [`crate::state`])
//! between the start and finish requests.

use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid,
    Webauthn, WebauthnBuilder,
};

use crate::error::{AppError, AppResult};

/// Build the WebAuthn context from the instance's public origin. The RP id is
/// the origin host (e.g. `vault.example.com`).
pub fn build(public_origin: &str) -> AppResult<Webauthn> {
    let origin = Url::parse(public_origin)
        .map_err(|e| AppError::Config(format!("invalid VAULT_PUBLIC_ORIGIN: {e}")))?;
    let rp_id = origin
        .host_str()
        .ok_or_else(|| AppError::Config("VAULT_PUBLIC_ORIGIN has no host".into()))?
        .to_string();
    let builder = WebauthnBuilder::new(&rp_id, &origin)
        .map_err(|e| AppError::Internal(format!("webauthn init: {e}")))?;
    builder
        .rp_name("Vault")
        .build()
        .map_err(|e| AppError::Internal(format!("webauthn build: {e}")))
}

/// Begin registering a new credential for `account_id`. Existing credentials are
/// excluded to prevent double-registration.
pub fn start_registration(
    webauthn: &Webauthn,
    account_id: Uuid,
    username: &str,
    existing: &[Passkey],
) -> AppResult<(CreationChallengeResponse, PasskeyRegistration)> {
    let exclude = existing.iter().map(|p| p.cred_id().clone()).collect();
    webauthn
        .start_passkey_registration(account_id, username, username, Some(exclude))
        .map_err(|e| AppError::Internal(format!("webauthn reg start: {e}")))
}

/// Finish registration, returning the credential to persist.
pub fn finish_registration(
    webauthn: &Webauthn,
    credential: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
) -> AppResult<Passkey> {
    webauthn
        .finish_passkey_registration(credential, state)
        .map_err(|_| AppError::BadRequest("webauthn registration failed".into()))
}

/// Begin an assertion challenge against the account's registered credentials.
pub fn start_authentication(
    webauthn: &Webauthn,
    passkeys: &[Passkey],
) -> AppResult<(RequestChallengeResponse, PasskeyAuthentication)> {
    webauthn
        .start_passkey_authentication(passkeys)
        .map_err(|e| AppError::Internal(format!("webauthn auth start: {e}")))
}

/// Verify an assertion. Returns Ok(()) on success.
pub fn finish_authentication(
    webauthn: &Webauthn,
    credential: &PublicKeyCredential,
    state: &PasskeyAuthentication,
) -> AppResult<()> {
    webauthn
        .finish_passkey_authentication(credential, state)
        .map(|_| ())
        .map_err(|_| AppError::Unauthorized)
}

/// Serialize a passkey for storage.
pub fn serialize_passkey(passkey: &Passkey) -> AppResult<String> {
    serde_json::to_string(passkey).map_err(|e| AppError::Internal(e.to_string()))
}

/// Deserialize a stored passkey.
pub fn deserialize_passkey(material: &str) -> AppResult<Passkey> {
    serde_json::from_str(material).map_err(|e| AppError::Internal(format!("bad passkey: {e}")))
}
