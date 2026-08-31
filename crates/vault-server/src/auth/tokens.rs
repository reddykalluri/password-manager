//! Access and refresh tokens.
//!
//! Access tokens are stateless HMAC-SHA256-signed blobs (short-lived, ≤15 min).
//! Refresh tokens are opaque random strings whose SHA-256 hash is stored on the
//! device row and rotated on every use (spec: rotating refresh tokens bound to a
//! registered device).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

type HmacSha256 = Hmac<Sha256>;

/// Claims carried by an access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub account_id: Uuid,
    pub device_id: Uuid,
    /// Unix expiry (seconds).
    pub exp: i64,
}

/// Signing key for access tokens, held in server memory only.
#[derive(Clone)]
pub struct TokenKey {
    key: Vec<u8>,
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenKey(<redacted>)")
    }
}

impl TokenKey {
    pub fn from_bytes(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Generate a random signing key (used when none is configured).
    pub fn random() -> Self {
        let mut key = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Issue a signed access token valid for `ttl`.
    pub fn issue(
        &self,
        account_id: Uuid,
        device_id: Uuid,
        ttl: std::time::Duration,
    ) -> AppResult<String> {
        let exp = OffsetDateTime::now_utc().unix_timestamp() + ttl.as_secs() as i64;
        let claims = AccessClaims {
            account_id,
            device_id,
            exp,
        };
        let payload = serde_json::to_vec(&claims).map_err(|e| AppError::Internal(e.to_string()))?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let sig = self.sign(payload_b64.as_bytes());
        Ok(format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }

    /// Verify a token's signature and expiry, returning its claims.
    pub fn verify(&self, token: &str) -> AppResult<AccessClaims> {
        let (payload_b64, sig_b64) = token.split_once('.').ok_or(AppError::Unauthorized)?;
        let expected = self.sign(payload_b64.as_bytes());
        let got = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| AppError::Unauthorized)?;
        // Constant-time comparison to avoid signature-timing leaks.
        if expected.ct_eq(&got).unwrap_u8() != 1 {
            return Err(AppError::Unauthorized);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| AppError::Unauthorized)?;
        let claims: AccessClaims =
            serde_json::from_slice(&payload).map_err(|_| AppError::Unauthorized)?;
        if claims.exp < OffsetDateTime::now_utc().unix_timestamp() {
            return Err(AppError::Unauthorized);
        }
        Ok(claims)
    }

    /// Issue a short-lived step-up token proving a second factor was satisfied,
    /// for use on a subsequent sensitive operation (e.g. after a WebAuthn
    /// assertion).
    pub fn issue_stepup(&self, account_id: Uuid, ttl: std::time::Duration) -> AppResult<String> {
        let exp = OffsetDateTime::now_utc().unix_timestamp() + ttl.as_secs() as i64;
        let claims = StepUpClaims {
            account_id,
            purpose: "stepup".into(),
            exp,
        };
        let payload = serde_json::to_vec(&claims).map_err(|e| AppError::Internal(e.to_string()))?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let sig = self.sign(payload_b64.as_bytes());
        Ok(format!("su.{payload_b64}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }

    /// Verify a step-up token for `account_id`.
    pub fn verify_stepup(&self, token: &str, account_id: Uuid) -> bool {
        let Some(rest) = token.strip_prefix("su.") else {
            return false;
        };
        let Some((payload_b64, sig_b64)) = rest.split_once('.') else {
            return false;
        };
        let expected = self.sign(payload_b64.as_bytes());
        let Ok(got) = URL_SAFE_NO_PAD.decode(sig_b64) else {
            return false;
        };
        if expected.ct_eq(&got).unwrap_u8() != 1 {
            return false;
        }
        let Ok(payload) = URL_SAFE_NO_PAD.decode(payload_b64) else {
            return false;
        };
        let Ok(claims) = serde_json::from_slice::<StepUpClaims>(&payload) else {
            return false;
        };
        claims.purpose == "stepup"
            && claims.account_id == account_id
            && claims.exp >= OffsetDateTime::now_utc().unix_timestamp()
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }
}

/// Claims for a step-up (second-factor-satisfied) token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StepUpClaims {
    account_id: Uuid,
    purpose: String,
    exp: i64,
}

/// A freshly minted refresh token: the plaintext to hand to the client and the
/// hash to store.
#[derive(Debug)]
pub struct RefreshToken {
    pub plaintext: String,
    pub hash: String,
}

/// Generate a new random refresh token and its storage hash.
pub fn new_refresh_token() -> RefreshToken {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let plaintext = URL_SAFE_NO_PAD.encode(raw);
    let hash = hash_refresh(&plaintext);
    RefreshToken { plaintext, hash }
}

/// Hash a refresh token for storage/comparison.
pub fn hash_refresh(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Constant-time compare a presented refresh token against a stored hash.
pub fn refresh_matches(presented: &str, stored_hash: &str) -> bool {
    let h = hash_refresh(presented);
    h.as_bytes().ct_eq(stored_hash.as_bytes()).unwrap_u8() == 1
}
