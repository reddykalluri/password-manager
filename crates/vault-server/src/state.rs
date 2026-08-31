//! Shared application state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Webauthn};

use crate::auth::opaque::CipherSuite;
use crate::auth::rate_limit::RateLimiter;
use crate::auth::tokens::TokenKey;
use crate::config::Config;
use crate::db::Db;
use crate::error::AppResult;

const OPAQUE_SETUP_KEY: &str = "opaque_server_setup";
/// Pending-login states older than this are purged.
const PENDING_LOGIN_TTL_SECS: u64 = 120;

/// A login flow awaiting its finish message.
pub struct PendingLogin {
    pub state: opaque_ke::ServerLogin<CipherSuite>,
    pub account_id: Uuid,
    pub created: Instant,
}

impl std::fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the OPAQUE login state.
        f.debug_struct("PendingLogin")
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

/// A WebAuthn registration ceremony awaiting its finish message.
#[derive(Debug)]
pub struct PendingWebauthnReg {
    pub account_id: Uuid,
    pub state: PasskeyRegistration,
    pub created: Instant,
}

/// A WebAuthn assertion ceremony awaiting its finish message. Used both at login
/// (second factor) and for step-up on sensitive operations.
#[derive(Debug)]
pub struct PendingWebauthnAuth {
    pub account_id: Uuid,
    pub state: PasskeyAuthentication,
    pub created: Instant,
}

pub struct AppState {
    pub db: Db,
    pub config: Config,
    pub token_key: TokenKey,
    pub limiter: RateLimiter,
    /// Persisted OPAQUE server setup (base64).
    pub opaque_setup: String,
    /// WebAuthn context (RP id/origin from the public origin).
    pub webauthn: Webauthn,
    pub pending_logins: Mutex<HashMap<Uuid, PendingLogin>>,
    pub pending_webauthn_reg: Mutex<HashMap<Uuid, PendingWebauthnReg>>,
    pub pending_webauthn_auth: Mutex<HashMap<Uuid, PendingWebauthnAuth>>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    /// Build state, loading or creating the persistent OPAQUE setup and the
    /// token signing key.
    pub async fn bootstrap(config: Config, db: Db) -> AppResult<SharedState> {
        let opaque_setup = match db.get_config(OPAQUE_SETUP_KEY).await? {
            Some(s) => s,
            None => {
                let s = crate::auth::opaque::new_server_setup();
                db.set_config(OPAQUE_SETUP_KEY, &s).await?;
                s
            }
        };

        // Token signing key: from env for stable tokens across restarts, else a
        // random key (tokens invalidated on restart).
        let token_key = match std::env::var("VAULT_TOKEN_KEY") {
            Ok(hex) if !hex.is_empty() => {
                let bytes = hex.into_bytes();
                TokenKey::from_bytes(bytes)
            }
            _ => TokenKey::random(),
        };

        let webauthn = crate::auth::webauthn::build(&config.public_origin)?;

        Ok(Arc::new(AppState {
            db,
            config,
            token_key,
            limiter: RateLimiter::new(),
            opaque_setup,
            webauthn,
            pending_logins: Mutex::new(HashMap::new()),
            pending_webauthn_reg: Mutex::new(HashMap::new()),
            pending_webauthn_auth: Mutex::new(HashMap::new()),
        }))
    }

    /// Stash a pending login, returning its flow id. Also garbage-collects
    /// expired entries.
    pub fn put_pending_login(
        &self,
        state: opaque_ke::ServerLogin<CipherSuite>,
        account_id: Uuid,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let mut map = self.pending_logins.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, p| now.duration_since(p.created).as_secs() < PENDING_LOGIN_TTL_SECS);
        map.insert(
            id,
            PendingLogin {
                state,
                account_id,
                created: now,
            },
        );
        id
    }

    /// Remove and return a pending login if present and unexpired.
    pub fn take_pending_login(&self, id: Uuid) -> Option<PendingLogin> {
        let mut map = self.pending_logins.lock().unwrap();
        let p = map.remove(&id)?;
        if Instant::now().duration_since(p.created).as_secs() >= PENDING_LOGIN_TTL_SECS {
            None
        } else {
            Some(p)
        }
    }

    /// Stash a pending WebAuthn registration ceremony, returning its flow id.
    pub fn put_pending_webauthn_reg(&self, account_id: Uuid, state: PasskeyRegistration) -> Uuid {
        let id = Uuid::new_v4();
        let mut map = self.pending_webauthn_reg.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, p| now.duration_since(p.created).as_secs() < PENDING_LOGIN_TTL_SECS);
        map.insert(
            id,
            PendingWebauthnReg {
                account_id,
                state,
                created: now,
            },
        );
        id
    }

    pub fn take_pending_webauthn_reg(&self, id: Uuid) -> Option<PendingWebauthnReg> {
        let mut map = self.pending_webauthn_reg.lock().unwrap();
        let p = map.remove(&id)?;
        (Instant::now().duration_since(p.created).as_secs() < PENDING_LOGIN_TTL_SECS).then_some(p)
    }

    /// Stash a pending WebAuthn assertion ceremony, returning its flow id.
    pub fn put_pending_webauthn_auth(
        &self,
        account_id: Uuid,
        state: PasskeyAuthentication,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let mut map = self.pending_webauthn_auth.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, p| now.duration_since(p.created).as_secs() < PENDING_LOGIN_TTL_SECS);
        map.insert(
            id,
            PendingWebauthnAuth {
                account_id,
                state,
                created: now,
            },
        );
        id
    }

    pub fn take_pending_webauthn_auth(&self, id: Uuid) -> Option<PendingWebauthnAuth> {
        let mut map = self.pending_webauthn_auth.lock().unwrap();
        let p = map.remove(&id)?;
        (Instant::now().duration_since(p.created).as_secs() < PENDING_LOGIN_TTL_SECS).then_some(p)
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}
