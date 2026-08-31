//! Server configuration, sourced from environment variables (12-factor) with
//! sensible self-host defaults. No secrets are logged (see [`crate::logging`]).

use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{AppError, AppResult};

/// Whether public registration is open or invite/flag gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// Closed by default: only invite links allow new accounts.
    InviteOnly,
    /// Explicitly opened via `VAULT_REGISTRATION=open`.
    Open,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// sqlx connection URL, e.g. `sqlite:///data/vault.db` or a `postgres://` URL.
    pub database_url: String,
    /// Directory served as the bundled web client (may be empty in API-only mode).
    pub web_root: Option<String>,
    pub registration: Registration,
    /// Access-token lifetime (spec: ≤15 minutes).
    pub access_token_ttl: Duration,
    /// Refresh-token lifetime.
    pub refresh_token_ttl: Duration,
    /// Public origin used for WebAuthn RP id / expected origin.
    pub public_origin: String,
    /// Failed-login lockout threshold before backoff escalates.
    pub login_backoff_threshold: u32,
}

impl Config {
    /// Load config from the environment, applying defaults.
    pub fn from_env() -> AppResult<Self> {
        let bind_addr = env::var("VAULT_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".into())
            .parse()
            .map_err(|e| AppError::Config(format!("VAULT_BIND invalid: {e}")))?;

        let database_url =
            env::var("VAULT_DATABASE_URL").unwrap_or_else(|_| "sqlite://data/vault.db".into());

        let web_root = env::var("VAULT_WEB_ROOT").ok().filter(|s| !s.is_empty());

        let registration = match env::var("VAULT_REGISTRATION").as_deref() {
            Ok("open") => Registration::Open,
            _ => Registration::InviteOnly,
        };

        let access_token_ttl = Duration::from_secs(
            env::var("VAULT_ACCESS_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(900),
        );
        if access_token_ttl > Duration::from_secs(900) {
            return Err(AppError::Config(
                "VAULT_ACCESS_TTL_SECS must be ≤ 900 (spec: access tokens ≤ 15 min)".into(),
            ));
        }
        let refresh_token_ttl = Duration::from_secs(
            env::var("VAULT_REFRESH_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60 * 60 * 24 * 30),
        );

        let public_origin =
            env::var("VAULT_PUBLIC_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".into());

        let login_backoff_threshold = env::var("VAULT_LOGIN_BACKOFF_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        Ok(Config {
            bind_addr,
            database_url,
            web_root,
            registration,
            access_token_ttl,
            refresh_token_ttl,
            public_origin,
            login_backoff_threshold,
        })
    }
}
