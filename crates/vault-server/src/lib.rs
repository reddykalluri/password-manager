//! vault-server: self-hosted zero-knowledge sync server.
//!
//! The server is untrusted with respect to secret content: it stores and serves
//! ciphertext, wrapped keys, and sync metadata, and verifies identity via
//! OPAQUE — nothing more.

pub mod auth;
pub mod backup;
pub mod config;
pub mod db;
pub mod error;
pub mod extract;
pub mod handlers;
pub mod logging;
pub mod routes;
#[cfg(feature = "s3")]
pub mod s3_sigv4;
pub mod state;
pub mod time_util;

use crate::config::Config;
use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Boot the server: load config, open+migrate the database, and serve.
pub async fn run() -> AppResult<()> {
    logging::init();
    let config = Config::from_env()?;
    tracing::info!(
        addr = %config.bind_addr,
        registration = ?config.registration,
        "starting vault-server"
    );

    let db = Db::connect(&config.database_url).await?;
    let state = AppState::bootstrap(config, db).await?;
    backup::spawn_scheduled(state.clone());

    let app = routes::router(state.clone());
    let listener = tokio::net::TcpListener::bind(state.config.bind_addr)
        .await
        .map_err(|e| AppError::Internal(format!("bind failed: {e}")))?;
    tracing::info!("vault-server ready");
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| AppError::Internal(format!("server error: {e}")))?;
    Ok(())
}
