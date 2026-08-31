//! Liveness and readiness probes (spec: health and readiness endpoints).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

use crate::state::SharedState;

/// Liveness: the process is up. Always 200.
pub async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

/// Readiness: dependencies (the database) are reachable.
pub async fn ready(State(state): State<SharedState>) -> (StatusCode, Json<serde_json::Value>) {
    match state.db.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ready"}))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready"})),
        ),
    }
}
