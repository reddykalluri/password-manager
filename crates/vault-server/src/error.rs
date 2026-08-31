//! Server error type and its HTTP mapping.
//!
//! Error responses never leak whether a resource exists across tenant
//! boundaries: cross-account access and missing items both map to 404.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub type AppResult<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("database error")]
    Db(#[from] sqlx::Error),

    #[error("unauthorized")]
    Unauthorized,

    #[error("second factor required")]
    SecondFactorRequired,

    #[error("forbidden")]
    Forbidden,

    /// Used for both "missing" and "belongs to another tenant" so existence is
    /// never confirmed across accounts.
    #[error("not found")]
    NotFound,

    #[error("stale write")]
    Conflict { current: serde_json::Value },

    #[error("too many requests")]
    RateLimited { retry_after_secs: u64 },

    #[error("registration is closed")]
    RegistrationClosed,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal error")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"})),
            AppError::SecondFactorRequired => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "second_factor_required"}),
            ),
            AppError::Forbidden => (StatusCode::FORBIDDEN, json!({"error": "forbidden"})),
            AppError::NotFound => (StatusCode::NOT_FOUND, json!({"error": "not_found"})),
            AppError::Conflict { current } => (
                StatusCode::CONFLICT,
                json!({"error": "stale_write", "current": current}),
            ),
            AppError::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                json!({"error": "rate_limited", "retry_after_secs": retry_after_secs}),
            ),
            AppError::RegistrationClosed => (
                StatusCode::FORBIDDEN,
                json!({"error": "registration_closed"}),
            ),
            AppError::BadRequest(m) => (
                StatusCode::BAD_REQUEST,
                json!({"error": "bad_request", "detail": m}),
            ),
            // Internal details are logged, never returned.
            AppError::Config(_) | AppError::Db(_) | AppError::Internal(_) => {
                tracing::error!(error = %self, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "internal"}),
                )
            }
        };
        (status, Json(body)).into_response()
    }
}
