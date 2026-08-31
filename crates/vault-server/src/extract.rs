//! Request extractors: bearer-token authentication and client IP.

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::error::AppError;
use crate::state::SharedState;

/// An authenticated caller, established from a valid access token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub account_id: Uuid,
    pub device_id: Uuid,
}

#[async_trait]
impl FromRequestParts<SharedState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, AppError> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or(AppError::Unauthorized)?;
        let claims = state.token_key.verify(token)?;
        Ok(AuthUser {
            account_id: claims.account_id,
            device_id: claims.device_id,
        })
    }
}

/// Best-effort client IP from reverse-proxy headers.
#[derive(Debug, Clone)]
pub struct ClientIp(pub Option<String>);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                parts
                    .headers
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            });
        Ok(ClientIp(ip))
    }
}
