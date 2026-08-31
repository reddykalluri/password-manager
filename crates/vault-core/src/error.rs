//! Crate-wide error type.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Deliberately opaque: never reveal whether it was a wrong key, tampering,
    /// or AAD mismatch.
    #[error("decryption failed")]
    Decrypt,

    #[error("vault is locked")]
    Locked,

    #[error("item not found")]
    NotFound,

    #[error("stale write: base version {base}, current {current}")]
    StaleWrite { base: u64, current: u64 },

    #[error("invalid recovery code")]
    InvalidRecoveryCode,

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("import/export error: {0}")]
    Import(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
