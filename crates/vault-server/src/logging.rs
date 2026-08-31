//! Structured logging with secret redaction.
//!
//! The zero-knowledge boundary (server spec) forbids any secret material in
//! logs. Handlers must never log request bodies directly; instead they pass
//! values through [`redact_json`] / [`redact_header`], which blank out known
//! sensitive fields. The unit tests assert nothing sensitive survives.

use serde_json::Value;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Field names whose values are always secrets and must never be logged.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "master_password",
    "new_password",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "secret",
    "totp",
    "totp_secret",
    "recovery_code",
    "ciphertext",
    "sealed",
    "blob",
    "opaque",
    "opaque_msg",
    "registration_record",
    "credential",
    "private_key",
    "private_key_b64",
];

fn is_sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|s| k == *s || k.contains(s))
}

/// Recursively redact sensitive fields in a JSON value, returning a copy safe to
/// log. Values under sensitive keys become `"<redacted>"`.
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if is_sensitive(k) {
                    out.insert(k.clone(), Value::String("<redacted>".into()));
                } else {
                    out.insert(k.clone(), redact_json(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(redact_json).collect()),
        other => other.clone(),
    }
}

/// Redact an HTTP header value for logging (e.g. `Authorization`). Anything that
/// looks like a bearer/token becomes a fixed placeholder.
pub fn redact_header(name: &str, value: &str) -> String {
    if is_sensitive(name) || value.to_ascii_lowercase().starts_with("bearer ") {
        "<redacted>".into()
    } else {
        value.to_string()
    }
}

/// Initialise the global tracing subscriber. JSON in production, pretty in dev
/// (controlled by `VAULT_LOG_FORMAT=json|pretty`). Level via `RUST_LOG`.
pub fn init() {
    let filter = EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("VAULT_LOG_FORMAT").as_deref() != Ok("pretty");
    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer().pretty()).init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_nested_secrets() {
        let input = json!({
            "username": "alice",
            "device": "laptop",
            "password": "hunter2",
            "login": {
                "access_token": "abc.def.ghi",
                // `sealed` is itself sensitive → whole subtree redacted.
                "sealed": {"ciphertext": "CIPHER", "nonce": "NONCE"}
            },
            "items": [
                {"title": "GitHub", "recovery_code": "AAAAA-BBBBB"}
            ]
        });
        let out = redact_json(&input);
        let s = out.to_string();

        // Non-secrets preserved.
        assert!(s.contains("alice"));
        assert!(s.contains("laptop"));
        assert!(s.contains("GitHub"));

        // Secrets gone (including everything under the sensitive `sealed` key).
        assert!(!s.contains("hunter2"));
        assert!(!s.contains("abc.def.ghi"));
        assert!(!s.contains("CIPHER"));
        assert!(!s.contains("NONCE"));
        assert!(!s.contains("AAAAA-BBBBB"));
        assert_eq!(out["password"], json!("<redacted>"));
        assert_eq!(out["device"], json!("laptop"));
        assert_eq!(out["login"]["access_token"], json!("<redacted>"));
        assert_eq!(out["login"]["sealed"], json!("<redacted>"));
    }

    #[test]
    fn redacts_authorization_header() {
        assert_eq!(redact_header("authorization", "Bearer xyz"), "<redacted>");
        assert_eq!(redact_header("Authorization", "bearer xyz"), "<redacted>");
        assert_eq!(redact_header("x-request-id", "req-123"), "req-123");
    }
}
