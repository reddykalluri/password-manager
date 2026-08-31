//! Minimal AWS SigV4 PUT for S3-compatible object stores (MinIO, Backblaze,
//! Wasabi, AWS). Path-style addressing. Built only under the `s3` feature.

#![cfg(feature = "s3")]

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::backup::s3::S3Target;
use crate::error::{AppError, AppResult};

type HmacSha256 = Hmac<Sha256>;

const DATE_FMT: &[FormatItem<'static>] = format_description!("[year][month][day]");
const AMZ_FMT: &[FormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// PUT `body` to `{endpoint}/{bucket}/{key}` with a SigV4 signature.
pub async fn put_object(target: &S3Target, key: &str, body: &[u8]) -> AppResult<()> {
    let now = OffsetDateTime::now_utc();
    let amz_date = now
        .format(AMZ_FMT)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let date = now
        .format(DATE_FMT)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let endpoint = target.endpoint.trim_end_matches('/');
    let host = endpoint
        .split("://")
        .nth(1)
        .unwrap_or(endpoint)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    let canonical_uri = format!("/{}/{}", target.bucket, uri_encode(key, false));
    let payload_hash = sha256_hex(body);

    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let scope = format!("{date}/{}/s3/aws4_request", target.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    // Derive the signing key.
    let k_date = hmac(
        format!("AWS4{}", target.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, target.region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        target.access_key
    );

    let url = format!("{endpoint}{canonical_uri}");
    let resp = reqwest::Client::new()
        .put(&url)
        .header("host", host)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("authorization", authorization)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("S3 upload request failed: {e}")))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(AppError::Internal(format!(
            "S3 upload rejected: {}",
            resp.status()
        )))
    }
}

/// RFC3986 encoding for S3 canonical URIs. `encode_slash` controls whether `/`
/// is escaped (false for object keys used as path segments here).
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
