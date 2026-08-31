//! RFC 6238 TOTP (SHA-1, 6 digits, 30s step) as a fallback second factor.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;

/// Decode a base32 (RFC 4648, no padding required) TOTP secret.
pub fn decode_base32(secret: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for c in secret.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let up = c.to_ascii_uppercase() as u8;
        let idx = ALPHABET.iter().position(|&a| a == up)? as u32;
        bits = (bits << 5) | idx;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn hotp(key: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    bin % 10u32.pow(DIGITS)
}

/// The current TOTP code for a secret at unix time `now`.
pub fn generate(secret_base32: &str, now_unix: u64) -> Option<String> {
    let key = decode_base32(secret_base32)?;
    let code = hotp(&key, now_unix / STEP_SECS);
    Some(format!("{code:0width$}", width = DIGITS as usize))
}

/// Verify a presented code, allowing ±1 step of clock skew. Constant-time.
pub fn verify(secret_base32: &str, code: &str, now_unix: u64) -> bool {
    let Some(key) = decode_base32(secret_base32) else {
        return false;
    };
    let counter = now_unix / STEP_SECS;
    for c in [counter.wrapping_sub(1), counter, counter + 1] {
        let expected = format!("{:0width$}", hotp(&key, c), width = DIGITS as usize);
        if expected
            .as_bytes()
            .ct_eq(code.trim().as_bytes())
            .unwrap_u8()
            == 1
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_roundtrip() {
        // "JBSWY3DPEHPK3PXP" is a common test secret.
        let secret = "JBSWY3DPEHPK3PXP";
        let now = 1_700_000_000u64;
        let code = generate(secret, now).unwrap();
        assert_eq!(code.len(), 6);
        assert!(verify(secret, &code, now));
        // Accepts one step of skew.
        assert!(verify(secret, &code, now + 29));
        // Rejects a wrong code.
        assert!(!verify(secret, "000000", now) || code == "000000");
    }

    #[test]
    fn base32_decodes_known_vector() {
        // RFC 4648 base32 of ASCII "1234567890".
        assert_eq!(
            decode_base32("GEZDGNBVGY3TQOJQ").unwrap(),
            b"1234567890".to_vec()
        );
    }
}
