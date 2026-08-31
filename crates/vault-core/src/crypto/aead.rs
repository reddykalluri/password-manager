//! Authenticated encryption with XChaCha20-Poly1305.
//!
//! Every encryption draws a fresh random 192-bit nonce, so nonce reuse under a
//! given key is not a practical concern even across large vaults.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use super::rng::fill_random;
use super::secret::Key256;
use crate::error::{Error, Result};

/// XChaCha20-Poly1305 nonce length (192 bits).
pub const NONCE_LEN: usize = 24;

/// A sealed blob: random nonce plus ciphertext+tag. Serialised as-is to storage
/// and the wire; carries no plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    #[serde(with = "crate::codec::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::codec::b64")]
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` under `key`, binding `aad` (associated data, e.g. the
/// item UUID) into the authentication tag.
pub fn seal(key: &Key256, plaintext: &[u8], aad: &[u8]) -> Result<SealedBlob> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("AEAD seal failed".into()))?;
    Ok(SealedBlob {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt a [`SealedBlob`], verifying `aad`. Returns [`Error::Decrypt`] on any
/// authentication failure (wrong key, tampering, or AAD mismatch).
pub fn open(key: &Key256, blob: &SealedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    if blob.nonce.len() != NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let nonce = XNonce::from_slice(&blob.nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

/// Wrap (encrypt) one key under another. Key-wrapping is ordinary AEAD over the
/// child key's raw bytes; the label is bound as AAD for domain separation.
pub fn wrap_key(wrapping_key: &Key256, child: &Key256, label: &[u8]) -> Result<SealedBlob> {
    seal(wrapping_key, child.expose(), label)
}

/// Unwrap a key previously sealed with [`wrap_key`].
pub fn unwrap_key(wrapping_key: &Key256, blob: &SealedBlob, label: &[u8]) -> Result<Key256> {
    let bytes = open(wrapping_key, blob, label)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("unwrapped key wrong length".into()))?;
    Ok(Key256::new(arr))
}
