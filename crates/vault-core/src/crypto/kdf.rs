//! Key derivation: Argon2id (password → master key) and HKDF-SHA256 (key
//! separation within the hierarchy).
//!
//! Per design.md Decision 3, Argon2id parameters vary per target and are stored
//! alongside ciphertext so a client can upgrade them at next unlock.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::secret::{Key256, SecretVec};
use crate::error::{Error, Result};

/// Argon2id cost parameters. Persisted next to the wrapped account key so the
/// exact derivation can be reproduced and later upgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub mem_kib: u32,
    /// Time cost (iterations).
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl KdfParams {
    /// Native minimum (server, desktop, mobile with capable hardware):
    /// 64 MiB / t=3 / p=4. See design.md Decision 3.
    pub const NATIVE_MIN: KdfParams = KdfParams {
        mem_kib: 64 * 1024,
        iterations: 3,
        parallelism: 4,
    };

    /// WASM / older-mobile minimum: 48 MiB / t=3 / p=1. Renegotiated upward when
    /// the client detects capable hardware.
    pub const WASM_MIN: KdfParams = KdfParams {
        mem_kib: 48 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Reject parameters weaker than the WASM floor; guards against a malicious
    /// server tricking a client into a cheap KDF.
    pub fn meets_minimum(&self) -> bool {
        self.mem_kib >= Self::WASM_MIN.mem_kib
            && self.iterations >= Self::WASM_MIN.iterations
            && self.parallelism >= 1
    }

    fn to_argon2_params(self) -> Result<Params> {
        Params::new(
            self.mem_kib,
            self.iterations,
            self.parallelism,
            Some(32), // output length: 256-bit master key
        )
        .map_err(|e| Error::Crypto(format!("invalid Argon2 params: {e}")))
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::NATIVE_MIN
    }
}

/// Length of the random salt bound to each account's KDF.
pub const KDF_SALT_LEN: usize = 16;

/// Derive the 256-bit master key from the master password with Argon2id.
///
/// The master key never leaves the device and is never transmitted.
pub fn derive_master_key(
    password: &SecretVec,
    salt: &[u8; KDF_SALT_LEN],
    params: KdfParams,
) -> Result<Key256> {
    if !params.meets_minimum() {
        return Err(Error::Crypto(
            "KDF parameters below the accepted minimum".into(),
        ));
    }
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params.to_argon2_params()?,
    );
    let mut out = Key256::zeroed();
    argon
        .hash_password_into(password.expose(), salt, out.expose_mut())
        .map_err(|e| Error::Crypto(format!("Argon2id failed: {e}")))?;
    Ok(out)
}

/// HKDF-SHA256 expand of a parent key into a labelled 256-bit child key.
///
/// Used for master key → MUK and any other domain separation. The `info` label
/// pins the purpose so the same parent never yields two identical children for
/// different roles.
pub fn hkdf_derive_key(parent: &Key256, info: &[u8]) -> Result<Key256> {
    let hk = Hkdf::<Sha256>::new(None, parent.expose());
    let mut out = Key256::zeroed();
    hk.expand(info, out.expose_mut())
        .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;
    Ok(out)
}

/// HKDF label for the master unlock key (MUK).
pub const INFO_MUK: &[u8] = b"vault-core:v1:muk";
