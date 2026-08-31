//! Cryptography layer: KDF, AEAD, CSPRNG, and zeroizing secret types.
//!
//! This module is the only place primitive crypto is performed. Higher layers
//! (key hierarchy, item store) call into it and never touch the underlying
//! crates directly.

pub mod aead;
pub mod kdf;
pub mod rng;
pub mod secret;

pub use aead::{open, seal, unwrap_key, wrap_key, SealedBlob, NONCE_LEN};
pub use kdf::{derive_master_key, hkdf_derive_key, KdfParams, INFO_MUK, KDF_SALT_LEN};
pub use rng::{fill_random, random_array, random_key256, uniform_below};
pub use secret::{Key256, SecretBytes, SecretVec};
