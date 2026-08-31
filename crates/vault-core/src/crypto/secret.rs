//! Zeroizing secret containers.
//!
//! All raw key material lives in [`SecretBytes`] so it is wiped from memory on
//! drop (and on vault lock). Never store key material in a plain `Vec<u8>` or
//! `[u8; N]`.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A fixed-size secret that is zeroised on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Wrap raw bytes as a secret.
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// A zero-filled secret, typically used as a scratch buffer to be filled.
    pub fn zeroed() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// Borrow the raw bytes. Callers must not copy these into non-zeroizing
    /// storage.
    pub fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Mutable access, for KDF/HKDF output buffers.
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

/// Never render secret contents, even accidentally via logs.
impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(<redacted>)")
    }
}

/// A variable-length secret (e.g. the master password bytes), zeroised on drop.
#[derive(Clone, Default, ZeroizeOnDrop)]
pub struct SecretVec {
    bytes: Vec<u8>,
}

impl SecretVec {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl From<&str> for SecretVec {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }
}

impl From<String> for SecretVec {
    fn from(mut s: String) -> Self {
        let out = Self::new(s.as_bytes().to_vec());
        s.zeroize();
        out
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVec(<redacted>)")
    }
}

/// A 256-bit symmetric key, the workhorse size across the hierarchy.
pub type Key256 = SecretBytes<32>;
