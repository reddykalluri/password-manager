//! CSPRNG access. Single choke point so every random draw in the crate uses the
//! operating-system entropy source.

use rand::rngs::OsRng;
use rand::RngCore;

use super::secret::Key256;

/// Fill `buf` with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// Generate a fresh random 256-bit key (account key, vault key, etc.).
pub fn random_key256() -> Key256 {
    let mut k = Key256::zeroed();
    fill_random(k.expose_mut());
    k
}

/// Generate `N` random bytes into a fixed array.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    fill_random(&mut a);
    a
}

/// Uniform integer in `0..bound` without modulo bias (rejection sampling).
/// `bound` must be non-zero.
pub fn uniform_below(bound: u32) -> u32 {
    debug_assert!(bound > 0);
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let mut b = [0u8; 4];
        fill_random(&mut b);
        let v = u32::from_le_bytes(b);
        if v < zone {
            return v % bound;
        }
    }
}
