//! The zero-knowledge key hierarchy (design.md Decision 2).
//!
//! ```text
//! master password ──Argon2id──► master key ──HKDF──► MUK
//! account key (random 256-bit) ── wrapped by MUK  (and, independently, by a recovery key)
//! vault key   (random per vault) ── wrapped by account key
//! item ciphertext ── XChaCha20-Poly1305 under the vault key
//! ```
//!
//! A master-password change re-wraps the account key only; item ciphertext is
//! untouched. The master key and master password never leave the device.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::crypto::{
    derive_master_key, hkdf_derive_key, random_array, random_key256, unwrap_key, wrap_key,
    KdfParams, Key256, SealedBlob, SecretVec, INFO_MUK, KDF_SALT_LEN,
};
use crate::error::{Error, Result};

/// AAD labels bind each wrapped key to its role, so a blob wrapped for one
/// purpose cannot be substituted for another.
const WRAP_ACCOUNT_BY_MUK: &[u8] = b"vault-core:v1:wrap:account-key:muk";
const WRAP_ACCOUNT_BY_RECOVERY: &[u8] = b"vault-core:v1:wrap:account-key:recovery";
const WRAP_VAULT_BY_ACCOUNT: &[u8] = b"vault-core:v1:wrap:vault-key:account";

/// HKDF label deriving the recovery-wrapping key from the recovery code.
const INFO_RECOVERY: &[u8] = b"vault-core:v1:recovery";

/// Recovery code entropy: 128 bits.
const RECOVERY_ENTROPY_BYTES: usize = 16;

/// A wrapped vault key as stored/synced (never the raw key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyRecord {
    pub vault_id: Uuid,
    pub wrapped: SealedBlob,
}

/// All account cryptographic material that is safe to persist on the server or
/// in a local cache. Contains only salts, KDF parameters, and wrapped keys —
/// no plaintext key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCrypto {
    #[serde(with = "crate::codec::b64")]
    pub kdf_salt: Vec<u8>,
    pub kdf_params: KdfParams,
    /// Account key wrapped by the MUK (the password path).
    pub account_key_by_muk: SealedBlob,
    /// Salt for deriving the recovery-wrapping key from the recovery code.
    #[serde(with = "crate::codec::b64")]
    pub recovery_salt: Vec<u8>,
    /// Account key wrapped by the recovery key (the recovery-code path).
    pub account_key_by_recovery: SealedBlob,
    /// Vault keys, each wrapped by the account key.
    pub vaults: Vec<VaultKeyRecord>,
}

impl AccountCrypto {
    fn kdf_salt_array(&self) -> Result<[u8; KDF_SALT_LEN]> {
        self.kdf_salt
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto("kdf_salt wrong length".into()))
    }
}

/// The unlocked, in-memory key material. Zeroised on [`Drop`] (and on lock, when
/// the owning vault drops it).
#[derive(Debug)]
pub struct KeyRing {
    account_key: Key256,
    vault_keys: HashMap<Uuid, Key256>,
}

impl KeyRing {
    /// The primary (first-enrolled) vault id, if any.
    pub fn primary_vault(&self) -> Option<Uuid> {
        self.vault_keys.keys().copied().min()
    }

    /// Borrow a vault key for encrypt/decrypt operations.
    pub fn vault_key(&self, vault_id: Uuid) -> Result<&Key256> {
        self.vault_keys.get(&vault_id).ok_or(Error::NotFound)
    }

    pub fn vault_ids(&self) -> Vec<Uuid> {
        let mut v: Vec<Uuid> = self.vault_keys.keys().copied().collect();
        v.sort();
        v
    }

    /// Add a new vault: generate a random vault key, wrap it under the account
    /// key, and return the record for persistence.
    pub fn create_vault(&mut self) -> Result<VaultKeyRecord> {
        let vault_id = Uuid::new_v4();
        let vault_key = random_key256();
        let wrapped = wrap_key(&self.account_key, &vault_key, WRAP_VAULT_BY_ACCOUNT)?;
        self.vault_keys.insert(vault_id, vault_key);
        Ok(VaultKeyRecord { vault_id, wrapped })
    }

    /// Export the account key for storage in a hardware-backed OS keystore to
    /// enable biometric unlock (Touch ID/Secure Enclave, Windows Hello/TPM).
    ///
    /// The returned key is highly sensitive: the caller MUST store it only in
    /// biometry-gated, this-device-only hardware storage that is invalidated on
    /// biometric-enrolment change, and require a master-password unlock again
    /// after reboot. It is the "session key" the OS keystore wraps.
    pub fn export_account_key(&self) -> Key256 {
        self.account_key.clone()
    }
}

/// Unlock using an account key previously exported via
/// [`KeyRing::export_account_key`] (the biometric path), skipping the password
/// KDF. `crypto` supplies the wrapped vault keys.
pub fn unlock_with_account_key(account_key: Key256, crypto: &AccountCrypto) -> Result<KeyRing> {
    unwrap_vaults(account_key, crypto)
}

/// Output of enrolment: server-storable material plus the one-time recovery code
/// to display to the user and the unlocked keyring for the current session.
#[derive(Debug)]
pub struct Enrollment {
    pub crypto: AccountCrypto,
    /// Human-formatted recovery code, shown exactly once. Never persisted.
    pub recovery_code: String,
    pub keyring: KeyRing,
}

/// Enrol a new account from a master password. Creates the account key, an
/// initial vault, and both the password and recovery wrapping paths.
pub fn enroll(password: &SecretVec, params: KdfParams) -> Result<Enrollment> {
    if !params.meets_minimum() {
        return Err(Error::Crypto("KDF parameters below minimum".into()));
    }
    // Password path.
    let kdf_salt = random_array::<KDF_SALT_LEN>();
    let master_key = derive_master_key(password, &kdf_salt, params)?;
    let muk = hkdf_derive_key(&master_key, INFO_MUK)?;

    let account_key = random_key256();
    let account_key_by_muk = wrap_key(&muk, &account_key, WRAP_ACCOUNT_BY_MUK)?;

    // Recovery path: 128-bit code → recovery key → wrap the same account key.
    let recovery_bytes = random_array::<RECOVERY_ENTROPY_BYTES>();
    let recovery_salt = random_array::<KDF_SALT_LEN>();
    let recovery_key = derive_recovery_key(&recovery_bytes, &recovery_salt)?;
    let account_key_by_recovery = wrap_key(&recovery_key, &account_key, WRAP_ACCOUNT_BY_RECOVERY)?;

    // Initial vault.
    let mut keyring = KeyRing {
        account_key,
        vault_keys: HashMap::new(),
    };
    let vault_record = keyring.create_vault()?;

    let crypto = AccountCrypto {
        kdf_salt: kdf_salt.to_vec(),
        kdf_params: params,
        account_key_by_muk,
        recovery_salt: recovery_salt.to_vec(),
        account_key_by_recovery,
        vaults: vec![vault_record],
    };

    Ok(Enrollment {
        crypto,
        recovery_code: format_recovery_code(&recovery_bytes),
        keyring,
    })
}

/// Unlock with the master password: derive the master key, then the MUK, unwrap
/// the account key, and unwrap every vault key.
pub fn unlock(password: &SecretVec, crypto: &AccountCrypto) -> Result<KeyRing> {
    let salt = crypto.kdf_salt_array()?;
    let master_key = derive_master_key(password, &salt, crypto.kdf_params)?;
    let muk = hkdf_derive_key(&master_key, INFO_MUK)?;
    let account_key = unwrap_key(&muk, &crypto.account_key_by_muk, WRAP_ACCOUNT_BY_MUK)?;
    unwrap_vaults(account_key, crypto)
}

/// Unlock with the recovery code (e.g. after a forgotten master password).
pub fn unlock_with_recovery(recovery_code: &str, crypto: &AccountCrypto) -> Result<KeyRing> {
    let recovery_bytes = parse_recovery_code(recovery_code)?;
    let salt: [u8; KDF_SALT_LEN] = crypto
        .recovery_salt
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("recovery_salt wrong length".into()))?;
    let recovery_key = derive_recovery_key(&recovery_bytes, &salt)?;
    let account_key = unwrap_key(
        &recovery_key,
        &crypto.account_key_by_recovery,
        WRAP_ACCOUNT_BY_RECOVERY,
    )
    .map_err(|_| Error::InvalidRecoveryCode)?;
    unwrap_vaults(account_key, crypto)
}

fn unwrap_vaults(account_key: Key256, crypto: &AccountCrypto) -> Result<KeyRing> {
    let mut vault_keys = HashMap::new();
    for rec in &crypto.vaults {
        let vk = unwrap_key(&account_key, &rec.wrapped, WRAP_VAULT_BY_ACCOUNT)?;
        vault_keys.insert(rec.vault_id, vk);
    }
    Ok(KeyRing {
        account_key,
        vault_keys,
    })
}

/// Change the master password. Re-derives the MUK from the new password and
/// re-wraps the account key. Item ciphertext and vault-key wrapping are
/// untouched, so this is O(1) in vault size.
///
/// Returns updated [`AccountCrypto`] to persist. The current session's keyring
/// remains valid.
pub fn change_master_password(
    current_password: &SecretVec,
    new_password: &SecretVec,
    new_params: KdfParams,
    crypto: &AccountCrypto,
) -> Result<AccountCrypto> {
    if !new_params.meets_minimum() {
        return Err(Error::Crypto("KDF parameters below minimum".into()));
    }
    // Recover the account key via the current password (authenticates the change).
    let cur_salt = crypto.kdf_salt_array()?;
    let cur_master = derive_master_key(current_password, &cur_salt, crypto.kdf_params)?;
    let cur_muk = hkdf_derive_key(&cur_master, INFO_MUK)?;
    let account_key = unwrap_key(&cur_muk, &crypto.account_key_by_muk, WRAP_ACCOUNT_BY_MUK)?;

    // Re-wrap under the new password path.
    let new_salt = random_array::<KDF_SALT_LEN>();
    let new_master = derive_master_key(new_password, &new_salt, new_params)?;
    let new_muk = hkdf_derive_key(&new_master, INFO_MUK)?;
    let account_key_by_muk = wrap_key(&new_muk, &account_key, WRAP_ACCOUNT_BY_MUK)?;

    Ok(AccountCrypto {
        kdf_salt: new_salt.to_vec(),
        kdf_params: new_params,
        account_key_by_muk,
        // Recovery path and vault keys are unchanged.
        recovery_salt: crypto.recovery_salt.clone(),
        account_key_by_recovery: crypto.account_key_by_recovery.clone(),
        vaults: crypto.vaults.clone(),
    })
}

/// Regenerate the recovery code, re-wrapping the account key under a fresh code.
/// Requires the current password to authenticate. Returns the new code (shown
/// once) and updated crypto material.
pub fn regenerate_recovery_code(
    password: &SecretVec,
    crypto: &AccountCrypto,
) -> Result<(String, AccountCrypto)> {
    let salt = crypto.kdf_salt_array()?;
    let master = derive_master_key(password, &salt, crypto.kdf_params)?;
    let muk = hkdf_derive_key(&master, INFO_MUK)?;
    let account_key = unwrap_key(&muk, &crypto.account_key_by_muk, WRAP_ACCOUNT_BY_MUK)?;

    let recovery_bytes = random_array::<RECOVERY_ENTROPY_BYTES>();
    let recovery_salt = random_array::<KDF_SALT_LEN>();
    let recovery_key = derive_recovery_key(&recovery_bytes, &recovery_salt)?;
    let account_key_by_recovery = wrap_key(&recovery_key, &account_key, WRAP_ACCOUNT_BY_RECOVERY)?;

    let mut updated = crypto.clone();
    updated.recovery_salt = recovery_salt.to_vec();
    updated.account_key_by_recovery = account_key_by_recovery;
    Ok((format_recovery_code(&recovery_bytes), updated))
}

/// Derive the recovery-wrapping key from the raw recovery code bytes. The code
/// is 128-bit random (high entropy), so HKDF-Extract/Expand suffices without an
/// expensive password KDF.
fn derive_recovery_key(
    recovery_bytes: &[u8; RECOVERY_ENTROPY_BYTES],
    salt: &[u8; KDF_SALT_LEN],
) -> Result<Key256> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(salt), recovery_bytes);
    let mut out = Key256::zeroed();
    hk.expand(INFO_RECOVERY, out.expose_mut())
        .map_err(|e| Error::Crypto(format!("recovery HKDF failed: {e}")))?;
    Ok(out)
}

/// Crockford base32 alphabet (no I, L, O, U) for legible recovery codes.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Format 128 bits as five groups of five Crockford-base32 characters
/// (e.g. `A1B2C-3D4E5-...`). Encodes 125 of the 128 bits; the display is a
/// user-facing convenience, while the full 16 bytes remain the secret.
fn format_recovery_code(bytes: &[u8; RECOVERY_ENTROPY_BYTES]) -> String {
    // Encode all 16 bytes (128 bits) as base32 → 26 chars (last carries 2 bits).
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = String::new();
    let mut count = 0;
    for &b in bytes.iter() {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 0x1f) as usize;
            out.push(CROCKFORD[idx] as char);
            count += 1;
            if count % 5 == 0 {
                out.push('-');
            }
        }
    }
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 0x1f) as usize;
        out.push(CROCKFORD[idx] as char);
    }
    out.trim_end_matches('-').to_string()
}

/// Parse a user-entered recovery code back into its 16 secret bytes. Accepts
/// lowercase, spaces, and dashes, and maps common Crockford substitutions.
fn parse_recovery_code(code: &str) -> Result<[u8; RECOVERY_ENTROPY_BYTES]> {
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(RECOVERY_ENTROPY_BYTES);
    for ch in code.chars() {
        if ch == '-' || ch.is_whitespace() {
            continue;
        }
        let up = ch.to_ascii_uppercase();
        let mapped = match up {
            'I' | 'L' => '1',
            'O' => '0',
            'U' => 'V',
            other => other,
        };
        let idx = CROCKFORD
            .iter()
            .position(|&c| c as char == mapped)
            .ok_or(Error::InvalidRecoveryCode)? as u32;
        bits = (bits << 5) | idx;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xff) as u8);
        }
    }
    out.truncate(RECOVERY_ENTROPY_BYTES);
    out.as_slice()
        .try_into()
        .map_err(|_| Error::InvalidRecoveryCode)
}
