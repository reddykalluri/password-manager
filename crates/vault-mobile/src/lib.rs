//! UniFFI bindings for `vault-core`, wrapped for Kotlin (Android) and Swift
//! (iOS). The interface mirrors the WASM and Tauri facades: JSON strings in and
//! out, plus an opaque [`VaultHandle`] object holding the unlocked native vault.

mod opaque;

use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use vault_core::crypto::{KdfParams, SecretVec};
use vault_core::generator::{
    generate_passphrase as vc_passphrase, generate_password as vc_password, rate_strength,
    PassphraseOptions, PasswordOptions,
};
use vault_core::importer::{
    export_csv_gated, export_encrypted_json, import_1pux_json, import_bitwarden_json, import_csv,
    ImportResult,
};
use vault_core::item::ItemContent;
use vault_core::keys::{self, AccountCrypto};
use vault_core::store::{ItemRecord, Vault};

uniffi::setup_scaffolding!();

/// Errors surfaced to Kotlin/Swift.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("{0}")]
    Message(String),
}

fn err<E: std::fmt::Display>(e: E) -> VaultError {
    VaultError::Message(e.to_string())
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

type R<T> = Result<T, VaultError>;

// --- stateless functions ---------------------------------------------------

#[uniffi::export]
pub fn benchmark_kdf(target_ms: f64) -> R<String> {
    let stretch = KdfParams {
        mem_kib: 64 * 1024,
        iterations: 3,
        parallelism: 4,
    };
    let candidates = [stretch, KdfParams::WASM_MIN];
    let password = SecretVec::from("kdf-benchmark-probe");
    let salt = [0u8; vault_core::crypto::KDF_SALT_LEN];
    let mut chosen = KdfParams::WASM_MIN;
    for c in candidates {
        let t0 = std::time::Instant::now();
        let _ = vault_core::crypto::derive_master_key(&password, &salt, c);
        if t0.elapsed().as_secs_f64() * 1000.0 <= target_ms {
            chosen = c;
            break;
        }
    }
    serde_json::to_string(&chosen).map_err(err)
}

#[uniffi::export]
pub fn default_kdf_params() -> R<String> {
    serde_json::to_string(&KdfParams::WASM_MIN).map_err(err)
}

#[derive(Deserialize)]
struct PasswordOptionsDto {
    length: u32,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    #[serde(default)]
    exclude_ambiguous: bool,
}

#[uniffi::export]
pub fn generate_password(options_json: String) -> R<String> {
    let d: PasswordOptionsDto = serde_json::from_str(&options_json).map_err(err)?;
    vc_password(&PasswordOptions {
        length: d.length as usize,
        lowercase: d.lowercase,
        uppercase: d.uppercase,
        digits: d.digits,
        symbols: d.symbols,
        exclude_ambiguous: d.exclude_ambiguous,
    })
    .map_err(err)
}

#[derive(Deserialize)]
struct PassphraseOptionsDto {
    words: u32,
    separator: String,
    #[serde(default)]
    capitalize: bool,
    #[serde(default)]
    include_number: bool,
}

#[uniffi::export]
pub fn generate_passphrase(options_json: String) -> R<String> {
    let d: PassphraseOptionsDto = serde_json::from_str(&options_json).map_err(err)?;
    vc_passphrase(&PassphraseOptions {
        words: d.words as usize,
        separator: d.separator,
        capitalize: d.capitalize,
        include_number: d.include_number,
    })
    .map_err(err)
}

#[derive(Serialize)]
struct StrengthDto {
    score: u8,
    entropy_bits: f64,
    label: String,
}

#[uniffi::export]
pub fn rate_password_strength(password: String) -> R<String> {
    let s = rate_strength(&password);
    serde_json::to_string(&StrengthDto {
        score: s.score,
        entropy_bits: s.entropy_bits,
        label: s.label().to_string(),
    })
    .map_err(err)
}

#[uniffi::export]
pub fn opaque_register_start(password: String) -> R<String> {
    opaque::register_start(&password).map_err(VaultError::Message)
}
#[uniffi::export]
pub fn opaque_register_finish(state_b64: String, password: String, response_b64: String) -> R<String> {
    opaque::register_finish(&state_b64, &password, &response_b64).map_err(VaultError::Message)
}
#[uniffi::export]
pub fn opaque_login_start(password: String) -> R<String> {
    opaque::login_start(&password).map_err(VaultError::Message)
}
#[uniffi::export]
pub fn opaque_login_finish(state_b64: String, password: String, response_b64: String) -> R<String> {
    opaque::login_finish(&state_b64, &password, &response_b64).map_err(VaultError::Message)
}

// --- the vault handle ------------------------------------------------------

struct Inner {
    vault: Vault,
    crypto: AccountCrypto,
    recovery: Option<String>,
}

/// An unlocked vault. Dropping the last reference zeroises key material.
#[derive(uniffi::Object)]
pub struct VaultHandle {
    inner: Mutex<Inner>,
}

#[derive(Serialize)]
struct RevisionDto {
    modified_at: String,
    content: ItemContent,
}
#[derive(Serialize)]
struct ImportPreviewDto {
    items: Vec<ItemContent>,
    errors: Vec<ImportErrorDto>,
}
#[derive(Serialize)]
struct ImportErrorDto {
    row: u32,
    message: String,
}

#[uniffi::export]
impl VaultHandle {
    /// Enrol a new account.
    #[uniffi::constructor]
    pub fn enroll(password: String, params_json: String) -> R<Arc<Self>> {
        let params: KdfParams = serde_json::from_str(&params_json).map_err(err)?;
        let enrollment = keys::enroll(&SecretVec::from(password.as_str()), params).map_err(err)?;
        let recovery = enrollment.recovery_code.clone();
        let vault = Vault::from_keyring(enrollment.keyring, now());
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                vault,
                crypto: enrollment.crypto,
                recovery: Some(recovery),
            }),
        }))
    }

    /// Unlock from stored crypto material + cached records.
    #[uniffi::constructor]
    pub fn unlock(password: String, crypto_json: String, records_json: String) -> R<Arc<Self>> {
        let crypto: AccountCrypto = serde_json::from_str(&crypto_json).map_err(err)?;
        let records: Vec<ItemRecord> = serde_json::from_str(&records_json).map_err(err)?;
        let vault =
            Vault::open(&SecretVec::from(password.as_str()), &crypto, records, now()).map_err(err)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                vault,
                crypto,
                recovery: None,
            }),
        }))
    }

    /// Unlock via recovery code.
    #[uniffi::constructor]
    pub fn unlock_with_recovery(
        recovery_code: String,
        crypto_json: String,
        records_json: String,
    ) -> R<Arc<Self>> {
        let crypto: AccountCrypto = serde_json::from_str(&crypto_json).map_err(err)?;
        let records: Vec<ItemRecord> = serde_json::from_str(&records_json).map_err(err)?;
        let vault = Vault::open_with_recovery(&recovery_code, &crypto, records, now()).map_err(err)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                vault,
                crypto,
                recovery: None,
            }),
        }))
    }

    pub fn take_recovery_code(&self) -> Option<String> {
        self.inner.lock().recovery.take()
    }

    pub fn account_crypto(&self) -> R<String> {
        serde_json::to_string(&self.inner.lock().crypto).map_err(err)
    }

    pub fn records(&self) -> R<String> {
        let g = self.inner.lock();
        let recs: Vec<ItemRecord> = g.vault.records().cloned().collect();
        serde_json::to_string(&recs).map_err(err)
    }

    pub fn apply_record(&self, record_json: String) -> R<()> {
        let rec: ItemRecord = serde_json::from_str(&record_json).map_err(err)?;
        self.inner.lock().vault.ingest_record(rec).map_err(err)
    }

    pub fn create_item(&self, content_json: String) -> R<String> {
        let content: ItemContent = serde_json::from_str(&content_json).map_err(err)?;
        self.inner
            .lock()
            .vault
            .create(None, &content, now())
            .map(|id| id.to_string())
            .map_err(err)
    }

    pub fn get_item(&self, id: String) -> R<String> {
        let g = self.inner.lock();
        let c = g.vault.get(parse_id(&id)?).map_err(err)?;
        serde_json::to_string(&c).map_err(err)
    }

    pub fn update_item(&self, id: String, content_json: String) -> R<()> {
        let content: ItemContent = serde_json::from_str(&content_json).map_err(err)?;
        self.inner
            .lock()
            .vault
            .update(parse_id(&id)?, &content, now())
            .map_err(err)
    }

    pub fn move_to_bin(&self, id: String) -> R<()> {
        self.inner.lock().vault.move_to_bin(parse_id(&id)?, now()).map_err(err)
    }
    pub fn restore_from_bin(&self, id: String) -> R<()> {
        self.inner.lock().vault.restore_from_bin(parse_id(&id)?, now()).map_err(err)
    }
    pub fn delete_permanent(&self, id: String) -> R<()> {
        self.inner.lock().vault.delete_permanent(parse_id(&id)?, now()).map_err(err)
    }

    pub fn list_active(&self) -> Vec<String> {
        self.inner.lock().vault.list_active().into_iter().map(|i| i.to_string()).collect()
    }
    pub fn list_bin(&self) -> R<Vec<String>> {
        Ok(self.inner.lock().vault.list_bin().map_err(err)?.into_iter().map(|i| i.to_string()).collect())
    }
    pub fn search(&self, query: String) -> Vec<String> {
        self.inner.lock().vault.search(&query).into_iter().map(|i| i.to_string()).collect()
    }
    pub fn candidates_for(&self, url: String) -> R<Vec<String>> {
        Ok(self
            .inner
            .lock()
            .vault
            .candidates_for(&url)
            .map_err(err)?
            .into_iter()
            .map(|i| i.to_string())
            .collect())
    }
    pub fn folders(&self) -> R<Vec<String>> {
        self.inner.lock().vault.folders().map_err(err)
    }
    pub fn tags(&self) -> R<Vec<String>> {
        self.inner.lock().vault.tags().map_err(err)
    }

    pub fn history(&self, id: String) -> R<String> {
        let g = self.inner.lock();
        let revs = g.vault.history(parse_id(&id)?).map_err(err)?;
        let dto: Vec<RevisionDto> = revs
            .into_iter()
            .map(|(ts, content)| RevisionDto {
                modified_at: ts
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                content,
            })
            .collect();
        serde_json::to_string(&dto).map_err(err)
    }

    pub fn restore_revision(&self, id: String, index: u32) -> R<()> {
        self.inner
            .lock()
            .vault
            .restore_revision(parse_id(&id)?, index as usize, now())
            .map_err(err)
    }

    pub fn change_master_password(&self, current: String, next: String, params_json: String) -> R<String> {
        let params: KdfParams = serde_json::from_str(&params_json).map_err(err)?;
        let mut g = self.inner.lock();
        let updated = keys::change_master_password(
            &SecretVec::from(current.as_str()),
            &SecretVec::from(next.as_str()),
            params,
            &g.crypto,
        )
        .map_err(err)?;
        g.crypto = updated;
        serde_json::to_string(&g.crypto).map_err(err)
    }

    pub fn regenerate_recovery_code(&self, password: String) -> R<String> {
        let mut g = self.inner.lock();
        let (code, updated) =
            keys::regenerate_recovery_code(&SecretVec::from(password.as_str()), &g.crypto).map_err(err)?;
        g.crypto = updated;
        Ok(code)
    }

    pub fn import_preview(&self, kind: String, data: String) -> R<String> {
        let result: ImportResult = match kind.as_str() {
            "csv" => import_csv(&data).map_err(err)?,
            "bitwarden" => import_bitwarden_json(&data).map_err(err)?,
            "1pux" => import_1pux_json(&data).map_err(err)?,
            other => return Err(VaultError::Message(format!("unknown import kind: {other}"))),
        };
        let dto = ImportPreviewDto {
            items: result.items,
            errors: result
                .errors
                .into_iter()
                .map(|x| ImportErrorDto {
                    row: x.row as u32,
                    message: x.message,
                })
                .collect(),
        };
        serde_json::to_string(&dto).map_err(err)
    }

    pub fn import_commit(&self, items_json: String) -> R<u32> {
        let items: Vec<ItemContent> = serde_json::from_str(&items_json).map_err(err)?;
        let mut g = self.inner.lock();
        let mut n = 0u32;
        for content in &items {
            g.vault.create(None, content, now()).map_err(err)?;
            n += 1;
        }
        Ok(n)
    }

    pub fn export_encrypted(&self, export_password: String) -> R<String> {
        let g = self.inner.lock();
        let items: Vec<ItemContent> = g
            .vault
            .list_active()
            .into_iter()
            .map(|id| g.vault.get(id))
            .collect::<Result<_, _>>()
            .map_err(err)?;
        export_encrypted_json(&items, &SecretVec::from(export_password.as_str())).map_err(err)
    }

    pub fn export_csv_gated(&self, master_password: String) -> R<String> {
        let g = self.inner.lock();
        export_csv_gated(&g.vault, &SecretVec::from(master_password.as_str()), &g.crypto).map_err(err)
    }

    pub fn set_lock_timeout_secs(&self, secs: i64) {
        let timeout = if secs <= 0 {
            None
        } else {
            Some(time::Duration::seconds(secs))
        };
        self.inner.lock().vault.set_lock_timeout(timeout);
    }
    pub fn touch(&self) {
        self.inner.lock().vault.touch(now());
    }
    pub fn should_lock(&self) -> bool {
        self.inner.lock().vault.should_lock(now())
    }
}

fn parse_id(id: &str) -> R<Uuid> {
    Uuid::parse_str(id).map_err(err)
}
