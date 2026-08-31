//! WASM/TypeScript bindings for `vault-core`.
//!
//! The web client (and browser extensions) drive all cryptography through this
//! module: enrolment, unlock, item CRUD, search, history, generator, import/
//! export, and in-browser KDF benchmarking. The master password and derived
//! keys never leave the WASM heap; only ciphertext + sync metadata are handed
//! back to JS for persistence/transport.

mod opaque;

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use vault_core::crypto::{KdfParams, SecretVec};
use vault_core::generator::{
    generate_passphrase, generate_password, rate_strength, PassphraseOptions, PasswordOptions,
};
use vault_core::importer::{
    export_csv_gated, export_encrypted_json, import_1pux_json, import_bitwarden_json, import_csv,
    ImportResult,
};
use vault_core::item::ItemContent;
use vault_core::keys::{self, AccountCrypto};
use vault_core::store::{ItemRecord, Vault};

/// Install a panic hook that surfaces Rust panics in the browser console.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Current time from the JS clock (the core is otherwise clock-free).
fn now() -> OffsetDateTime {
    let ms = js_sys::Date::now();
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

// --- KDF benchmark / parameter negotiation --------------------------------

/// Benchmark Argon2id in this browser and return the strongest [`KdfParams`]
/// whose derivation stays under `target_ms`. Falls back to the WASM minimum if
/// even that is too slow. Returned as a JSON string.
#[wasm_bindgen(js_name = benchmarkKdf)]
pub fn benchmark_kdf(target_ms: f64) -> Result<String, JsError> {
    // 96 MiB is a stretch goal above the native minimum; try strongest first.
    let stretch = KdfParams {
        mem_kib: 96 * 1024,
        iterations: 4,
        parallelism: 1,
    };
    let candidates = [stretch, KdfParams::NATIVE_MIN, KdfParams::WASM_MIN];
    let password = SecretVec::from("kdf-benchmark-probe");
    let salt = [0u8; vault_core::crypto::KDF_SALT_LEN];

    let mut chosen = KdfParams::WASM_MIN;
    for c in candidates {
        let t0 = js_sys::Date::now();
        // Ignore the derived key; we only care about the timing.
        let _ = keys_derive_probe(&password, &salt, c);
        let dt = js_sys::Date::now() - t0;
        if dt <= target_ms {
            chosen = c;
            break;
        }
    }
    Ok(serde_json::to_string(&chosen)?)
}

/// The conservative default params for first paint before a benchmark runs.
#[wasm_bindgen(js_name = defaultKdfParams)]
pub fn default_kdf_params() -> Result<String, JsError> {
    Ok(serde_json::to_string(&KdfParams::WASM_MIN)?)
}

fn keys_derive_probe(
    password: &SecretVec,
    salt: &[u8; vault_core::crypto::KDF_SALT_LEN],
    params: KdfParams,
) -> Result<(), vault_core::Error> {
    vault_core::crypto::derive_master_key(password, salt, params)?;
    Ok(())
}

// --- generator (stateless helpers) ----------------------------------------

#[wasm_bindgen(js_name = generatePassword)]
pub fn wasm_generate_password(options_json: &str) -> Result<String, JsError> {
    let opts: PasswordOptionsDto = serde_json::from_str(options_json)?;
    Ok(generate_password(&opts.into())?)
}

#[wasm_bindgen(js_name = generatePassphrase)]
pub fn wasm_generate_passphrase(options_json: &str) -> Result<String, JsError> {
    let opts: PassphraseOptionsDto = serde_json::from_str(options_json)?;
    Ok(generate_passphrase(&opts.into())?)
}

#[wasm_bindgen(js_name = rateStrength)]
pub fn wasm_rate_strength(password: &str) -> Result<String, JsError> {
    let s = rate_strength(password);
    Ok(serde_json::to_string(&StrengthDto {
        score: s.score,
        entropy_bits: s.entropy_bits,
        label: s.label().to_string(),
    })?)
}

// --- the vault handle ------------------------------------------------------

/// An unlocked vault. Dropping it (`.free()` from JS) zeroises key material.
#[wasm_bindgen]
pub struct WasmVault {
    vault: Vault,
    crypto: AccountCrypto,
    recovery_code: Option<String>,
}

#[wasm_bindgen]
impl WasmVault {
    /// Enrol a new account. Returns a vault; the one-time recovery code and the
    /// server-storable crypto material are retrieved via getters.
    pub fn enroll(password: &str, params_json: &str) -> Result<WasmVault, JsError> {
        let params: KdfParams = serde_json::from_str(params_json)?;
        let enrollment = keys::enroll(&SecretVec::from(password), params)?;
        let vault = Vault::from_keyring(enrollment.keyring, now());
        Ok(WasmVault {
            vault,
            crypto: enrollment.crypto,
            recovery_code: Some(enrollment.recovery_code),
        })
    }

    /// Unlock an existing account from stored crypto material + cached records.
    pub fn unlock(
        password: &str,
        crypto_json: &str,
        records_json: &str,
    ) -> Result<WasmVault, JsError> {
        let crypto: AccountCrypto = serde_json::from_str(crypto_json)?;
        let records: Vec<ItemRecord> = serde_json::from_str(records_json)?;
        let vault = Vault::open(&SecretVec::from(password), &crypto, records, now())?;
        Ok(WasmVault {
            vault,
            crypto,
            recovery_code: None,
        })
    }

    /// Unlock via recovery code.
    #[wasm_bindgen(js_name = unlockWithRecovery)]
    pub fn unlock_with_recovery(
        recovery_code: &str,
        crypto_json: &str,
        records_json: &str,
    ) -> Result<WasmVault, JsError> {
        let crypto: AccountCrypto = serde_json::from_str(crypto_json)?;
        let records: Vec<ItemRecord> = serde_json::from_str(records_json)?;
        let vault = Vault::open_with_recovery(recovery_code, &crypto, records, now())?;
        Ok(WasmVault {
            vault,
            crypto,
            recovery_code: None,
        })
    }

    /// The one-time recovery code (present only immediately after `enroll`);
    /// consumed on read so it is not retained.
    #[wasm_bindgen(js_name = takeRecoveryCode)]
    pub fn take_recovery_code(&mut self) -> Option<String> {
        self.recovery_code.take()
    }

    /// Server-storable account crypto material (wrapped keys, salts, params).
    #[wasm_bindgen(js_name = accountCrypto)]
    pub fn account_crypto(&self) -> Result<String, JsError> {
        Ok(serde_json::to_string(&self.crypto)?)
    }

    /// All sealed item records, for local caching / sync push.
    #[wasm_bindgen(js_name = records)]
    pub fn records(&self) -> Result<String, JsError> {
        let recs: Vec<ItemRecord> = self.vault.records().cloned().collect();
        Ok(serde_json::to_string(&recs)?)
    }

    /// Ingest a record received from the server during sync (apply a pull, or
    /// adopt the server's copy after a 409 conflict).
    #[wasm_bindgen(js_name = applyRecord)]
    pub fn apply_record(&mut self, record_json: &str) -> Result<(), JsError> {
        let rec: ItemRecord = serde_json::from_str(record_json)?;
        self.vault.ingest_record(rec)?;
        Ok(())
    }

    // --- CRUD --------------------------------------------------------------

    #[wasm_bindgen(js_name = createItem)]
    pub fn create_item(&mut self, content_json: &str) -> Result<String, JsError> {
        let content: ItemContent = serde_json::from_str(content_json)?;
        let id = self.vault.create(None, &content, now())?;
        Ok(id.to_string())
    }

    #[wasm_bindgen(js_name = getItem)]
    pub fn get_item(&self, id: &str) -> Result<String, JsError> {
        let content = self.vault.get(parse_id(id)?)?;
        Ok(serde_json::to_string(&content)?)
    }

    #[wasm_bindgen(js_name = updateItem)]
    pub fn update_item(&mut self, id: &str, content_json: &str) -> Result<(), JsError> {
        let content: ItemContent = serde_json::from_str(content_json)?;
        self.vault.update(parse_id(id)?, &content, now())?;
        Ok(())
    }

    #[wasm_bindgen(js_name = moveToBin)]
    pub fn move_to_bin(&mut self, id: &str) -> Result<(), JsError> {
        self.vault.move_to_bin(parse_id(id)?, now())?;
        Ok(())
    }

    #[wasm_bindgen(js_name = restoreFromBin)]
    pub fn restore_from_bin(&mut self, id: &str) -> Result<(), JsError> {
        self.vault.restore_from_bin(parse_id(id)?, now())?;
        Ok(())
    }

    #[wasm_bindgen(js_name = deletePermanent)]
    pub fn delete_permanent(&mut self, id: &str) -> Result<(), JsError> {
        self.vault.delete_permanent(parse_id(id)?, now())?;
        Ok(())
    }

    // --- listing / search --------------------------------------------------

    #[wasm_bindgen(js_name = listActive)]
    pub fn list_active(&self) -> Vec<String> {
        self.vault
            .list_active()
            .into_iter()
            .map(|id| id.to_string())
            .collect()
    }

    #[wasm_bindgen(js_name = listBin)]
    pub fn list_bin(&self) -> Result<Vec<String>, JsError> {
        Ok(self
            .vault
            .list_bin()?
            .into_iter()
            .map(|id| id.to_string())
            .collect())
    }

    pub fn search(&self, query: &str) -> Vec<String> {
        self.vault
            .search(query)
            .into_iter()
            .map(|id| id.to_string())
            .collect()
    }

    #[wasm_bindgen(js_name = candidatesFor)]
    pub fn candidates_for(&self, url: &str) -> Result<Vec<String>, JsError> {
        Ok(self
            .vault
            .candidates_for(url)?
            .into_iter()
            .map(|id| id.to_string())
            .collect())
    }

    pub fn folders(&self) -> Result<Vec<String>, JsError> {
        Ok(self.vault.folders()?)
    }

    pub fn tags(&self) -> Result<Vec<String>, JsError> {
        Ok(self.vault.tags()?)
    }

    // --- history -----------------------------------------------------------

    pub fn history(&self, id: &str) -> Result<String, JsError> {
        let revs = self.vault.history(parse_id(id)?)?;
        let dto: Vec<RevisionDto> = revs
            .into_iter()
            .map(|(ts, content)| RevisionDto {
                modified_at: ts
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                content,
            })
            .collect();
        Ok(serde_json::to_string(&dto)?)
    }

    #[wasm_bindgen(js_name = restoreRevision)]
    pub fn restore_revision(&mut self, id: &str, index: usize) -> Result<(), JsError> {
        self.vault.restore_revision(parse_id(id)?, index, now())?;
        Ok(())
    }

    // --- account security --------------------------------------------------

    /// Change the master password: re-wraps the account key only. Returns the
    /// updated crypto material to upload.
    #[wasm_bindgen(js_name = changeMasterPassword)]
    pub fn change_master_password(
        &mut self,
        current: &str,
        new: &str,
        params_json: &str,
    ) -> Result<String, JsError> {
        let params: KdfParams = serde_json::from_str(params_json)?;
        let updated = keys::change_master_password(
            &SecretVec::from(current),
            &SecretVec::from(new),
            params,
            &self.crypto,
        )?;
        self.crypto = updated;
        Ok(serde_json::to_string(&self.crypto)?)
    }

    /// Regenerate the recovery code. Returns the new one-time code; the updated
    /// crypto material is then available via `accountCrypto()`.
    #[wasm_bindgen(js_name = regenerateRecoveryCode)]
    pub fn regenerate_recovery_code(&mut self, password: &str) -> Result<String, JsError> {
        let (code, updated) =
            keys::regenerate_recovery_code(&SecretVec::from(password), &self.crypto)?;
        self.crypto = updated;
        Ok(code)
    }

    // --- import / export ---------------------------------------------------

    /// Preview an import without committing. `kind` is `csv` | `bitwarden` | `1pux`.
    #[wasm_bindgen(js_name = importPreview)]
    pub fn import_preview(&self, kind: &str, data: &str) -> Result<String, JsError> {
        let result: ImportResult = match kind {
            "csv" => import_csv(data)?,
            "bitwarden" => import_bitwarden_json(data)?,
            "1pux" => import_1pux_json(data)?,
            other => return Err(JsError::new(&format!("unknown import kind: {other}"))),
        };
        let dto = ImportPreviewDto {
            items: result.items,
            errors: result
                .errors
                .into_iter()
                .map(|e| ImportErrorDto {
                    row: e.row,
                    message: e.message,
                })
                .collect(),
        };
        Ok(serde_json::to_string(&dto)?)
    }

    /// Commit a batch of item contents (e.g. accepted import rows).
    #[wasm_bindgen(js_name = importCommit)]
    pub fn import_commit(&mut self, items_json: &str) -> Result<usize, JsError> {
        let items: Vec<ItemContent> = serde_json::from_str(items_json)?;
        let mut n = 0;
        for content in &items {
            self.vault.create(None, content, now())?;
            n += 1;
        }
        Ok(n)
    }

    /// Password-protected encrypted JSON export of all active items.
    #[wasm_bindgen(js_name = exportEncrypted)]
    pub fn export_encrypted(&self, export_password: &str) -> Result<String, JsError> {
        let items: Vec<ItemContent> = self
            .vault
            .list_active()
            .into_iter()
            .map(|id| self.vault.get(id))
            .collect::<Result<_, _>>()?;
        Ok(export_encrypted_json(
            &items,
            &SecretVec::from(export_password),
        )?)
    }

    /// Plaintext CSV export, gated by master-password re-entry (verified here).
    /// The caller MUST also show the plaintext-risk warning.
    #[wasm_bindgen(js_name = exportCsvGated)]
    pub fn export_csv_gated(&self, master_password: &str) -> Result<String, JsError> {
        Ok(export_csv_gated(
            &self.vault,
            &SecretVec::from(master_password),
            &self.crypto,
        )?)
    }

    /// Configure the auto-lock idle timeout in seconds (0 = never).
    #[wasm_bindgen(js_name = setLockTimeoutSecs)]
    pub fn set_lock_timeout_secs(&mut self, secs: i64) {
        let timeout = if secs <= 0 {
            None
        } else {
            Some(time::Duration::seconds(secs))
        };
        self.vault.set_lock_timeout(timeout);
    }

    /// Record user activity (call on interaction) to defer auto-lock.
    pub fn touch(&mut self) {
        self.vault.touch(now());
    }

    /// Whether the vault should auto-lock now.
    #[wasm_bindgen(js_name = shouldLock)]
    pub fn should_lock(&self) -> bool {
        self.vault.should_lock(now())
    }
}

// --- DTOs ------------------------------------------------------------------

#[derive(Serialize)]
struct StrengthDto {
    score: u8,
    entropy_bits: f64,
    label: String,
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
    row: usize,
    message: String,
}

#[derive(serde::Deserialize)]
struct PasswordOptionsDto {
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    #[serde(default)]
    exclude_ambiguous: bool,
}

impl From<PasswordOptionsDto> for PasswordOptions {
    fn from(d: PasswordOptionsDto) -> Self {
        PasswordOptions {
            length: d.length,
            lowercase: d.lowercase,
            uppercase: d.uppercase,
            digits: d.digits,
            symbols: d.symbols,
            exclude_ambiguous: d.exclude_ambiguous,
        }
    }
}

#[derive(serde::Deserialize)]
struct PassphraseOptionsDto {
    words: usize,
    separator: String,
    #[serde(default)]
    capitalize: bool,
    #[serde(default)]
    include_number: bool,
}

impl From<PassphraseOptionsDto> for PassphraseOptions {
    fn from(d: PassphraseOptionsDto) -> Self {
        PassphraseOptions {
            words: d.words,
            separator: d.separator,
            capitalize: d.capitalize,
            include_number: d.include_number,
        }
    }
}

fn parse_id(id: &str) -> Result<Uuid, JsError> {
    Uuid::parse_str(id).map_err(|e| JsError::new(&format!("invalid id: {e}")))
}
