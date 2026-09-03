//! Tauri commands exposing native vault-core to the shared web UI.

use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use vault_core::crypto::{KdfParams, Key256, SecretVec};
use vault_core::generator::{
    generate_passphrase, generate_password, rate_strength, PassphraseOptions, PasswordOptions,
};
use vault_core::importer::{
    export_csv_gated as vc_export_csv_gated, export_encrypted_json, import_1pux_json,
    import_bitwarden_json, import_csv, ImportResult,
};
use vault_core::item::ItemContent;
use vault_core::keys::{self, AccountCrypto};
use vault_core::store::{ItemRecord, Vault};

use crate::state::{now, Session, VaultState};
use crate::{biometric, opaque};

type R<T> = Result<T, String>;

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

fn with<T>(state: &VaultState, f: impl FnOnce(&mut Session) -> R<T>) -> R<T> {
    let mut guard = state.0.lock();
    let session = guard.as_mut().ok_or_else(|| "vault is locked".to_string())?;
    f(session)
}

fn parse_id(id: &str) -> R<Uuid> {
    Uuid::parse_str(id).map_err(e)
}

// --- KDF / generator / strength (stateless) --------------------------------

#[tauri::command]
pub fn kdf_benchmark(target_ms: f64) -> R<String> {
    let stretch = KdfParams {
        mem_kib: 128 * 1024,
        iterations: 4,
        parallelism: 4,
    };
    let candidates = [stretch, KdfParams::NATIVE_MIN, KdfParams::WASM_MIN];
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
    serde_json::to_string(&chosen).map_err(e)
}

#[tauri::command]
pub fn default_kdf_params() -> R<String> {
    // Desktop links natively: default to the strong native minimum.
    serde_json::to_string(&KdfParams::NATIVE_MIN).map_err(e)
}

#[derive(Deserialize)]
pub struct PasswordOptionsDto {
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    #[serde(default)]
    exclude_ambiguous: bool,
}

#[tauri::command]
pub fn gen_password(options_json: String) -> R<String> {
    let d: PasswordOptionsDto = serde_json::from_str(&options_json).map_err(e)?;
    generate_password(&PasswordOptions {
        length: d.length,
        lowercase: d.lowercase,
        uppercase: d.uppercase,
        digits: d.digits,
        symbols: d.symbols,
        exclude_ambiguous: d.exclude_ambiguous,
    })
    .map_err(e)
}

#[derive(Deserialize)]
pub struct PassphraseOptionsDto {
    words: usize,
    separator: String,
    #[serde(default)]
    capitalize: bool,
    #[serde(default)]
    include_number: bool,
}

#[tauri::command]
pub fn gen_passphrase(options_json: String) -> R<String> {
    let d: PassphraseOptionsDto = serde_json::from_str(&options_json).map_err(e)?;
    generate_passphrase(&PassphraseOptions {
        words: d.words,
        separator: d.separator,
        capitalize: d.capitalize,
        include_number: d.include_number,
    })
    .map_err(e)
}

#[derive(Serialize)]
struct StrengthDto {
    score: u8,
    entropy_bits: f64,
    label: String,
}

#[tauri::command]
pub fn strength(password: String) -> R<String> {
    let s = rate_strength(&password);
    serde_json::to_string(&StrengthDto {
        score: s.score,
        entropy_bits: s.entropy_bits,
        label: s.label().to_string(),
    })
    .map_err(e)
}

// --- OPAQUE (stateless) ----------------------------------------------------

#[tauri::command]
pub fn opaque_register_start(password: String) -> R<String> {
    opaque::register_start(&password)
}
#[tauri::command]
pub fn opaque_register_finish(state_b64: String, password: String, response_b64: String) -> R<String> {
    opaque::register_finish(&state_b64, &password, &response_b64)
}
#[tauri::command]
pub fn opaque_login_start(password: String) -> R<String> {
    opaque::login_start(&password)
}
#[tauri::command]
pub fn opaque_login_finish(state_b64: String, password: String, response_b64: String) -> R<String> {
    opaque::login_finish(&state_b64, &password, &response_b64)
}

// --- vault lifecycle -------------------------------------------------------

#[derive(Serialize)]
pub struct EnrollResult {
    recovery_code: String,
    account_crypto: serde_json::Value,
}

#[tauri::command]
pub fn vault_enroll(state: State<VaultState>, password: String, params_json: String) -> R<EnrollResult> {
    let params: KdfParams = serde_json::from_str(&params_json).map_err(e)?;
    let enrollment = keys::enroll(&SecretVec::from(password.as_str()), params).map_err(e)?;
    let account_crypto = serde_json::to_value(&enrollment.crypto).map_err(e)?;
    let recovery = enrollment.recovery_code.clone();
    let vault = Vault::from_keyring(enrollment.keyring, now());
    *state.0.lock() = Some(Session {
        vault,
        crypto: enrollment.crypto,
        recovery: Some(recovery.clone()),
    });
    Ok(EnrollResult {
        recovery_code: recovery,
        account_crypto,
    })
}

#[tauri::command]
pub fn vault_unlock(
    state: State<VaultState>,
    password: String,
    crypto_json: String,
    records_json: String,
) -> R<()> {
    let crypto: AccountCrypto = serde_json::from_str(&crypto_json).map_err(e)?;
    let records: Vec<ItemRecord> = serde_json::from_str(&records_json).map_err(e)?;
    let vault = Vault::open(&SecretVec::from(password.as_str()), &crypto, records, now()).map_err(e)?;
    *state.0.lock() = Some(Session {
        vault,
        crypto,
        recovery: None,
    });
    Ok(())
}

#[tauri::command]
pub fn vault_unlock_recovery(
    state: State<VaultState>,
    recovery_code: String,
    crypto_json: String,
    records_json: String,
) -> R<()> {
    let crypto: AccountCrypto = serde_json::from_str(&crypto_json).map_err(e)?;
    let records: Vec<ItemRecord> = serde_json::from_str(&records_json).map_err(e)?;
    let vault =
        Vault::open_with_recovery(&recovery_code, &crypto, records, now()).map_err(e)?;
    *state.0.lock() = Some(Session {
        vault,
        crypto,
        recovery: None,
    });
    Ok(())
}

#[tauri::command]
pub fn vault_lock(state: State<VaultState>) {
    state.lock_now();
}

#[tauri::command]
pub fn vault_unlocked(state: State<VaultState>) -> bool {
    state.is_unlocked()
}

#[tauri::command]
pub fn account_crypto(state: State<VaultState>) -> R<String> {
    with(&state, |s| serde_json::to_string(&s.crypto).map_err(e))
}

#[tauri::command]
pub fn take_recovery_code(state: State<VaultState>) -> Option<String> {
    state.0.lock().as_mut().and_then(|s| s.recovery.take())
}

#[tauri::command]
pub fn records(state: State<VaultState>) -> R<String> {
    with(&state, |s| {
        let recs: Vec<ItemRecord> = s.vault.records().cloned().collect();
        serde_json::to_string(&recs).map_err(e)
    })
}

#[tauri::command]
pub fn apply_record(state: State<VaultState>, record_json: String) -> R<()> {
    with(&state, |s| {
        let rec: ItemRecord = serde_json::from_str(&record_json).map_err(e)?;
        s.vault.ingest_record(rec).map_err(e)
    })
}

// --- CRUD ------------------------------------------------------------------

#[tauri::command]
pub fn create_item(state: State<VaultState>, content_json: String) -> R<String> {
    with(&state, |s| {
        let content: ItemContent = serde_json::from_str(&content_json).map_err(e)?;
        s.vault.create(None, &content, now()).map(|id| id.to_string()).map_err(e)
    })
}

#[tauri::command]
pub fn get_item(state: State<VaultState>, id: String) -> R<String> {
    with(&state, |s| {
        let c = s.vault.get(parse_id(&id)?).map_err(e)?;
        serde_json::to_string(&c).map_err(e)
    })
}

#[tauri::command]
pub fn update_item(state: State<VaultState>, id: String, content_json: String) -> R<()> {
    with(&state, |s| {
        let content: ItemContent = serde_json::from_str(&content_json).map_err(e)?;
        s.vault.update(parse_id(&id)?, &content, now()).map_err(e)
    })
}

#[tauri::command]
pub fn move_to_bin(state: State<VaultState>, id: String) -> R<()> {
    with(&state, |s| s.vault.move_to_bin(parse_id(&id)?, now()).map_err(e))
}

#[tauri::command]
pub fn restore_from_bin(state: State<VaultState>, id: String) -> R<()> {
    with(&state, |s| s.vault.restore_from_bin(parse_id(&id)?, now()).map_err(e))
}

#[tauri::command]
pub fn delete_permanent(state: State<VaultState>, id: String) -> R<()> {
    with(&state, |s| s.vault.delete_permanent(parse_id(&id)?, now()).map_err(e))
}

#[tauri::command]
pub fn list_active(state: State<VaultState>) -> R<Vec<String>> {
    with(&state, |s| Ok(s.vault.list_active().into_iter().map(|i| i.to_string()).collect()))
}

#[tauri::command]
pub fn list_bin(state: State<VaultState>) -> R<Vec<String>> {
    with(&state, |s| {
        Ok(s.vault.list_bin().map_err(e)?.into_iter().map(|i| i.to_string()).collect())
    })
}

#[tauri::command]
pub fn search(state: State<VaultState>, query: String) -> R<Vec<String>> {
    with(&state, |s| Ok(s.vault.search(&query).into_iter().map(|i| i.to_string()).collect()))
}

#[tauri::command]
pub fn candidates_for(state: State<VaultState>, url: String) -> R<Vec<String>> {
    with(&state, |s| {
        Ok(s.vault.candidates_for(&url).map_err(e)?.into_iter().map(|i| i.to_string()).collect())
    })
}

#[tauri::command]
pub fn folders(state: State<VaultState>) -> R<Vec<String>> {
    with(&state, |s| s.vault.folders().map_err(e))
}

#[tauri::command]
pub fn tags(state: State<VaultState>) -> R<Vec<String>> {
    with(&state, |s| s.vault.tags().map_err(e))
}

#[derive(Serialize)]
struct RevisionDto {
    modified_at: String,
    content: ItemContent,
}

#[tauri::command]
pub fn history(state: State<VaultState>, id: String) -> R<String> {
    with(&state, |s| {
        let revs = s.vault.history(parse_id(&id)?).map_err(e)?;
        let dto: Vec<RevisionDto> = revs
            .into_iter()
            .map(|(ts, content)| RevisionDto {
                modified_at: ts
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                content,
            })
            .collect();
        serde_json::to_string(&dto).map_err(e)
    })
}

#[tauri::command]
pub fn restore_revision(state: State<VaultState>, id: String, index: usize) -> R<()> {
    with(&state, |s| s.vault.restore_revision(parse_id(&id)?, index, now()).map_err(e))
}

// --- account security ------------------------------------------------------

#[tauri::command]
pub fn change_master_password(
    state: State<VaultState>,
    current: String,
    next: String,
    params_json: String,
) -> R<String> {
    let params: KdfParams = serde_json::from_str(&params_json).map_err(e)?;
    with(&state, |s| {
        let updated = keys::change_master_password(
            &SecretVec::from(current.as_str()),
            &SecretVec::from(next.as_str()),
            params,
            &s.crypto,
        )
        .map_err(e)?;
        s.crypto = updated;
        serde_json::to_string(&s.crypto).map_err(e)
    })
}

#[tauri::command]
pub fn regenerate_recovery_code(state: State<VaultState>, password: String) -> R<String> {
    with(&state, |s| {
        let (code, updated) =
            keys::regenerate_recovery_code(&SecretVec::from(password.as_str()), &s.crypto).map_err(e)?;
        s.crypto = updated;
        Ok(code)
    })
}

// --- import / export -------------------------------------------------------

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

#[tauri::command]
pub fn import_preview(kind: String, data: String) -> R<String> {
    let result: ImportResult = match kind.as_str() {
        "csv" => import_csv(&data).map_err(e)?,
        "bitwarden" => import_bitwarden_json(&data).map_err(e)?,
        "1pux" => import_1pux_json(&data).map_err(e)?,
        other => return Err(format!("unknown import kind: {other}")),
    };
    let dto = ImportPreviewDto {
        items: result.items,
        errors: result
            .errors
            .into_iter()
            .map(|x| ImportErrorDto {
                row: x.row,
                message: x.message,
            })
            .collect(),
    };
    serde_json::to_string(&dto).map_err(e)
}

#[tauri::command]
pub fn import_commit(state: State<VaultState>, items_json: String) -> R<usize> {
    with(&state, |s| {
        let items: Vec<ItemContent> = serde_json::from_str(&items_json).map_err(e)?;
        let mut n = 0;
        for content in &items {
            s.vault.create(None, content, now()).map_err(e)?;
            n += 1;
        }
        Ok(n)
    })
}

#[tauri::command]
pub fn export_encrypted(state: State<VaultState>, export_password: String) -> R<String> {
    with(&state, |s| {
        let items: Vec<ItemContent> = s
            .vault
            .list_active()
            .into_iter()
            .map(|id| s.vault.get(id))
            .collect::<Result<_, _>>()
            .map_err(e)?;
        export_encrypted_json(&items, &SecretVec::from(export_password.as_str())).map_err(e)
    })
}

#[tauri::command]
pub fn export_csv_gated(state: State<VaultState>, master_password: String) -> R<String> {
    with(&state, |s| {
        vc_export_csv_gated(&s.vault, &SecretVec::from(master_password.as_str()), &s.crypto)
            .map_err(e)
    })
}

// --- session hardening -----------------------------------------------------

#[tauri::command]
pub fn set_lock_timeout_secs(state: State<VaultState>, secs: i64) -> R<()> {
    with(&state, |s| {
        let timeout = if secs <= 0 {
            None
        } else {
            Some(time::Duration::seconds(secs))
        };
        s.vault.set_lock_timeout(timeout);
        Ok(())
    })
}

#[tauri::command]
pub fn touch(state: State<VaultState>) {
    if let Some(s) = state.0.lock().as_mut() {
        s.vault.touch(now());
    }
}

#[tauri::command]
pub fn should_lock(state: State<VaultState>) -> bool {
    state
        .0
        .lock()
        .as_ref()
        .map(|s| s.vault.should_lock(now()))
        .unwrap_or(false)
}

// --- biometric unlock (Touch ID) -------------------------------------------

#[tauri::command]
pub fn biometric_available() -> bool {
    biometric::available()
}

#[tauri::command]
pub fn biometric_enabled() -> bool {
    biometric::enabled()
}

/// Enable biometric unlock by stashing the current session's account key in the
/// OS keystore. Requires the vault to be unlocked.
#[tauri::command]
pub fn biometric_enable(state: State<VaultState>) -> R<()> {
    with(&state, |s| {
        let key = s.vault.keyring().export_account_key();
        biometric::store(key.expose())
    })
}

#[tauri::command]
pub fn biometric_disable() -> R<()> {
    biometric::clear()
}

/// Unlock via biometrics: retrieve the account key from the keystore (Touch ID
/// prompt on a signed build) and reconstruct the vault without the master
/// password. Crypto material and cached records come from the caller.
#[tauri::command]
pub fn biometric_unlock(
    state: State<VaultState>,
    crypto_json: String,
    records_json: String,
) -> R<()> {
    let bytes = biometric::load()?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "corrupt biometric session key".to_string())?;
    let account_key = Key256::new(arr);
    let crypto: AccountCrypto = serde_json::from_str(&crypto_json).map_err(e)?;
    let records: Vec<ItemRecord> = serde_json::from_str(&records_json).map_err(e)?;
    let vault = Vault::open_with_account_key(account_key, &crypto, records, now()).map_err(e)?;
    *state.0.lock() = Some(Session {
        vault,
        crypto,
        recovery: None,
    });
    Ok(())
}
