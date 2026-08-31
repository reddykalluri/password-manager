//! Import and export.
//!
//! Import parsers (generic CSV, Bitwarden JSON, 1Password 1PUX) return a preview
//! plus per-row errors so the UI can show what will land before committing.
//! Export produces password-protected encrypted JSON, or plaintext CSV gated by
//! master-password re-entry (verified cryptographically here, not merely by UI).

use serde::{Deserialize, Serialize};

use crate::crypto::kdf::{derive_master_key, hkdf_derive_key, KdfParams, INFO_MUK, KDF_SALT_LEN};
use crate::crypto::rng::random_array;
use crate::crypto::{open, seal, unwrap_key, SealedBlob, SecretVec};
use crate::error::{Error, Result};
use crate::item::{ItemContent, ItemData, LoginData, Uri, UriMatch};
use crate::keys::AccountCrypto;
use crate::store::Vault;

/// A per-row import error, for preview reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowError {
    pub row: usize,
    pub message: String,
}

/// Outcome of an import: successfully parsed items plus any row-level errors.
#[derive(Debug, Default)]
pub struct ImportResult {
    pub items: Vec<ItemContent>,
    pub errors: Vec<RowError>,
}

// --- Generic CSV -----------------------------------------------------------

/// Import generic CSV. Recognises common headers (title/name, url/uri/website,
/// username/user, password/pass, notes) case-insensitively.
pub fn import_csv(data: &str) -> Result<ImportResult> {
    let rows = parse_csv(data);
    let mut result = ImportResult::default();
    let Some(header) = rows.first() else {
        return Ok(result);
    };
    let idx = |names: &[&str]| -> Option<usize> {
        header
            .iter()
            .position(|h| names.iter().any(|n| h.trim().eq_ignore_ascii_case(n)))
    };
    let title_i = idx(&["title", "name"]);
    let url_i = idx(&["url", "uri", "website", "login_uri"]);
    let user_i = idx(&["username", "user", "login_username", "email"]);
    let pass_i = idx(&["password", "pass", "login_password"]);
    let notes_i = idx(&["notes", "note"]);

    if title_i.is_none() && url_i.is_none() && user_i.is_none() {
        return Err(Error::Import(
            "CSV missing recognisable columns (need at least title, url, or username)".into(),
        ));
    }

    for (n, row) in rows.iter().enumerate().skip(1) {
        if row.iter().all(|c| c.trim().is_empty()) {
            continue; // skip blank lines
        }
        let get = |i: Option<usize>| i.and_then(|i| row.get(i)).cloned().unwrap_or_default();
        let title = {
            let t = get(title_i);
            if t.trim().is_empty() {
                get(url_i)
            } else {
                t
            }
        };
        if title.trim().is_empty() {
            result.errors.push(RowError {
                row: n + 1,
                message: "row has no title, url, or username".into(),
            });
            continue;
        }
        let mut login = LoginData {
            username: get(user_i),
            password: get(pass_i),
            ..Default::default()
        };
        let url = get(url_i);
        if !url.trim().is_empty() {
            login.uris.push(Uri {
                value: url.trim().to_string(),
                match_rule: UriMatch::BaseDomain,
            });
        }
        let mut content = ItemContent::new(title.trim(), ItemData::Login(login));
        content.notes = get(notes_i);
        result.items.push(content);
    }
    Ok(result)
}

// --- Bitwarden JSON --------------------------------------------------------

#[derive(Deserialize)]
struct BwExport {
    items: Vec<BwItem>,
}
#[derive(Deserialize)]
struct BwItem {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: u8,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default)]
    favorite: bool,
}
#[derive(Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<BwUri>,
}
#[derive(Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

/// Import a Bitwarden unencrypted JSON export.
pub fn import_bitwarden_json(data: &str) -> Result<ImportResult> {
    let parsed: BwExport = serde_json::from_str(data)
        .map_err(|e| Error::Import(format!("invalid Bitwarden JSON: {e}")))?;
    let mut result = ImportResult::default();
    for (n, item) in parsed.items.into_iter().enumerate() {
        // Bitwarden type 1 = login; others become secure notes.
        let data = if item.kind == 1 {
            if let Some(l) = item.login {
                ItemData::Login(LoginData {
                    username: l.username.unwrap_or_default(),
                    password: l.password.unwrap_or_default(),
                    totp: l.totp,
                    uris: l
                        .uris
                        .into_iter()
                        .filter_map(|u| u.uri)
                        .map(|v| Uri {
                            value: v,
                            match_rule: UriMatch::BaseDomain,
                        })
                        .collect(),
                })
            } else {
                ItemData::SecureNote
            }
        } else {
            ItemData::SecureNote
        };
        if item.name.trim().is_empty() {
            result.errors.push(RowError {
                row: n + 1,
                message: "item has no name".into(),
            });
            continue;
        }
        let mut content = ItemContent::new(item.name.trim(), data);
        content.notes = item.notes.unwrap_or_default();
        content.favorite = item.favorite;
        result.items.push(content);
    }
    Ok(result)
}

// --- 1Password 1PUX --------------------------------------------------------
//
// A `.1pux` file is a zip whose `export.data` member is the JSON parsed here.
// Zip extraction belongs to the caller/UI layer (it varies per client target);
// this function takes the already-extracted `export.data` JSON.

#[derive(Deserialize)]
struct PuxExport {
    accounts: Vec<PuxAccount>,
}
#[derive(Deserialize)]
struct PuxAccount {
    vaults: Vec<PuxVault>,
}
#[derive(Deserialize)]
struct PuxVault {
    items: Vec<PuxItem>,
}
#[derive(Deserialize)]
struct PuxItem {
    #[serde(default)]
    item: Option<PuxItemInner>,
}
#[derive(Deserialize)]
struct PuxItemInner {
    #[serde(default)]
    overview: PuxOverview,
    #[serde(default)]
    details: PuxDetails,
    #[serde(default, rename = "favIndex")]
    fav_index: Option<i64>,
}
#[derive(Deserialize, Default)]
struct PuxOverview {
    #[serde(default)]
    title: String,
    #[serde(default)]
    urls: Vec<PuxUrl>,
}
#[derive(Deserialize)]
struct PuxUrl {
    #[serde(default)]
    url: String,
}
#[derive(Deserialize, Default)]
struct PuxDetails {
    #[serde(default, rename = "loginFields")]
    login_fields: Vec<PuxLoginField>,
    #[serde(default, rename = "notesPlain")]
    notes_plain: Option<String>,
}
#[derive(Deserialize)]
struct PuxLoginField {
    #[serde(default)]
    designation: Option<String>,
    #[serde(default)]
    value: String,
}

/// Import the JSON payload (`export.data`) of a 1Password 1PUX export.
pub fn import_1pux_json(data: &str) -> Result<ImportResult> {
    let parsed: PuxExport =
        serde_json::from_str(data).map_err(|e| Error::Import(format!("invalid 1PUX JSON: {e}")))?;
    let mut result = ImportResult::default();
    let mut n = 0usize;
    for account in parsed.accounts {
        for vault in account.vaults {
            for wrapper in vault.items {
                n += 1;
                let Some(inner) = wrapper.item else { continue };
                let mut login = LoginData::default();
                for f in &inner.details.login_fields {
                    match f.designation.as_deref() {
                        Some("username") => login.username = f.value.clone(),
                        Some("password") => login.password = f.value.clone(),
                        _ => {}
                    }
                }
                for u in &inner.overview.urls {
                    if !u.url.trim().is_empty() {
                        login.uris.push(Uri {
                            value: u.url.trim().to_string(),
                            match_rule: UriMatch::BaseDomain,
                        });
                    }
                }
                let title = inner.overview.title.trim();
                if title.is_empty() {
                    result.errors.push(RowError {
                        row: n,
                        message: "item has no title".into(),
                    });
                    continue;
                }
                let mut content = ItemContent::new(title, ItemData::Login(login));
                content.notes = inner.details.notes_plain.unwrap_or_default();
                content.favorite = inner.fav_index.is_some();
                result.items.push(content);
            }
        }
    }
    Ok(result)
}

// --- Export ----------------------------------------------------------------

/// Envelope for a password-protected encrypted JSON export. Self-describing so a
/// future import can reproduce the key derivation.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedExport {
    pub format: String,
    pub kdf_params: KdfParams,
    #[serde(with = "crate::codec::b64")]
    pub salt: Vec<u8>,
    pub blob: SealedBlob,
}

const EXPORT_AAD: &[u8] = b"vault-core:v1:encrypted-export";

/// Export the given items as password-protected encrypted JSON. The export
/// password is independent of the master password.
pub fn export_encrypted_json(items: &[ItemContent], export_password: &SecretVec) -> Result<String> {
    let salt = random_array::<KDF_SALT_LEN>();
    let params = KdfParams::default();
    let master = derive_master_key(export_password, &salt, params)?;
    let key = hkdf_derive_key(&master, b"vault-core:v1:export-key")?;
    let plaintext = serde_json::to_vec(items)?;
    let blob = seal(&key, &plaintext, EXPORT_AAD)?;
    let envelope = EncryptedExport {
        format: "vault-core-encrypted-export-v1".into(),
        kdf_params: params,
        salt: salt.to_vec(),
        blob,
    };
    Ok(serde_json::to_string(&envelope)?)
}

/// Decrypt a [`export_encrypted_json`] envelope (used for round-trips and
/// re-import).
pub fn import_encrypted_json(data: &str, export_password: &SecretVec) -> Result<Vec<ItemContent>> {
    let envelope: EncryptedExport =
        serde_json::from_str(data).map_err(|e| Error::Import(format!("invalid export: {e}")))?;
    let salt: [u8; KDF_SALT_LEN] = envelope
        .salt
        .as_slice()
        .try_into()
        .map_err(|_| Error::Import("bad salt".into()))?;
    let master = derive_master_key(export_password, &salt, envelope.kdf_params)?;
    let key = hkdf_derive_key(&master, b"vault-core:v1:export-key")?;
    let plaintext = open(&key, &envelope.blob, EXPORT_AAD)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// Export the vault as plaintext CSV, **gated** by re-entry of the master
/// password. The password is verified cryptographically (it must unwrap the
/// account key) before any plaintext is produced — a UI cannot bypass this by
/// simply not showing the warning.
///
/// Callers MUST also display the plaintext-risk warning (spec scenario); this
/// function enforces the credential gate, the UI enforces the warning.
pub fn export_csv_gated(
    vault: &Vault,
    master_password: &SecretVec,
    crypto: &AccountCrypto,
) -> Result<String> {
    // Verify the password by re-deriving the MUK and unwrapping the account key.
    let salt: [u8; KDF_SALT_LEN] = crypto
        .kdf_salt
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("bad kdf salt".into()))?;
    let master = derive_master_key(master_password, &salt, crypto.kdf_params)?;
    let muk = hkdf_derive_key(&master, INFO_MUK)?;
    // Wrong password → Decrypt error, so no plaintext is ever produced.
    unwrap_key(
        &muk,
        &crypto.account_key_by_muk,
        b"vault-core:v1:wrap:account-key:muk",
    )?;

    let mut out = String::from("title,url,username,password,notes\n");
    for id in vault.list_active() {
        let c = vault.get(id)?;
        let (url, user, pass) = match &c.data {
            ItemData::Login(l) => (
                l.uris.first().map(|u| u.value.clone()).unwrap_or_default(),
                l.username.clone(),
                l.password.clone(),
            ),
            _ => (String::new(), String::new(), String::new()),
        };
        out.push_str(&csv_row(&[&c.title, &url, &user, &pass, &c.notes]));
    }
    Ok(out)
}

// --- minimal RFC4180 CSV ---------------------------------------------------

/// Parse CSV into rows of fields (handles quoted fields, embedded commas,
/// quotes, and newlines).
fn parse_csv(data: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut field = String::new();
    let mut record = Vec::new();
    let mut in_quotes = false;
    let mut chars = data.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                }
                _ => field.push(c),
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    record.push(std::mem::take(&mut field));
                }
                '\r' => {}
                '\n' => {
                    record.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut record));
                }
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        rows.push(record);
    }
    rows
}

/// Encode one CSV row, quoting fields that need it.
fn csv_row(fields: &[&str]) -> String {
    let escaped: Vec<String> = fields
        .iter()
        .map(|f| {
            if f.contains([',', '"', '\n', '\r']) {
                format!("\"{}\"", f.replace('"', "\"\""))
            } else {
                f.to_string()
            }
        })
        .collect();
    format!("{}\n", escaped.join(","))
}
