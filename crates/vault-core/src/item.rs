//! The item model: the plaintext content that gets sealed under a vault key.
//!
//! Everything a user would consider sensitive — including folder names, tags,
//! and the favourite flag — lives inside [`ItemContent`] and is encrypted. The
//! server sees only the sync metadata in [`crate::store::ItemRecord`].

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// How a stored URI is matched against a page/app the user is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UriMatch {
    /// Match any host under the same registrable (base) domain.
    #[default]
    BaseDomain,
    /// Match the exact host only.
    Host,
    /// Match the exact URL (scheme + host + path).
    Exact,
    /// Never offer this URI for autofill.
    Never,
}

/// A stored URI plus its match rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uri {
    pub value: String,
    #[serde(default)]
    pub match_rule: UriMatch,
}

/// Specificity of a URI match; higher wins when an item has multiple matching
/// URIs, so the most specific rule is chosen (spec: multiple-URI scenario).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchSpecificity {
    BaseDomain = 1,
    Host = 2,
    Exact = 3,
}

impl Uri {
    /// Return the specificity if this URI matches `target`, else `None`.
    pub fn matches(&self, target: &str) -> Option<MatchSpecificity> {
        match self.match_rule {
            UriMatch::Never => None,
            UriMatch::Exact => (normalize_url(&self.value) == normalize_url(target))
                .then_some(MatchSpecificity::Exact),
            UriMatch::Host => {
                let (a, b) = (host_of(&self.value)?, host_of(target)?);
                a.eq_ignore_ascii_case(&b).then_some(MatchSpecificity::Host)
            }
            UriMatch::BaseDomain => {
                let (a, b) = (host_of(&self.value)?, host_of(target)?);
                (registrable_domain(&a) == registrable_domain(&b))
                    .then_some(MatchSpecificity::BaseDomain)
            }
        }
    }
}

/// A user-defined custom field on an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    /// Marks the value as sensitive so UIs mask it by default.
    #[serde(default)]
    pub hidden: bool,
}

/// Login credentials, the most common item type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginData {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub uris: Vec<Uri>,
    /// TOTP secret in `otpauth://` URI form or a bare base32 secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

/// A WebAuthn passkey stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyData {
    pub rp_id: String,
    pub user_handle: String,
    pub credential_id: String,
    /// PKCS#8 private key bytes, base64. Sensitive; only ever inside sealed content.
    pub private_key_b64: String,
    #[serde(default)]
    pub counter: u32,
}

/// A payment card.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardData {
    #[serde(default)]
    pub cardholder: String,
    #[serde(default)]
    pub number: String,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub exp_month: String,
    #[serde(default)]
    pub exp_year: String,
    #[serde(default)]
    pub security_code: String,
}

/// An identity/contact record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityData {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub address: String,
}

/// Type-specific payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemData {
    Login(LoginData),
    SecureNote,
    Passkey(PasskeyData),
    Card(CardData),
    Identity(IdentityData),
}

impl ItemData {
    pub fn kind(&self) -> &'static str {
        match self {
            ItemData::Login(_) => "login",
            ItemData::SecureNote => "secure_note",
            ItemData::Passkey(_) => "passkey",
            ItemData::Card(_) => "card",
            ItemData::Identity(_) => "identity",
        }
    }
}

/// The full decrypted content of an item. This is what is serialised and sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemContent {
    pub title: String,
    pub data: ItemData,
    #[serde(default)]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// When set, the item is in the bin (soft-deleted), restorable until purge.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_ts")]
    pub binned_at: Option<OffsetDateTime>,
}

impl ItemContent {
    /// A new login item with the given title.
    pub fn new_login(title: impl Into<String>) -> Self {
        Self::new(title, ItemData::Login(LoginData::default()))
    }

    pub fn new(title: impl Into<String>, data: ItemData) -> Self {
        Self {
            title: title.into(),
            data,
            notes: String::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            custom_fields: Vec::new(),
            binned_at: None,
        }
    }

    pub fn is_binned(&self) -> bool {
        self.binned_at.is_some()
    }

    /// Login username, if this is a login item.
    pub fn username(&self) -> Option<&str> {
        match &self.data {
            ItemData::Login(l) => Some(l.username.as_str()),
            _ => None,
        }
    }

    /// All URIs, if this is a login item.
    pub fn uris(&self) -> &[Uri] {
        match &self.data {
            ItemData::Login(l) => &l.uris,
            _ => &[],
        }
    }

    /// Best match specificity of this item's URIs against `target`.
    pub fn best_match(&self, target: &str) -> Option<MatchSpecificity> {
        self.uris().iter().filter_map(|u| u.matches(target)).max()
    }
}

/// A change identifying an item within a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ItemId {
    pub vault_id: Uuid,
    pub item_id: Uuid,
}

// --- URL helpers -----------------------------------------------------------

/// Extract the lowercased host from a URL-ish string, tolerating missing scheme.
pub fn host_of(url: &str) -> Option<String> {
    let s = url.trim();
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s,
    };
    let host_port = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip userinfo and port.
    let host = host_port.rsplit('@').next().unwrap_or(host_port);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Registrable ("base") domain heuristic: the last two labels. This is a
/// deliberate approximation — the browser extension refines matching with the
/// Public Suffix List (tasks 5.5) so multi-part TLDs like `co.uk` are handled
/// correctly there. Kept simple here to avoid bundling the PSL into every
/// client target.
pub fn registrable_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    let n = labels.len();
    if n <= 2 {
        host.to_string()
    } else {
        labels[n - 2..].join(".")
    }
}

/// Normalise a URL for exact comparison: lowercase scheme+host, strip trailing
/// slash and default ports.
fn normalize_url(url: &str) -> String {
    let s = url.trim().trim_end_matches('/');
    s.to_ascii_lowercase()
}

/// Serde for `Option<OffsetDateTime>` as RFC3339.
mod opt_ts {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(v: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(t) => t
                .format(&Rfc3339)
                .map_err(serde::ser::Error::custom)?
                .serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => OffsetDateTime::parse(&s, &Rfc3339)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
