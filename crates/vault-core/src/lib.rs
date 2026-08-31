//! # vault-core
//!
//! The zero-knowledge encrypted vault shared by every client and the server.
//!
//! Layers, bottom to top:
//! - [`crypto`] — Argon2id/HKDF KDF, XChaCha20-Poly1305 AEAD, CSPRNG, zeroizing
//!   secrets.
//! - [`keys`] — the master key → MUK → account key → vault key hierarchy,
//!   enrolment, unlock, master-password change, recovery codes.
//! - [`item`] — the item model (login, note, passkey, card) and URI match rules.
//! - [`store`] — the unlocked in-memory vault: CRUD, soft delete/bin, folders,
//!   tags, history.
//! - [`search`] — case-insensitive search index over titles/usernames/URIs.
//! - [`generator`] — password/passphrase generation and strength rating.
//! - [`sync`] — the client side of the offline-first delta-sync protocol.
//! - [`importer`] / [`exporter`] — CSV, Bitwarden JSON, 1PUX in; encrypted JSON
//!   / gated CSV out.
//!
//! Design authority: `openspec/changes/add-password-manager/design.md`.

pub mod codec;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod importer;
pub mod item;
pub mod keys;
pub mod search;
pub mod store;
pub mod sync;

pub use error::{Error, Result};

/// Serde for a required `OffsetDateTime` as an RFC3339 string.
pub(crate) mod item_ts {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(v: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
        v.format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
        let s = String::deserialize(d)?;
        OffsetDateTime::parse(&s, &Rfc3339).map_err(serde::de::Error::custom)
    }
}
