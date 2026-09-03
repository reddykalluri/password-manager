//! The unlocked vault: an in-memory collection of encrypted item records with
//! CRUD, soft-delete/bin, folders, tags, item history, and lock/auto-lock.
//!
//! Item plaintext exists only transiently while an operation runs; at rest each
//! item is a [`SealedBlob`]. On [`Vault::lock`] the keyring is dropped and its
//! key material zeroised.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::crypto::{open, seal, Key256, SealedBlob};
use crate::error::{Error, Result};
use crate::item::ItemContent;
use crate::keys::{unlock, unlock_with_account_key, unlock_with_recovery, AccountCrypto, KeyRing};
use crate::search::SearchIndex;

/// Maximum retained prior revisions per item (vault-core spec: 20).
pub const MAX_HISTORY: usize = 20;

/// Default auto-lock idle timeout.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::minutes(5);

/// One historical revision of an item's sealed content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    pub sealed: SealedBlob,
    #[serde(with = "crate::item_ts")]
    pub modified_at: OffsetDateTime,
}

/// The persisted/synced representation of an item. Only the fields outside
/// `sealed` are visible to the server (sync metadata).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRecord {
    pub id: Uuid,
    pub vault_id: Uuid,
    /// Monotonic per-item version; incremented on every write.
    pub version: u64,
    #[serde(with = "crate::item_ts")]
    pub modified_at: OffsetDateTime,
    /// Tombstone marker for permanent deletion (distinct from the user bin).
    #[serde(default)]
    pub deleted: bool,
    /// Current sealed content; `None` for a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealedBlob>,
    /// Up to [`MAX_HISTORY`] prior revisions, newest last.
    #[serde(default)]
    pub history: Vec<Revision>,
}

impl ItemRecord {
    fn push_history(&mut self, sealed: SealedBlob, modified_at: OffsetDateTime) {
        self.history.push(Revision {
            sealed,
            modified_at,
        });
        if self.history.len() > MAX_HISTORY {
            let overflow = self.history.len() - MAX_HISTORY;
            self.history.drain(0..overflow);
        }
    }
}

/// Auto-lock policy. Time is supplied by the caller so the core stays free of
/// platform clocks and remains deterministically testable.
#[derive(Debug, Clone)]
pub struct LockPolicy {
    /// Idle timeout; `None` means never auto-lock.
    pub idle_timeout: Option<Duration>,
    last_activity: OffsetDateTime,
}

impl LockPolicy {
    pub fn new(idle_timeout: Option<Duration>, now: OffsetDateTime) -> Self {
        Self {
            idle_timeout,
            last_activity: now,
        }
    }

    /// Record user activity, resetting the idle clock.
    pub fn touch(&mut self, now: OffsetDateTime) {
        self.last_activity = now;
    }

    /// Whether the vault should auto-lock as of `now`.
    pub fn should_lock(&self, now: OffsetDateTime) -> bool {
        match self.idle_timeout {
            Some(t) => now - self.last_activity >= t,
            None => false,
        }
    }
}

/// The unlocked vault. Dropping it (or calling [`Vault::lock`]) zeroises keys.
#[derive(Debug)]
pub struct Vault {
    keyring: KeyRing,
    items: HashMap<Uuid, ItemRecord>,
    index: SearchIndex,
    lock_policy: LockPolicy,
}

impl Vault {
    /// Unlock from account crypto + master password, hydrating from stored item
    /// records (e.g. the local encrypted cache).
    pub fn open(
        password: &crate::crypto::SecretVec,
        crypto: &AccountCrypto,
        records: Vec<ItemRecord>,
        now: OffsetDateTime,
    ) -> Result<Self> {
        let keyring = unlock(password, crypto)?;
        Self::hydrate(keyring, records, now)
    }

    /// Unlock via a biometric session key (the exported account key held in the
    /// OS keystore), skipping the master-password KDF.
    pub fn open_with_account_key(
        account_key: Key256,
        crypto: &AccountCrypto,
        records: Vec<ItemRecord>,
        now: OffsetDateTime,
    ) -> Result<Self> {
        let keyring = unlock_with_account_key(account_key, crypto)?;
        Self::hydrate(keyring, records, now)
    }

    /// Unlock via recovery code instead of the master password.
    pub fn open_with_recovery(
        recovery_code: &str,
        crypto: &AccountCrypto,
        records: Vec<ItemRecord>,
        now: OffsetDateTime,
    ) -> Result<Self> {
        let keyring = unlock_with_recovery(recovery_code, crypto)?;
        Self::hydrate(keyring, records, now)
    }

    /// Build a vault directly from an already-unlocked keyring (e.g. right after
    /// enrolment).
    pub fn from_keyring(keyring: KeyRing, now: OffsetDateTime) -> Self {
        Vault {
            keyring,
            items: HashMap::new(),
            index: SearchIndex::default(),
            lock_policy: LockPolicy::new(Some(DEFAULT_LOCK_TIMEOUT), now),
        }
    }

    fn hydrate(keyring: KeyRing, records: Vec<ItemRecord>, now: OffsetDateTime) -> Result<Self> {
        let mut v = Vault {
            keyring,
            items: HashMap::new(),
            index: SearchIndex::default(),
            lock_policy: LockPolicy::new(Some(DEFAULT_LOCK_TIMEOUT), now),
        };
        for rec in records {
            // Rebuild the search index from decrypted content of live items.
            if !rec.deleted {
                if let Some(sealed) = &rec.sealed {
                    let content = v.decrypt(rec.vault_id, rec.id, sealed)?;
                    if !content.is_binned() {
                        v.index.upsert(rec.id, &content);
                    }
                }
            }
            v.items.insert(rec.id, rec);
        }
        Ok(v)
    }

    // --- lock / lifecycle --------------------------------------------------

    /// Configure the auto-lock idle timeout (spec: 30s..never; `None` = never).
    pub fn set_lock_timeout(&mut self, timeout: Option<Duration>) {
        self.lock_policy.idle_timeout = timeout;
    }

    /// Record activity to defer auto-lock.
    pub fn touch(&mut self, now: OffsetDateTime) {
        self.lock_policy.touch(now);
    }

    /// Whether the vault should auto-lock now.
    pub fn should_lock(&self, now: OffsetDateTime) -> bool {
        self.lock_policy.should_lock(now)
    }

    /// Explicit lock: consume the vault, returning the sealed records to persist.
    /// The keyring is dropped here, zeroising all key material.
    pub fn lock(self) -> Vec<ItemRecord> {
        self.into_records()
        // `self.keyring` drops → keys zeroised.
    }

    // --- CRUD --------------------------------------------------------------

    /// Create a new item in `vault_id` (defaults to the primary vault).
    pub fn create(
        &mut self,
        vault_id: Option<Uuid>,
        content: &ItemContent,
        now: OffsetDateTime,
    ) -> Result<Uuid> {
        let vault_id = self.resolve_vault(vault_id)?;
        let id = Uuid::new_v4();
        let sealed = self.encrypt(vault_id, id, content)?;
        let rec = ItemRecord {
            id,
            vault_id,
            version: 1,
            modified_at: now,
            deleted: false,
            sealed: Some(sealed),
            history: Vec::new(),
        };
        if !content.is_binned() {
            self.index.upsert(id, content);
        }
        self.items.insert(id, rec);
        self.touch(now);
        Ok(id)
    }

    /// Read and decrypt an item's current content.
    pub fn get(&self, id: Uuid) -> Result<ItemContent> {
        let rec = self.record(id)?;
        let sealed = rec.sealed.as_ref().ok_or(Error::NotFound)?;
        self.decrypt(rec.vault_id, rec.id, sealed)
    }

    /// Update an item's content. The prior sealed content is pushed to history.
    pub fn update(&mut self, id: Uuid, content: &ItemContent, now: OffsetDateTime) -> Result<()> {
        let (vault_id, prior, prior_ts) = {
            let rec = self.record(id)?;
            (
                rec.vault_id,
                rec.sealed.clone().ok_or(Error::NotFound)?,
                rec.modified_at,
            )
        };
        let sealed = self.encrypt(vault_id, id, content)?;
        let rec = self.items.get_mut(&id).ok_or(Error::NotFound)?;
        rec.push_history(prior, prior_ts);
        rec.sealed = Some(sealed);
        rec.version += 1;
        rec.modified_at = now;

        if content.is_binned() {
            self.index.remove(id);
        } else {
            self.index.upsert(id, content);
        }
        self.touch(now);
        Ok(())
    }

    /// Soft-delete: move the item to the bin (restorable; hidden from search).
    pub fn move_to_bin(&mut self, id: Uuid, now: OffsetDateTime) -> Result<()> {
        let mut content = self.get(id)?;
        content.binned_at = Some(now);
        self.update(id, &content, now)
    }

    /// Restore an item from the bin.
    pub fn restore_from_bin(&mut self, id: Uuid, now: OffsetDateTime) -> Result<()> {
        let mut content = self.get(id)?;
        content.binned_at = None;
        self.update(id, &content, now)
    }

    /// Permanently delete: replace with a tombstone (no content), preserving
    /// version monotonicity for sync. History is cleared.
    pub fn delete_permanent(&mut self, id: Uuid, now: OffsetDateTime) -> Result<()> {
        let rec = self.items.get_mut(&id).ok_or(Error::NotFound)?;
        rec.deleted = true;
        rec.sealed = None;
        rec.history.clear();
        rec.version += 1;
        rec.modified_at = now;
        self.index.remove(id);
        self.touch(now);
        Ok(())
    }

    // --- history -----------------------------------------------------------

    /// Decrypted prior revisions of an item, newest first.
    pub fn history(&self, id: Uuid) -> Result<Vec<(OffsetDateTime, ItemContent)>> {
        let rec = self.record(id)?;
        let mut out = Vec::with_capacity(rec.history.len());
        for rev in rec.history.iter().rev() {
            let content = self.decrypt(rec.vault_id, rec.id, &rev.sealed)?;
            out.push((rev.modified_at, content));
        }
        Ok(out)
    }

    /// Restore a prior revision (index 0 = most recent prior). The restore is
    /// itself recorded in history.
    pub fn restore_revision(
        &mut self,
        id: Uuid,
        revision_index: usize,
        now: OffsetDateTime,
    ) -> Result<()> {
        let content = {
            let rec = self.record(id)?;
            let n = rec.history.len();
            if revision_index >= n {
                return Err(Error::NotFound);
            }
            // revision_index 0 == newest prior == last in the Vec.
            let rev = &rec.history[n - 1 - revision_index];
            self.decrypt(rec.vault_id, rec.id, &rev.sealed)?
        };
        self.update(id, &content, now)
    }

    // --- listing / query ---------------------------------------------------

    /// Live (non-tombstone, non-binned) item ids.
    pub fn list_active(&self) -> Vec<Uuid> {
        self.items
            .values()
            .filter(|r| !r.deleted && r.sealed.is_some())
            .filter(|r| self.index.contains(r.id))
            .map(|r| r.id)
            .collect()
    }

    /// Ids of items currently in the bin.
    pub fn list_bin(&self) -> Result<Vec<Uuid>> {
        let mut out = Vec::new();
        for rec in self.items.values() {
            if rec.deleted {
                continue;
            }
            if let Some(sealed) = &rec.sealed {
                if self.decrypt(rec.vault_id, rec.id, sealed)?.is_binned() {
                    out.push(rec.id);
                }
            }
        }
        Ok(out)
    }

    /// Case-insensitive search across titles, usernames, and URIs.
    pub fn search(&self, query: &str) -> Vec<Uuid> {
        self.index.query(query)
    }

    /// Autofill candidates for `target`, best-matching first.
    pub fn candidates_for(&self, target: &str) -> Result<Vec<Uuid>> {
        let mut scored: Vec<(u8, Uuid)> = Vec::new();
        for id in self.list_active() {
            let content = self.get(id)?;
            if let Some(m) = content.best_match(target) {
                scored.push((m as u8, id));
            }
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(scored.into_iter().map(|(_, id)| id).collect())
    }

    /// All distinct folder names across live items.
    pub fn folders(&self) -> Result<Vec<String>> {
        let mut set = std::collections::BTreeSet::new();
        for id in self.list_active() {
            if let Some(f) = self.get(id)?.folder {
                set.insert(f);
            }
        }
        Ok(set.into_iter().collect())
    }

    /// All distinct tags across live items.
    pub fn tags(&self) -> Result<Vec<String>> {
        let mut set = std::collections::BTreeSet::new();
        for id in self.list_active() {
            for t in self.get(id)?.tags {
                set.insert(t);
            }
        }
        Ok(set.into_iter().collect())
    }

    // --- sync support ------------------------------------------------------

    /// Borrow all raw records (for the sync engine).
    pub fn records(&self) -> impl Iterator<Item = &ItemRecord> {
        self.items.values()
    }

    pub fn record(&self, id: Uuid) -> Result<&ItemRecord> {
        self.items.get(&id).ok_or(Error::NotFound)
    }

    /// Access the keyring (for sync/rewrapping operations).
    pub fn keyring(&self) -> &KeyRing {
        &self.keyring
    }

    /// Ingest a record received from the server (public wrapper over
    /// [`Self::apply_record`]) for clients that drive sync externally.
    pub fn ingest_record(&mut self, rec: ItemRecord) -> Result<()> {
        self.apply_record(rec)
    }

    /// Insert or replace a record coming from sync, refreshing the index.
    pub(crate) fn apply_record(&mut self, rec: ItemRecord) -> Result<()> {
        if rec.deleted {
            self.index.remove(rec.id);
        } else if let Some(sealed) = &rec.sealed {
            let content = self.decrypt(rec.vault_id, rec.id, sealed)?;
            if content.is_binned() {
                self.index.remove(rec.id);
            } else {
                self.index.upsert(rec.id, &content);
            }
        }
        self.items.insert(rec.id, rec);
        Ok(())
    }

    fn into_records(self) -> Vec<ItemRecord> {
        self.items.into_values().collect()
    }

    // --- internals ---------------------------------------------------------

    fn resolve_vault(&self, vault_id: Option<Uuid>) -> Result<Uuid> {
        match vault_id {
            Some(v) => {
                // Validate the vault exists in the keyring.
                self.keyring.vault_key(v)?;
                Ok(v)
            }
            None => self.keyring.primary_vault().ok_or(Error::NotFound),
        }
    }

    /// AAD binds ciphertext to its item id, preventing blob substitution.
    fn aad(item_id: Uuid) -> [u8; 16] {
        *item_id.as_bytes()
    }

    fn encrypt(&self, vault_id: Uuid, item_id: Uuid, content: &ItemContent) -> Result<SealedBlob> {
        let key = self.keyring.vault_key(vault_id)?;
        let plaintext = serde_json::to_vec(content)?;
        seal(key, &plaintext, &Self::aad(item_id))
    }

    fn decrypt(&self, vault_id: Uuid, item_id: Uuid, sealed: &SealedBlob) -> Result<ItemContent> {
        let key = self.keyring.vault_key(vault_id)?;
        let plaintext = open(key, sealed, &Self::aad(item_id))?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}
