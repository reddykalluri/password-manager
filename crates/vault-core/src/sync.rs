//! Client side of the offline-first, state-based sync protocol
//! (design.md Decision 5).
//!
//! - Every item carries `(uuid, version, modified_at, tombstone)`.
//! - The client pulls records changed since a cursor and pushes local changes
//!   carrying the base version.
//! - The server accepts fast-forwards and rejects stale writes with the current
//!   record; conflicts resolve **client-side**, last-writer-wins per item by
//!   `modified_at`, with the losing revision preserved in item history — never
//!   silently dropped.
//!
//! vault-core is transport-agnostic: networking is provided by an implementor
//! of [`SyncTransport`] (the server crate supplies an HTTP one).

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::error::Result;
use crate::store::{ItemRecord, Vault, MAX_HISTORY};

/// Opaque server change-sequence cursor.
pub type Cursor = u64;

/// A push carrying the base (last-synced) server version for optimistic
/// concurrency.
#[derive(Debug, Clone)]
pub struct PushRequest {
    pub record: ItemRecord,
    pub base_version: u64,
}

/// Server outcome of a push.
#[derive(Debug, Clone)]
pub enum PushOutcome {
    /// Fast-forward accepted; the server assigned `new_version` and advanced the
    /// change log to `cursor`.
    Accepted { new_version: u64, cursor: Cursor },
    /// Stale write: the server returned its current record for client-side merge.
    Conflict { current: ItemRecord },
}

/// Records changed since a cursor, plus the new cursor.
#[derive(Debug, Clone)]
pub struct PullResponse {
    pub records: Vec<ItemRecord>,
    pub cursor: Cursor,
}

/// Networking abstraction. Implementors talk to the server's sync API.
pub trait SyncTransport {
    fn pull(&mut self, since: Cursor) -> Result<PullResponse>;
    fn push(&mut self, req: &PushRequest) -> Result<PushOutcome>;
}

/// Merge two competing records for the same item, last-writer-wins by
/// `modified_at`. The losing revision's sealed content is appended to the
/// winner's history so no edit is lost. Ties break deterministically by version
/// then uuid.
///
/// The returned record adopts the winner's content but is *based on* the
/// server's version lineage; the caller assigns the next version on push.
pub fn merge_lww(local: &ItemRecord, server: &ItemRecord) -> ItemRecord {
    let local_wins = match local.modified_at.cmp(&server.modified_at) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => match local.version.cmp(&server.version) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => local.id >= server.id,
        },
    };
    let (winner, loser) = if local_wins {
        (local, server)
    } else {
        (server, local)
    };

    let mut merged = winner.clone();
    // Preserve the loser's content in history (unless it is a tombstone).
    if let Some(sealed) = &loser.sealed {
        merged.history.push(crate::store::Revision {
            sealed: sealed.clone(),
            modified_at: loser.modified_at,
        });
    }
    // Also fold in the loser's own history so nothing is dropped, then cap.
    for rev in &loser.history {
        merged.history.push(rev.clone());
    }
    if merged.history.len() > MAX_HISTORY {
        let overflow = merged.history.len() - MAX_HISTORY;
        merged.history.drain(0..overflow);
    }
    merged
}

/// The client sync engine: tracks the cursor, the server version each local
/// item is based on, and which items are dirty (edited since last sync).
#[derive(Debug, Default)]
pub struct SyncEngine {
    cursor: Cursor,
    /// Last server version adopted for each item.
    base_versions: HashMap<Uuid, u64>,
    /// Items edited locally and awaiting push.
    dirty: HashSet<Uuid>,
}

impl SyncEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a persisted cursor (e.g. from the local cache).
    pub fn with_cursor(mut self, cursor: Cursor) -> Self {
        self.cursor = cursor;
        self
    }

    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Note that an item was changed locally (call after any CRUD write). Queues
    /// it for the next push.
    pub fn record_local_change(&mut self, id: Uuid) {
        self.dirty.insert(id);
    }

    pub fn pending(&self) -> usize {
        self.dirty.len()
    }

    /// Run a full sync round: pull remote changes and merge, then push local
    /// changes, resolving any conflicts client-side.
    pub fn sync<T: SyncTransport>(&mut self, vault: &mut Vault, transport: &mut T) -> Result<()> {
        self.pull_phase(vault, transport)?;
        self.push_phase(vault, transport)?;
        Ok(())
    }

    fn pull_phase<T: SyncTransport>(&mut self, vault: &mut Vault, transport: &mut T) -> Result<()> {
        let resp = transport.pull(self.cursor)?;
        for remote in resp.records {
            let id = remote.id;
            let is_dirty = self.dirty.contains(&id);
            match vault.record(id).ok().cloned() {
                // Unknown or clean locally → adopt the server record.
                None => {
                    self.base_versions.insert(id, remote.version);
                    vault.apply_record(remote)?;
                }
                Some(_local) if !is_dirty => {
                    self.base_versions.insert(id, remote.version);
                    vault.apply_record(remote)?;
                }
                // Concurrent local + remote edit → merge, keep dirty to re-push.
                Some(local) => {
                    let merged = merge_lww(&local, &remote);
                    self.base_versions.insert(id, remote.version);
                    vault.apply_record(merged)?;
                    // Stays dirty; push_phase will upload the merged winner.
                }
            }
        }
        self.cursor = resp.cursor;
        Ok(())
    }

    fn push_phase<T: SyncTransport>(&mut self, vault: &mut Vault, transport: &mut T) -> Result<()> {
        let dirty: Vec<Uuid> = self.dirty.iter().copied().collect();
        for id in dirty {
            let Ok(record) = vault.record(id).cloned() else {
                // Item vanished locally; drop from the queue.
                self.dirty.remove(&id);
                continue;
            };
            let base_version = self.base_versions.get(&id).copied().unwrap_or(0);
            let mut req = PushRequest {
                record,
                base_version,
            };

            loop {
                match transport.push(&req)? {
                    PushOutcome::Accepted {
                        new_version,
                        cursor,
                    } => {
                        // Reflect the server-assigned version locally.
                        let mut updated = req.record.clone();
                        updated.version = new_version;
                        vault.apply_record(updated)?;
                        self.base_versions.insert(id, new_version);
                        self.cursor = self.cursor.max(cursor);
                        self.dirty.remove(&id);
                        break;
                    }
                    PushOutcome::Conflict { current } => {
                        // Merge against the server's current record and retry.
                        let local = req.record.clone();
                        let merged = merge_lww(&local, &current);
                        self.base_versions.insert(id, current.version);
                        vault.apply_record(merged.clone())?;
                        req = PushRequest {
                            record: merged,
                            base_version: current.version,
                        };
                        // loop retries the push with the merged record.
                    }
                }
            }
        }
        Ok(())
    }
}
