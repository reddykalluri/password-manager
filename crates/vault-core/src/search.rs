//! In-memory, case-insensitive search over item titles, usernames, and URIs.
//!
//! At rest, items are encrypted; this index is rebuilt in memory each time the
//! vault is unlocked (see [`crate::store::Vault::open`]) and never persisted in
//! plaintext — satisfying "encrypted-at-rest" while giving sub-millisecond
//! queries over the working set.
//!
//! For the spec's 5,000-item target a flat scan of short, pre-lowercased
//! strings completes far inside the 50 ms desktop / 150 ms mobile budget; the
//! `bench` harness in `benches/` measures it. Results are ranked so the most
//! relevant items surface first while typing.

use std::collections::HashMap;

use uuid::Uuid;

use crate::item::ItemContent;

/// Pre-lowercased searchable projection of an item.
#[derive(Debug, Clone, Default)]
struct Entry {
    title: String,
    username: String,
    uris: Vec<String>,
}

/// Match rank; higher sorts first.
fn score(entry: &Entry, q: &str) -> Option<u32> {
    if q.is_empty() {
        return Some(1); // empty query lists everything at a flat rank
    }
    if entry.title.starts_with(q) {
        Some(100)
    } else if entry.title.contains(q) {
        Some(80)
    } else if entry.username.starts_with(q) {
        Some(60)
    } else if entry.username.contains(q) {
        Some(50)
    } else if entry.uris.iter().any(|u| u.contains(q)) {
        Some(40)
    } else {
        None
    }
}

/// The search index. Cheap to mutate on every CRUD operation.
#[derive(Debug, Default)]
pub struct SearchIndex {
    entries: HashMap<Uuid, Entry>,
}

impl SearchIndex {
    /// Insert or replace an item's searchable projection.
    pub fn upsert(&mut self, id: Uuid, content: &ItemContent) {
        let entry = Entry {
            title: content.title.to_lowercase(),
            username: content.username().unwrap_or("").to_lowercase(),
            uris: content
                .uris()
                .iter()
                .map(|u| u.value.to_lowercase())
                .collect(),
        };
        self.entries.insert(id, entry);
    }

    /// Drop an item from the index (delete or bin).
    pub fn remove(&mut self, id: Uuid) {
        self.entries.remove(&id);
    }

    pub fn contains(&self, id: Uuid) -> bool {
        self.entries.contains_key(&id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Ranked query. Ties break by title for stable ordering.
    pub fn query(&self, query: &str) -> Vec<Uuid> {
        let q = query.trim().to_lowercase();
        let mut hits: Vec<(u32, &str, Uuid)> = self
            .entries
            .iter()
            .filter_map(|(id, e)| score(e, &q).map(|s| (s, e.title.as_str(), *id)))
            .collect();
        hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
        hits.into_iter().map(|(_, _, id)| id).collect()
    }
}
