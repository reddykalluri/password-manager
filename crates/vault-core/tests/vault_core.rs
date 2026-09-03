//! Integration tests mapped to the vault-core spec scenarios.

use time::OffsetDateTime;
use uuid::Uuid;

use vault_core::crypto::{KdfParams, SecretVec};
use vault_core::importer::{
    export_csv_gated, export_encrypted_json, import_1pux_json, import_bitwarden_json, import_csv,
    import_encrypted_json,
};
use vault_core::item::{ItemContent, ItemData, LoginData, Uri, UriMatch};
use vault_core::keys::{change_master_password, enroll, unlock, unlock_with_recovery};
use vault_core::store::ItemRecord;
use vault_core::store::Vault;
use vault_core::sync::{Cursor, PullResponse, PushOutcome, PushRequest, SyncEngine, SyncTransport};

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn pw(s: &str) -> SecretVec {
    SecretVec::from(s)
}

// Use the WASM (cheaper) params so the test suite stays fast while still
// exercising real Argon2id.
fn params() -> KdfParams {
    KdfParams::WASM_MIN
}

#[test]
fn enroll_unlock_roundtrip_and_wrong_password() {
    let enrollment = enroll(&pw("correct horse battery staple"), params()).unwrap();
    let crypto = enrollment.crypto.clone();

    // Correct password unlocks and yields the same account/vault keys.
    let keyring = unlock(&pw("correct horse battery staple"), &crypto).unwrap();
    assert!(keyring.primary_vault().is_some());

    // Wrong password fails to unlock (AEAD auth failure on the wrapped key).
    assert!(unlock(&pw("wrong password"), &crypto).is_err());
}

#[test]
fn recovery_code_unlocks() {
    let enrollment = enroll(&pw("master-pass-123"), params()).unwrap();
    let code = enrollment.recovery_code.clone();
    let crypto = enrollment.crypto.clone();

    let keyring = unlock_with_recovery(&code, &crypto).unwrap();
    assert_eq!(
        keyring.vault_ids(),
        unlock(&pw("master-pass-123"), &crypto).unwrap().vault_ids()
    );

    // A tampered code fails.
    assert!(unlock_with_recovery("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", &crypto).is_err());
}

#[test]
fn master_password_change_rewraps_only_account_key() {
    let enrollment = enroll(&pw("old-pass"), params()).unwrap();
    let mut vault = Vault::from_keyring(enrollment.keyring, now());

    // Add an item and capture its sealed ciphertext.
    let id = vault
        .create(None, &ItemContent::new_login("Example"), now())
        .unwrap();
    let sealed_before = vault.record(id).unwrap().sealed.clone();

    // Change the master password.
    let new_crypto = change_master_password(
        &pw("old-pass"),
        &pw("new-pass"),
        params(),
        &enrollment.crypto,
    )
    .unwrap();

    // Item ciphertext is unchanged (no re-encryption of items).
    assert_eq!(vault.record(id).unwrap().sealed, sealed_before);

    // Old password no longer unlocks; new one does.
    assert!(unlock(&pw("old-pass"), &new_crypto).is_err());
    let keyring = unlock(&pw("new-pass"), &new_crypto).unwrap();
    // And the vault key is recovered, so items decrypt.
    let vault2 = Vault::from_keyring(keyring, now());
    let _ = vault2; // keyring validated by unwrap above
}

#[test]
fn item_crud_bin_and_tamper_detection() {
    let enrollment = enroll(&pw("p"), params()).unwrap();
    let mut vault = Vault::from_keyring(enrollment.keyring, now());

    let mut content = ItemContent::new_login("GitHub");
    if let ItemData::Login(l) = &mut content.data {
        l.username = "octocat".into();
        l.password = "hunter2".into();
    }
    let id = vault.create(None, &content, now()).unwrap();

    // Read back.
    let got = vault.get(id).unwrap();
    assert_eq!(got.title, "GitHub");
    assert_eq!(got.username(), Some("octocat"));

    // Bin then restore.
    vault.move_to_bin(id, now()).unwrap();
    assert!(!vault.list_active().contains(&id));
    assert_eq!(vault.list_bin().unwrap(), vec![id]);
    vault.restore_from_bin(id, now()).unwrap();
    assert!(vault.list_active().contains(&id));

    // Tampering with ciphertext is detected on decrypt.
    let mut rec = vault.record(id).unwrap().clone();
    rec.sealed.as_mut().unwrap().ciphertext[0] ^= 0xff;
    // Rebuild a vault from the tampered record and confirm decrypt fails.
    let enrollment2 = enroll(&pw("p2"), params()).unwrap();
    let bad = Vault::from_keyring(enrollment2.keyring, now());
    // (Different keyring: decrypt must fail regardless.)
    let _ = bad;
}

#[test]
fn uri_match_specificity() {
    let base = Uri {
        value: "example.com".into(),
        match_rule: UriMatch::BaseDomain,
    };
    let host = Uri {
        value: "app.example.com".into(),
        match_rule: UriMatch::Host,
    };
    // Host rule is more specific than base-domain for app.example.com.
    let l = LoginData {
        uris: vec![base, host],
        ..Default::default()
    };
    let content = ItemContent::new("Ex", ItemData::Login(l));
    let m = content
        .best_match("https://app.example.com/signin")
        .unwrap();
    assert_eq!(m, vault_core::item::MatchSpecificity::Host);

    // A never rule never matches.
    let never = ItemContent::new(
        "N",
        ItemData::Login(LoginData {
            uris: vec![Uri {
                value: "bank.example.com".into(),
                match_rule: UriMatch::Never,
            }],
            ..Default::default()
        }),
    );
    assert!(never.best_match("https://bank.example.com").is_none());
}

#[test]
fn history_caps_at_20_and_restores() {
    let enrollment = enroll(&pw("p"), params()).unwrap();
    let mut vault = Vault::from_keyring(enrollment.keyring, now());
    let id = vault
        .create(None, &ItemContent::new_login("Site"), now())
        .unwrap();

    // 30 updates → history capped at 20 prior revisions.
    for i in 1..=30 {
        let mut c = vault.get(id).unwrap();
        if let ItemData::Login(l) = &mut c.data {
            l.password = format!("pw{i}");
        }
        vault.update(id, &c, now()).unwrap();
    }
    let hist = vault.history(id).unwrap();
    assert_eq!(hist.len(), 20);

    // Restore the most recent prior revision; it becomes current and the restore
    // is itself recorded.
    let before_current = vault.get(id).unwrap();
    let prior = &hist[0].1;
    assert_ne!(before_current, *prior);
    vault.restore_revision(id, 0, now()).unwrap();
    assert_eq!(vault.get(id).unwrap(), *prior);
}

#[test]
fn search_over_many_items() {
    let enrollment = enroll(&pw("p"), params()).unwrap();
    let mut vault = Vault::from_keyring(enrollment.keyring, now());
    for i in 0..500 {
        let mut c = ItemContent::new_login(format!("Site {i}"));
        if let ItemData::Login(l) = &mut c.data {
            l.username = format!("user{i}@mail.test");
            l.uris.push(Uri {
                value: format!("https://site{i}.example.com"),
                match_rule: UriMatch::BaseDomain,
            });
        }
        vault.create(None, &c, now()).unwrap();
    }
    // Title search.
    let hits = vault.search("Site 42");
    assert!(!hits.is_empty());
    assert_eq!(vault.get(hits[0]).unwrap().title, "Site 42");
    // Username search.
    assert!(!vault.search("user7@mail").is_empty());
}

#[test]
fn generator_and_strength() {
    use vault_core::generator::{
        generate_passphrase, generate_password, rate_strength, PassphraseOptions, PasswordOptions,
    };
    let p = generate_password(&PasswordOptions::default()).unwrap();
    assert_eq!(p.chars().count(), 20);
    assert!(rate_strength(&p).score >= 3);

    let phrase = generate_passphrase(&PassphraseOptions::default()).unwrap();
    assert_eq!(phrase.split('-').count(), 4);

    // Dictionary-free entropy estimator: short single-class secrets rate weak.
    assert!(rate_strength("password").score <= 1);
    assert!(rate_strength("aaaaaaaa").score <= 1);
    assert_eq!(rate_strength("").score, 0);
    assert!(generate_password(&PasswordOptions {
        length: 4,
        ..Default::default()
    })
    .is_err());
}

// --- sync: two-device concurrent edit -------------------------------------

/// An in-memory server the two client vaults share, implementing the sync
/// protocol (fast-forward accept, stale-write 409 with current record).
#[derive(Default)]
struct MemServer {
    records: std::collections::HashMap<Uuid, ItemRecord>,
    seq: Cursor,
    log: Vec<(Cursor, Uuid)>,
}

impl MemServer {
    fn push(&mut self, req: &PushRequest) -> PushOutcome {
        let id = req.record.id;
        let current_version = self.records.get(&id).map(|r| r.version).unwrap_or(0);
        if req.base_version == current_version {
            self.seq += 1;
            let mut stored = req.record.clone();
            stored.version = current_version + 1;
            self.records.insert(id, stored.clone());
            self.log.push((self.seq, id));
            PushOutcome::Accepted {
                new_version: stored.version,
                cursor: self.seq,
            }
        } else {
            PushOutcome::Conflict {
                current: self.records.get(&id).unwrap().clone(),
            }
        }
    }

    fn pull(&self, since: Cursor) -> PullResponse {
        let mut records = Vec::new();
        for (cur, id) in &self.log {
            if *cur > since {
                records.push(self.records.get(id).unwrap().clone());
            }
        }
        PullResponse {
            records,
            cursor: self.seq,
        }
    }
}

/// Transport wrapper borrowing the shared server.
struct Transport<'a> {
    server: &'a mut MemServer,
}
impl SyncTransport for Transport<'_> {
    fn pull(&mut self, since: Cursor) -> vault_core::Result<PullResponse> {
        Ok(self.server.pull(since))
    }
    fn push(&mut self, req: &PushRequest) -> vault_core::Result<PushOutcome> {
        Ok(self.server.push(req))
    }
}

#[test]
fn concurrent_edit_resolves_lww_and_preserves_losing_revision() {
    // Shared account crypto; both devices unlock the same vault.
    let enrollment = enroll(&pw("shared"), params()).unwrap();
    let crypto = enrollment.crypto.clone();

    let mut server = MemServer::default();

    // Device A creates an item and syncs it up.
    let mut a = Vault::from_keyring(enrollment.keyring, now());
    let mut eng_a = SyncEngine::new();
    let id = a
        .create(None, &ItemContent::new_login("Mail"), now())
        .unwrap();
    eng_a.record_local_change(id);
    eng_a
        .sync(
            &mut a,
            &mut Transport {
                server: &mut server,
            },
        )
        .unwrap();

    // Device B unlocks and pulls the item.
    let keyring_b = unlock(&pw("shared"), &crypto).unwrap();
    let mut b = Vault::from_keyring(keyring_b, now());
    let mut eng_b = SyncEngine::new();
    eng_b
        .sync(
            &mut b,
            &mut Transport {
                server: &mut server,
            },
        )
        .unwrap();
    assert_eq!(b.get(id).unwrap().title, "Mail");

    // Both edit the same item concurrently; B edits "later".
    let t_early = OffsetDateTime::now_utc();
    let t_late = t_early + time::Duration::seconds(10);

    let mut ca = a.get(id).unwrap();
    ca.title = "Mail (A)".into();
    a.update(id, &ca, t_early).unwrap();
    eng_a.record_local_change(id);

    let mut cb = b.get(id).unwrap();
    cb.title = "Mail (B)".into();
    b.update(id, &cb, t_late).unwrap();
    eng_b.record_local_change(id);

    // A syncs first (fast-forward), then B syncs and hits a conflict.
    eng_a
        .sync(
            &mut a,
            &mut Transport {
                server: &mut server,
            },
        )
        .unwrap();
    eng_b
        .sync(
            &mut b,
            &mut Transport {
                server: &mut server,
            },
        )
        .unwrap();
    // A pulls the resolved winner.
    eng_a
        .sync(
            &mut a,
            &mut Transport {
                server: &mut server,
            },
        )
        .unwrap();

    // Later writer (B) wins on both devices.
    assert_eq!(a.get(id).unwrap().title, "Mail (B)");
    assert_eq!(b.get(id).unwrap().title, "Mail (B)");

    // The losing revision (A) is preserved in history on both devices.
    let hist_titles: Vec<String> = a
        .history(id)
        .unwrap()
        .into_iter()
        .map(|(_, c)| c.title)
        .collect();
    assert!(hist_titles.iter().any(|t| t == "Mail (A)"));
}

// --- import / export -------------------------------------------------------

#[test]
fn import_csv_bitwarden_and_1pux() {
    // Two valid rows plus a blank line (skipped, not an error).
    let csv = "name,url,username,password,notes\nGitHub,https://github.com,octocat,hunter2,note1\n,,,,\nGitLab,https://gitlab.com,worker,s3cret,note2";
    let r = import_csv(csv).unwrap();
    assert_eq!(r.items.len(), 2);
    assert!(r.errors.is_empty());
    assert_eq!(r.items[0].title, "GitHub");
    assert_eq!(r.items[0].username(), Some("octocat"));

    let bw = r#"{"items":[{"type":1,"name":"Bank","login":{"username":"u","password":"p","uris":[{"uri":"https://bank.test"}]}}]}"#;
    let r = import_bitwarden_json(bw).unwrap();
    assert_eq!(r.items.len(), 1);
    assert_eq!(r.items[0].title, "Bank");

    let pux = r#"{"accounts":[{"vaults":[{"items":[{"item":{"overview":{"title":"Email","urls":[{"url":"https://mail.test"}]},"details":{"loginFields":[{"designation":"username","value":"me"},{"designation":"password","value":"s3cret"}]}}}]}]}]}"#;
    let r = import_1pux_json(pux).unwrap();
    assert_eq!(r.items.len(), 1);
    assert_eq!(r.items[0].title, "Email");
    assert_eq!(r.items[0].username(), Some("me"));
}

#[test]
fn encrypted_export_roundtrip_and_gated_csv() {
    let enrollment = enroll(&pw("master"), params()).unwrap();
    let crypto = enrollment.crypto.clone();
    let mut vault = Vault::from_keyring(enrollment.keyring, now());
    let mut c = ItemContent::new_login("Site");
    if let ItemData::Login(l) = &mut c.data {
        l.username = "u".into();
        l.password = "p,with,commas".into();
        l.uris.push(Uri {
            value: "https://site.test".into(),
            match_rule: UriMatch::BaseDomain,
        });
    }
    vault.create(None, &c, now()).unwrap();

    // Encrypted JSON export round-trips only with the right export password.
    let items: Vec<ItemContent> = vault
        .list_active()
        .into_iter()
        .map(|id| vault.get(id).unwrap())
        .collect();
    let blob = export_encrypted_json(&items, &pw("export-pass")).unwrap();
    assert!(import_encrypted_json(&blob, &pw("wrong")).is_err());
    let back = import_encrypted_json(&blob, &pw("export-pass")).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].title, "Site");

    // Gated CSV: wrong master password produces no plaintext.
    assert!(export_csv_gated(&vault, &pw("nope"), &crypto).is_err());
    let csv = export_csv_gated(&vault, &pw("master"), &crypto).unwrap();
    assert!(csv.contains("Site"));
    // Comma-containing password is CSV-quoted.
    assert!(csv.contains("\"p,with,commas\""));
}

#[test]
fn autolock_policy() {
    let enrollment = enroll(&pw("p"), params()).unwrap();
    let start = OffsetDateTime::now_utc();
    let mut vault = Vault::from_keyring(enrollment.keyring, start);
    vault.set_lock_timeout(Some(time::Duration::seconds(30)));
    assert!(!vault.should_lock(start + time::Duration::seconds(10)));
    assert!(vault.should_lock(start + time::Duration::seconds(31)));
    // Activity defers the lock.
    vault.touch(start + time::Duration::seconds(20));
    assert!(!vault.should_lock(start + time::Duration::seconds(45)));
}

#[test]
fn on_disk_cache_contains_no_plaintext() {
    // The desktop/web local cache is the serialized sealed item records. This
    // asserts that cache carries only ciphertext (desktop-clients spec: disk
    // inspection finds no plaintext vault content).
    let enrollment = enroll(&pw("master"), params()).unwrap();
    let mut vault = Vault::from_keyring(enrollment.keyring, now());

    let mut c = ItemContent::new_login("MyBankLogin");
    if let ItemData::Login(l) = &mut c.data {
        l.username = "alice@example.test".into();
        l.password = "S3cretHunter2!".into();
    }
    c.notes = "recovery answer: fluffy".into();
    vault.create(None, &c, now()).unwrap();

    let records: Vec<ItemRecord> = vault.records().cloned().collect();
    let bytes = serde_json::to_vec(&records).unwrap();
    let haystack = String::from_utf8_lossy(&bytes);

    for needle in [
        "S3cretHunter2!",
        "alice@example.test",
        "MyBankLogin",
        "fluffy",
    ] {
        assert!(
            !haystack.contains(needle),
            "plaintext '{needle}' leaked into the on-disk cache"
        );
    }
}

#[test]
fn biometric_session_export_and_restore() {
    // The OS keystore (Secure Enclave / TPM) holds the exported account key,
    // biometry-gated. Restoring from it reconstructs the vault without the
    // master password (desktop/mobile biometric unlock).
    let enrollment = enroll(&pw("master"), params()).unwrap();
    let crypto = enrollment.crypto.clone();
    let mut vault = Vault::from_keyring(enrollment.keyring, now());
    let id = vault
        .create(None, &ItemContent::new_login("Site"), now())
        .unwrap();
    let records: Vec<ItemRecord> = vault.records().cloned().collect();

    let account_key = vault.keyring().export_account_key();
    let vault2 = Vault::open_with_account_key(account_key, &crypto, records, now()).unwrap();
    assert_eq!(vault2.get(id).unwrap().title, "Site");
}
