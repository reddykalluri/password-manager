//! Benchmark harness for the search index at the spec's 5,000-item target.
//!
//! The vault-core spec requires search over 5,000 items to return under 50 ms on
//! reference desktop hardware (150 ms mobile). This measures the median query
//! latency and asserts the desktop budget, so a regression fails CI. Run with
//! `cargo test -p vault-core --test search_bench -- --nocapture` to see numbers.

use std::time::Instant;

use time::OffsetDateTime;

use vault_core::crypto::{KdfParams, SecretVec};
use vault_core::item::{ItemContent, ItemData, Uri, UriMatch};
use vault_core::keys::enroll;
use vault_core::store::Vault;

const N: usize = 5_000;
const QUERIES: usize = 200;
/// Desktop budget from the spec, with headroom for CI-runner jitter.
const BUDGET_MS: f64 = 50.0;

fn build_vault() -> Vault {
    let enrollment = enroll(&SecretVec::from("bench"), KdfParams::WASM_MIN).unwrap();
    let now = OffsetDateTime::now_utc();
    let mut vault = Vault::from_keyring(enrollment.keyring, now);
    for i in 0..N {
        let mut c = ItemContent::new_login(format!("Account {i} for service"));
        if let ItemData::Login(l) = &mut c.data {
            l.username = format!("user{i}@example.test");
            l.uris.push(Uri {
                value: format!("https://service{i}.example.com/login"),
                match_rule: UriMatch::BaseDomain,
            });
        }
        vault.create(None, &c, now).unwrap();
    }
    vault
}

#[test]
fn search_5000_items_under_budget() {
    let vault = build_vault();

    // Warm up.
    let _ = vault.search("Account 100");

    let mut timings_us: Vec<u128> = Vec::with_capacity(QUERIES);
    for i in 0..QUERIES {
        let q = format!("Account {}", i * 7 % N);
        let t = Instant::now();
        let hits = vault.search(&q);
        timings_us.push(t.elapsed().as_micros());
        assert!(!hits.is_empty(), "expected a hit for {q}");
    }
    timings_us.sort_unstable();
    let median_ms = timings_us[QUERIES / 2] as f64 / 1000.0;
    let p95_ms = timings_us[(QUERIES as f64 * 0.95) as usize] as f64 / 1000.0;
    eprintln!("search@{N}: median {median_ms:.3} ms, p95 {p95_ms:.3} ms (budget {BUDGET_MS} ms)");
    assert!(
        p95_ms < BUDGET_MS,
        "p95 search latency {p95_ms:.3} ms exceeded {BUDGET_MS} ms budget"
    );
}
