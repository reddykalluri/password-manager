//! In-memory failed-auth rate limiting with exponential backoff, per account and
//! per source IP (server spec: OPAQUE authentication).
//!
//! Per-account counters are also persisted (see `accounts.failed_logins`) so
//! backoff survives restarts; this in-memory layer additionally throttles by IP
//! to blunt spraying across accounts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tracks failures keyed by an arbitrary string (IP or account id).
#[derive(Debug, Default)]
pub struct RateLimiter {
    inner: Mutex<HashMap<String, Bucket>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// If the key is currently blocked, return the remaining seconds.
    pub fn check(&self, key: &str) -> Option<u64> {
        let map = self.inner.lock().unwrap();
        map.get(key).and_then(|b| {
            b.blocked_until.and_then(|until| {
                let now = Instant::now();
                (until > now).then(|| (until - now).as_secs() + 1)
            })
        })
    }

    /// Record a failure and compute the new block window with exponential
    /// backoff after `threshold` failures.
    pub fn record_failure(&self, key: &str, threshold: u32) -> u64 {
        let mut map = self.inner.lock().unwrap();
        let bucket = map.entry(key.to_string()).or_insert(Bucket {
            failures: 0,
            blocked_until: None,
        });
        bucket.failures += 1;
        if bucket.failures >= threshold {
            // Backoff: 2^(failures-threshold) seconds, capped at 15 minutes.
            let over = bucket.failures - threshold;
            let secs = 2u64.saturating_pow(over.min(10)).min(900);
            bucket.blocked_until = Some(Instant::now() + Duration::from_secs(secs));
            secs
        } else {
            0
        }
    }

    /// Clear a key after a successful auth.
    pub fn reset(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_kicks_in_after_threshold() {
        let rl = RateLimiter::new();
        for _ in 0..9 {
            assert_eq!(rl.record_failure("ip", 10), 0);
            assert!(rl.check("ip").is_none());
        }
        // 10th failure triggers a block.
        let wait = rl.record_failure("ip", 10);
        assert!(wait >= 1);
        assert!(rl.check("ip").is_some());
        rl.reset("ip");
        assert!(rl.check("ip").is_none());
    }
}
