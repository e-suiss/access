//! The governor layer (§10.6, §14.6): token buckets per caller key, so one source cannot spend a
//! gateway's capacity. Keys are kept as SHA-256 digests, never as the identifier or address
//! itself (OP-47). The table is bounded; when it is full and nothing in it has refilled, a new
//! key is refused (fail closed).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Most keys tracked at once.
pub const MAX_KEYS: usize = 65_536;

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens_milli: u64,
    at_ms: u64,
}

/// Token buckets: `burst` requests at once, refilled at `per_second`.
#[derive(Debug)]
pub struct Governor {
    per_second: u64,
    burst: u64,
    max_keys: usize,
    buckets: Mutex<HashMap<[u8; 32], Bucket>>,
}

impl Governor {
    /// A governor allowing `burst` requests at once and `per_second` sustained, per key.
    #[must_use]
    pub fn new(per_second: u64, burst: u64) -> Self {
        Self::bounded(per_second, burst, MAX_KEYS)
    }

    /// [`Governor::new`] with at most `max_keys` keys tracked.
    #[must_use]
    pub fn bounded(per_second: u64, burst: u64, max_keys: usize) -> Self {
        Self {
            per_second,
            burst: burst.max(1),
            max_keys,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn refill(&self, b: Bucket, now_ms: u64) -> Bucket {
        let elapsed = now_ms.saturating_sub(b.at_ms);
        let gained = elapsed.saturating_mul(self.per_second);
        Bucket {
            tokens_milli: b
                .tokens_milli
                .saturating_add(gained)
                .min(self.burst.saturating_mul(1000)),
            at_ms: now_ms.max(b.at_ms),
        }
    }

    /// Whether one more request of `key` is admitted at `now_ms`.
    #[must_use]
    pub fn admit(&self, key: &[u8], now_ms: u64) -> bool {
        let id = suiss_crypto::digest::sha256(key);
        let full = self.burst.saturating_mul(1000);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if !buckets.contains_key(&id) && buckets.len() >= self.max_keys {
            buckets.retain(|_, b| self.refill(*b, now_ms).tokens_milli < full);
            if buckets.len() >= self.max_keys {
                return false;
            }
        }
        let b = buckets.get(&id).copied().unwrap_or(Bucket {
            tokens_milli: full,
            at_ms: now_ms,
        });
        let b = self.refill(b, now_ms);
        let (admitted, tokens_milli) = match b.tokens_milli.checked_sub(1000) {
            Some(left) => (true, left),
            None => (false, b.tokens_milli),
        };
        buckets.insert(
            id,
            Bucket {
                tokens_milli,
                at_ms: b.at_ms,
            },
        );
        admitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // §10.6, §14.6
    #[test]
    fn a_key_gets_its_burst_then_its_rate() {
        let g = Governor::new(1, 3);
        assert!((0..3).all(|_| g.admit(b"10.0.0.1", 1_000)));
        assert!(!g.admit(b"10.0.0.1", 1_000));
        assert!(g.admit(b"10.0.0.2", 1_000));
        assert!(g.admit(b"10.0.0.1", 2_000));
        assert!(!g.admit(b"10.0.0.1", 2_000));
    }

    // §14.6
    #[test]
    fn a_full_table_fails_closed() {
        let g = Governor::bounded(1, 2, 2);
        assert!(g.admit(b"a", 0));
        assert!(g.admit(b"b", 0));
        assert!(!g.admit(b"c", 0));
        assert!(g.admit(b"c", 5_000));
    }
}
