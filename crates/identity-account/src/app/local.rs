//! Layer A (OP-35, OP-146 m.5 (d)): an in-process GCRA per network, the cheap
//! identity-independent gate before any database or hash work (TN-83). It only tightens the
//! network dimension; account limits live in layer B. It never fails open (MD-8).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::domain::gcra::{Gcra, GcraDecision};
use crate::domain::login::network;

/// Default layer A rate per network (PD): bursts of 20, one per 500 ms.
pub const DEFAULT_RATE: Gcra = Gcra {
    interval_ms: 500,
    burst: 20,
};

/// Default number of networks tracked (PD).
pub const DEFAULT_CAPACITY: usize = 100_000;

/// The per-network limiter.
pub struct LocalLimiter {
    rate: Gcra,
    capacity: usize,
    tats: Mutex<HashMap<Vec<u8>, u64>>,
}

impl LocalLimiter {
    /// A limiter tracking up to `capacity` networks.
    #[must_use]
    pub fn new(rate: Gcra, capacity: usize) -> Self {
        Self {
            rate,
            capacity,
            tats: Mutex::new(HashMap::new()),
        }
    }

    /// Admits one attempt from `ip` at `now_ms`, or the wait in milliseconds. A full table
    /// that cannot be pruned, or a poisoned lock, refuses.
    ///
    /// # Errors
    /// The wait.
    pub fn check(&self, ip: IpAddr, now_ms: u64) -> Result<(), u64> {
        let refuse = self.rate.interval_ms.max(1);
        let Ok(mut tats) = self.tats.lock() else {
            return Err(refuse);
        };
        let key = network(ip);
        if !tats.contains_key(&key) && tats.len() >= self.capacity {
            tats.retain(|_, tat| *tat > now_ms);
            if tats.len() >= self.capacity {
                return Err(refuse);
            }
        }
        let tat = tats.get(&key).copied().unwrap_or(0);
        match self.rate.check(tat, now_ms) {
            GcraDecision::Allow { tat_ms } => {
                tats.insert(key, tat_ms);
                Ok(())
            }
            GcraDecision::Deny { retry_after_ms } => Err(retry_after_ms),
        }
    }
}

impl Default for LocalLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RATE, DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    // OP-35, SA-30, MD-8
    #[test]
    fn per_network_and_closed_when_full() {
        let l = LocalLimiter::new(
            Gcra {
                interval_ms: 1000,
                burst: 2,
            },
            1,
        );
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        assert!(l.check(a, 10_000).is_ok());
        assert!(l.check(a, 10_000).is_ok());
        assert_eq!(l.check(a, 10_000), Err(1000));
        assert_eq!(l.check(b, 10_000), Err(1000));
        assert!(l.check(b, 100_000).is_ok());
    }
}
