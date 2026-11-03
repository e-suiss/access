//! The host's clock, randomness, cores and memory budget.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::AccountError;
use crate::ports::{Clock, Entropy};

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0)
    }
}

/// The operating system's random source.
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn salt(&self) -> Result<[u8; 16], AccountError> {
        access_crypto::random::bytes::<16>().map_err(|_| AccountError::Random)
    }
}

/// Usable cores.
#[must_use]
pub fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// The cgroup v2 memory limit, when one is set (OP-146 m.4 (f)).
#[must_use]
pub fn cgroup_memory_budget() -> Option<u64> {
    let text = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    text.trim().parse().ok()
}
