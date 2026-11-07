//! An in-memory [`ReplayStore`] for one resource server process (§10.4.3 m.5, IDP-11 step 9,
//! TN-30): each key is kept until its window ends; a key seen again inside it is
//! [`Replay::Seen`]. The store is bounded: when it is full of live keys it answers
//! [`Replay::Unavailable`] and the proof is refused, never accepted unrecorded (MD-8). Several
//! replicas behind one audience need a shared store instead.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use access_kernel::model::TrustedTime;

use crate::resource::{Replay, ReplayStore};
use crate::transport::Clock;

/// Default capacity.
pub const DEFAULT_CAPACITY: usize = 100_000;

/// The in-memory store.
pub struct MemoryReplay<C> {
    clock: C,
    capacity: usize,
    seen: Mutex<BTreeMap<[u8; 32], TrustedTime>>,
}

impl<C> core::fmt::Debug for MemoryReplay<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryReplay")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> MemoryReplay<C> {
    /// A store holding at most `capacity` live keys.
    #[must_use]
    pub const fn new(clock: C, capacity: usize) -> Self {
        Self {
            clock,
            capacity,
            seen: Mutex::new(BTreeMap::new()),
        }
    }
}

impl<C: Clock> ReplayStore for MemoryReplay<C> {
    fn record(&self, key: &[u8; 32], until: TrustedTime) -> Replay {
        let Some(now) = self.clock.now() else {
            return Replay::Unavailable;
        };
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(&end) = seen.get(key)
            && end >= now
        {
            return Replay::Seen;
        }
        if seen.len() >= self.capacity {
            seen.retain(|_, end| *end >= now);
        }
        if seen.len() >= self.capacity {
            return Replay::Unavailable;
        }
        seen.insert(*key, until);
        Replay::Fresh
    }
}
