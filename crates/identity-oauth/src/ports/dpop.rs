//! What DPoP checks need from outside (OP-63): trusted time and the replay cache.

use std::future::Future;

/// The replay cache could not answer; the proof is rejected (TN-30, MD-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("replay cache unavailable")]
pub struct CacheUnavailable;

/// Trusted time could not be read; nothing is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("clock unavailable")]
pub struct ClockUnavailable;

/// The realm's replay cache of proof keys (TN-30): shared by every node of the cell and
/// synchronous within it.
pub trait ReplayCache {
    /// Records `key` for a proof whose `iat` falls on `day` (days since the Unix epoch);
    /// `true` the first time, `false` for a replay.
    fn first_use(
        &self,
        day: u32,
        key: [u8; 32],
    ) -> impl Future<Output = Result<bool, CacheUnavailable>> + Send;
}

/// Trusted time (OP-63): never read from the system clock directly.
pub trait Clock {
    /// Unix milliseconds.
    ///
    /// # Errors
    /// [`ClockUnavailable`].
    fn now(&self) -> Result<u64, ClockUnavailable>;
}
