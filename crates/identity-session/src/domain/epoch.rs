//! The three epochs (MD-7, TN-37, L17): no single global epoch. `session_epoch` revokes identity
//! plane sessions and tokens per subject; `key_epoch` maps to a signing key window (T20,
//! TN-12); `authz_epoch` is the authority plane's applied position (C32), wired in Stage 6.
//!
//! The node cache is a positive accelerator only (OP-21): a fresh entry that matches lets a
//! check pass without the primary; a cached epoch above the presented one denies at any age,
//! because epochs only grow; everything else asks the primary, and a primary that cannot
//! answer denies. "This node never saw the subject" is never "valid" (MD-7, G49).

use std::collections::HashMap;

/// A subject's identity plane revocation counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionEpoch(pub i64);

/// A realm signing key window (T20, TN-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyEpoch(pub u32);

/// The authority plane's applied position that replaces `authz_epoch` (C32).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthzEpoch(pub u64);

/// The answer of an epoch check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochCheck {
    /// The presented epoch is current.
    Current,
    /// The subject's epoch moved past it.
    Revoked,
    /// No fresh answer: the caller asks the primary.
    AskPrimary,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    epoch: i64,
    verified_ms: u64,
}

/// The node-local tier of the epoch cache.
#[derive(Debug, Default)]
pub struct EpochCache {
    entries: HashMap<[u8; 16], Entry>,
    max_staleness_ms: u64,
    cursor_ms: i64,
}

impl EpochCache {
    /// A cache whose positive answers are at most `max_staleness_ms` old (the poll interval
    /// plus margin; OP-21: 100-250 ms).
    #[must_use]
    pub fn new(max_staleness_ms: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_staleness_ms,
            cursor_ms: 0,
        }
    }

    /// Checks `presented` for `subject` at `now_ms`.
    #[must_use]
    pub fn check(&self, subject: &[u8; 16], presented: i64, now_ms: u64) -> EpochCheck {
        match self.entries.get(subject) {
            Some(e) if e.epoch > presented => EpochCheck::Revoked,
            Some(e)
                if e.epoch == presented
                    && now_ms.saturating_sub(e.verified_ms) <= self.max_staleness_ms =>
            {
                EpochCheck::Current
            }
            _ => EpochCheck::AskPrimary,
        }
    }

    /// Records an answer from the primary or the poll at `now_ms`. An entry never goes back.
    pub fn observe(&mut self, subject: [u8; 16], epoch: i64, now_ms: u64) {
        let e = self.entries.entry(subject).or_insert(Entry {
            epoch,
            verified_ms: now_ms,
        });
        if epoch >= e.epoch {
            e.epoch = epoch;
            e.verified_ms = now_ms;
        }
    }

    /// The poll cursor (database clock, Unix milliseconds).
    #[must_use]
    pub const fn cursor_ms(&self) -> i64 {
        self.cursor_ms
    }

    /// Advances the poll cursor.
    pub fn advance(&mut self, at_ms: i64) {
        self.cursor_ms = self.cursor_ms.max(at_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: [u8; 16] = [1; 16];

    // MD-7, G49, OPI-3
    #[test]
    fn a_never_seen_subject_asks_the_primary() {
        let c = EpochCache::new(250);
        assert_eq!(c.check(&S, 0, 10), EpochCheck::AskPrimary);
    }

    // OP-21
    #[test]
    fn fresh_hits_pass_stale_hits_ask_and_moves_deny() {
        let mut c = EpochCache::new(250);
        c.observe(S, 3, 1_000);
        assert_eq!(c.check(&S, 3, 1_200), EpochCheck::Current);
        assert_eq!(c.check(&S, 3, 1_251), EpochCheck::AskPrimary);
        assert_eq!(c.check(&S, 2, 9_999), EpochCheck::Revoked);
        assert_eq!(c.check(&S, 4, 1_100), EpochCheck::AskPrimary);
        c.observe(S, 2, 1_300);
        assert_eq!(c.check(&S, 3, 1_100), EpochCheck::Current);
        c.observe(S, 3, 2_000);
        assert_eq!(c.check(&S, 3, 2_100), EpochCheck::Current);
        c.advance(50);
        c.advance(40);
        assert_eq!(c.cursor_ms(), 50);
    }
}
