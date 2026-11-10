//! The decision cache of forward-auth (IDP-30 (1), OP-156 m.3 (l)): keyed by session,
//! application, method and path pattern; an entry lives at most min(ValidityContract horizon,
//! 30 s); the doorbell or a revocation empties the entries of its domain at once. A miss always
//! asks; nothing here ever answers for Access when it is unreachable.

use std::collections::HashMap;
use std::sync::Mutex;

use access_kernel::digest::Digest;

/// The longest any entry lives, ms (OP-156 m.3 (l)).
pub const MAX_TTL_MS: u64 = 30_000;

/// Most entries held; past it a new decision is not cached.
pub const MAX_ENTRIES: usize = 100_000;

/// The lifetime of a decision whose authority holds until `horizon`, asked at `now`: at most
/// [`MAX_TTL_MS`], never past the horizon.
#[must_use]
pub fn ttl_ms(now: u64, horizon: u64) -> u64 {
    horizon.saturating_sub(now).min(MAX_TTL_MS)
}

/// What a decision is cached under.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    /// The digest of the proxy session's cookie.
    pub session: [u8; 32],
    /// The registration.
    pub app: String,
    /// The forwarded method.
    pub method: String,
    /// The path pattern the request fell under.
    pub pattern: String,
}

/// A cached decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry<T> {
    /// What was decided.
    pub decided: T,
    /// The domain it was decided in.
    pub domain: Digest,
    /// The domain's head position it was decided at.
    pub head: u64,
    /// When it stops being used, ms.
    pub until_ms: u64,
}

/// The cache of one process.
pub struct Cache<T> {
    entries: Mutex<HashMap<Key, Entry<T>>>,
}

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<T: Clone> Cache<T> {
    /// The live entry for `key` at `now`; an expired one is dropped. A poisoned lock is a miss.
    pub fn get(&self, key: &Key, now: u64) -> Option<Entry<T>> {
        let mut map = self.entries.lock().ok()?;
        match map.get(key) {
            Some(e) if now < e.until_ms => Some(e.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    /// Keeps `entry` under `key` at `now`, unless it is already over or the cache is full.
    pub fn put(&self, key: Key, entry: Entry<T>, now: u64) {
        if entry.until_ms <= now {
            return;
        }
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        if map.len() >= MAX_ENTRIES {
            map.retain(|_, e| now < e.until_ms);
        }
        if map.len() < MAX_ENTRIES {
            map.insert(key, entry);
        }
    }

    /// The domains entries are held for, with the oldest head each was decided at.
    pub fn domains(&self) -> Vec<(Digest, u64)> {
        let Ok(map) = self.entries.lock() else {
            return Vec::new();
        };
        let mut out: Vec<(Digest, u64)> = Vec::new();
        for e in map.values() {
            match out.iter_mut().find(|(d, _)| *d == e.domain) {
                Some((_, h)) => *h = (*h).min(e.head),
                None => out.push((e.domain, e.head)),
            }
        }
        out
    }

    /// Drops every entry of `domain` decided before `head`; how many went.
    pub fn flush_domain(&self, domain: &Digest, head: u64) -> usize {
        self.flush(|e| e.domain == *domain && e.head < head)
    }

    /// Drops every entry; how many went. A poisoned lock is recovered and emptied.
    pub fn flush_all(&self) -> usize {
        match self.entries.lock() {
            Ok(mut map) => {
                let n = map.len();
                map.clear();
                n
            }
            Err(poisoned) => {
                let mut map = poisoned.into_inner();
                let n = map.len();
                map.clear();
                n
            }
        }
    }

    /// Drops every entry of the session whose cookie digest is `session`; how many went.
    pub fn flush_session(&self, session: &[u8; 32]) -> usize {
        let Ok(mut map) = self.entries.lock() else {
            return self.flush_all();
        };
        let before = map.len();
        map.retain(|k, _| k.session != *session);
        before.saturating_sub(map.len())
    }

    fn flush(&self, gone: impl Fn(&Entry<T>) -> bool) -> usize {
        let Ok(mut map) = self.entries.lock() else {
            return self.flush_all();
        };
        let before = map.len();
        map.retain(|_, e| !gone(e));
        before.saturating_sub(map.len())
    }

    /// How many entries are held.
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |m| m.len())
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test code")]

    use super::*;

    fn key(s: u8) -> Key {
        Key {
            session: [s; 32],
            app: String::from("wiki"),
            method: String::from("GET"),
            pattern: String::from("/"),
        }
    }

    fn entry(domain: u8, head: u64, until_ms: u64) -> Entry<bool> {
        Entry {
            decided: true,
            domain: Digest([domain; 32]),
            head,
            until_ms,
        }
    }

    // IDP-30, OP-156 m.3 (l)
    #[test]
    fn an_entry_lives_at_most_thirty_seconds_and_never_past_the_horizon() {
        assert_eq!(ttl_ms(1_000, 1_000_000), MAX_TTL_MS);
        assert_eq!(ttl_ms(1_000, 6_000), 5_000);
        assert_eq!(ttl_ms(9_000, 6_000), 0);
        let c = Cache::default();
        c.put(key(1), entry(1, 5, 1_000 + ttl_ms(1_000, 1_000_000)), 1_000);
        assert!(c.get(&key(1), 30_999).is_some());
        assert!(c.get(&key(1), 31_000).is_none());
        assert!(c.is_empty());
        c.put(key(2), entry(1, 5, 1_000 + ttl_ms(1_000, 1_000)), 1_000);
        assert!(c.is_empty());
    }

    // IDP-30, OP-156 m.3 (l)
    #[test]
    fn a_newer_head_of_its_domain_empties_it_at_once() {
        let c = Cache::default();
        c.put(key(1), entry(1, 5, 30_000), 0);
        c.put(key(2), entry(2, 5, 30_000), 0);
        assert_eq!(c.flush_domain(&Digest([1; 32]), 5), 0);
        assert_eq!(c.flush_domain(&Digest([1; 32]), 6), 1);
        assert!(c.get(&key(1), 1).is_none());
        assert!(c.get(&key(2), 1).is_some());
        assert_eq!(c.domains(), vec![(Digest([2; 32]), 5)]);
        assert_eq!(c.flush_session(&[2; 32]), 1);
        assert!(c.is_empty());
    }
}
