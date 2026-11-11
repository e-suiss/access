//! The advisory decision cache (§9.7A.4, P45, U61, G51, OP-158 m.3 (u)). Only an advisory
//! `check` (an evaluation in `check` mode or an eligibility check, without a payload, proofs or
//! an explanation) is ever looked up or stored; the commit path never reads it (TI-5). The key is
//! a length-prefixed SHA-256 of the request's parts and the domain's `applied_pos`, so any commit
//! moves every later lookup to a new key; TTLs are the last line: 10 s for ALLOW, 1 s otherwise,
//! and never past the intent's validity. A key never seen is a miss and goes to the canonical
//! state (MD-7).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use access_kernel::combinator::{Capacity, Mode, Outcome};
use access_kernel::intent::intent_digest;
use access_kernel::model::Id;

use super::{Incoming, Response};

/// TTL of a cached ALLOW, in milliseconds (U61, §9.7A.4).
pub const POSITIVE_TTL_MS: u64 = 10_000;
/// TTL of any other cached answer, in milliseconds (U61, §9.7A.4: at most 1 s).
pub const NEGATIVE_TTL_MS: u64 = 1_000;
/// The `as_of` history window in milliseconds: an older position, time or consistency token is
/// `as-of-expired` and the reader falls back to `head` (§9.7A.2 k.3, OP-158 m.3 (u), PD).
pub const AS_OF_WINDOW_MS: u64 = 24 * 3_600 * 1_000;
/// Most entries kept; a full cache drops entries of older positions first, then refuses to store.
pub const CAPACITY: usize = 16_384;
/// Domain separation label of the key.
pub const KEY_LABEL: &[u8] = b"access/advisory-cache/v1";

/// A cache key: SHA-256 over the label and each part as `u64 BE length ‖ bytes` (P45).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key(pub [u8; 32]);

/// The key of `parts`. Two different part lists never share an encoding, so they share a key
/// only by a SHA-256 collision (P45, CVE class "cache key confusion").
#[must_use]
pub fn key(parts: &[&[u8]]) -> Key {
    let mut buf = Vec::new();
    buf.extend_from_slice(
        &u64::try_from(KEY_LABEL.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    buf.extend_from_slice(KEY_LABEL);
    for p in parts {
        buf.extend_from_slice(&u64::try_from(p.len()).unwrap_or(u64::MAX).to_be_bytes());
        buf.extend_from_slice(p);
    }
    Key(suiss_crypto::digest::sha256(&buf))
}

/// The key of an advisory request at `applied_pos`, or `None` when the request is not one the
/// cache may answer: anything but a plain `check`.
#[must_use]
pub fn request_key(inc: &Incoming, subject: Option<Id>, applied_pos: u64) -> Option<Key> {
    let req = &inc.request;
    if req.mode != Mode::Check
        || req.payload.is_some()
        || !req.proofs.is_empty()
        || req.exercise.is_some()
        || inc.explain
        || inc.status.is_some()
    {
        return None;
    }
    let intent = intent_digest(&req.intent).ok()?;
    let basis = suiss_crypto::dcbor::encode(
        &access_kernel::meta::basis_value(&req.basis),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .ok()?;
    let capacity: Vec<u8> = match req.capacity {
        Capacity::Own => vec![0],
        Capacity::For(p) => std::iter::once(1).chain(p.0).collect(),
    };
    let ais = inc
        .ais
        .as_deref()
        .map(|a| suiss_crypto::digest::sha256(a).to_vec())
        .unwrap_or_default();
    let subject = subject.map(|s| s.0.to_vec()).unwrap_or_default();
    let pos = applied_pos.to_be_bytes();
    let model = access_kernel::version::CORE.to_be_bytes();
    Some(key(&[
        &req.domain.0,
        inc.pep.as_bytes(),
        &intent.0,
        &basis,
        &capacity,
        &ais,
        &subject,
        &model,
        &pos,
    ]))
}

#[derive(Clone, Debug)]
struct Entry {
    response: Response,
    pos: u64,
    expires: u64,
}

/// What the cache has done, for tests and metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Lookups made.
    pub lookups: u64,
    /// Lookups answered.
    pub hits: u64,
    /// Answers stored.
    pub stored: u64,
}

/// The cache of one process.
#[derive(Debug, Default)]
pub struct AdvisoryCache {
    entries: Mutex<HashMap<Key, Entry>>,
    lookups: AtomicU64,
    hits: AtomicU64,
    stored: AtomicU64,
}

impl AdvisoryCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The answer kept under `key`, if it has not expired at `now`.
    pub fn get(&self, key: &Key, now: u64) -> Option<Response> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let entries = self.entries.lock().ok()?;
        let e = entries.get(key).filter(|e| now < e.expires)?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(e.response.clone())
    }

    /// Keeps `response` under `key`, given at `applied_pos` at `now`, for its TTL and never past
    /// `until` (the intent's validity end). A full cache first drops entries of positions below
    /// `applied_pos` and expired ones, and keeps nothing new when still full.
    pub fn put(&self, key: Key, applied_pos: u64, now: u64, until: u64, response: &Response) {
        let ttl = if response.decision.outcome == Outcome::Allow {
            POSITIVE_TTL_MS
        } else {
            NEGATIVE_TTL_MS
        };
        let expires = now.saturating_add(ttl).min(until.saturating_add(1));
        if expires <= now {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= CAPACITY {
            entries.retain(|_, e| e.pos >= applied_pos && e.expires > now);
            if entries.len() >= CAPACITY {
                return;
            }
        }
        entries.insert(
            key,
            Entry {
                response: response.clone(),
                pos: applied_pos,
                expires,
            },
        );
        self.stored.fetch_add(1, Ordering::Relaxed);
    }

    /// Drops every entry given below `applied_pos`: a commit made them unreachable (§9.7A.4
    /// invalidation by position).
    pub fn advance(&self, applied_pos: u64) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, e| e.pos >= applied_pos);
        }
    }

    /// What the cache has done so far.
    #[must_use]
    pub fn counts(&self) -> Counts {
        Counts {
            lookups: self.lookups.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            stored: self.stored.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests;
