//! `cacheScope` and `ttlMs` of list results (SEP-2549; §11.5.4, RS-M16 to RS-M18, AG-12,
//! AGI-5, U63, OP-154 m.3 (v)). A list is a viewer-scoped disclosure: it is `public` only when
//! every candidate's visibility came from a Public Grant and nothing about the viewer, and
//! `private` otherwise and whenever anything was unknown. A private result is cached under
//! `(Instance, capacity, aud, applied_pos)` and the token's projection; a cached item is never
//! the authority of a call.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use std::sync::{Mutex, PoisonError};

use access_kernel::digest::Digest;
use access_kernel::model::TrustedTime;
use suiss_crypto::digest::context_digest;

use crate::resource::TokenCapacity;

/// Digest context of a private cache key.
pub const KEY_CONTEXT: &str = "access/mcp-list-cache/v1";

/// The two values SEP-2549 allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheScope {
    /// Any client or shared cache may serve the result to anyone.
    Public,
    /// Reusable only for the same authorization context.
    Private,
}

impl CacheScope {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// Where one candidate's visibility came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// An anonymous check under a Public Grant: the same for every viewer.
    Public,
    /// The viewer's token or decision: another viewer may see another list.
    Viewer,
    /// The check did not answer; the item is hidden and the list is private.
    Unknown,
}

/// AG-12: `public` only when every candidate is [`Visibility::Public`]; anything else, an
/// unknown included, is `private`. An empty catalogue is public.
#[must_use]
pub fn scope_of(candidates: impl IntoIterator<Item = Visibility>) -> CacheScope {
    if candidates.into_iter().all(|v| v == Visibility::Public) {
        CacheScope::Public
    } else {
        CacheScope::Private
    }
}

/// The authorization context a private result belongs to (§9.7A.4 adapted, AG-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheKey {
    /// The holder Instance's key thumbprint.
    pub instance: [u8; 32],
    /// The capacity the token projects.
    pub capacity: TokenCapacity,
    /// This server.
    pub audience: String,
    /// The position the viewer's authority was read at.
    pub applied_pos: u64,
    /// The `projection.issue` Exercise of the token: two tokens of one Instance may project
    /// different bounds, so they never share a result.
    pub projection: Digest,
}

impl CacheKey {
    /// The fixed-length key.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut b = Vec::with_capacity(128);
        b.extend_from_slice(&self.instance);
        match &self.capacity {
            TokenCapacity::Own { subject } => {
                b.extend_from_slice(b"own\0");
                b.extend_from_slice(subject.as_bytes());
            }
            TokenCapacity::For { principal, actors } => {
                b.extend_from_slice(b"for\0");
                b.extend_from_slice(principal.as_bytes());
                for a in actors {
                    b.push(0);
                    b.extend_from_slice(a.sub.as_bytes());
                    b.push(0);
                    b.extend_from_slice(a.iss.as_deref().unwrap_or("").as_bytes());
                }
            }
        }
        b.push(0);
        b.extend_from_slice(self.audience.as_bytes());
        b.push(0);
        b.extend_from_slice(&self.applied_pos.to_be_bytes());
        b.extend_from_slice(&self.projection.0);
        context_digest(KEY_CONTEXT, &b)
    }
}

/// Which slot a result goes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    /// A public result of this audience.
    Public(String),
    /// A private result of this context.
    Private(CacheKey),
}

impl Slot {
    fn key(&self) -> [u8; 32] {
        match self {
            Self::Public(aud) => context_digest(KEY_CONTEXT, aud.as_bytes()).0,
            Self::Private(k) => k.digest().0,
        }
    }
}

/// A bounded in-memory cache of rendered list results. A full cache stores nothing more; it
/// never evicts one context into another.
pub struct ListCache {
    capacity: usize,
    entries: Mutex<BTreeMap<[u8; 32], (TrustedTime, CacheScope, String)>>,
}

impl core::fmt::Debug for ListCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ListCache")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl ListCache {
    /// A cache of at most `capacity` results.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    /// The live result of `slot`, with its scope.
    #[must_use]
    pub fn get(&self, slot: &Slot, now: TrustedTime) -> Option<(CacheScope, String)> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(&slot.key())
            .filter(|(until, _, _)| *until > now)
            .map(|(_, scope, body)| (*scope, body.clone()))
    }

    /// Stores `body` under `slot` from `now` until `until`. A public slot only takes a public
    /// result.
    pub fn put(
        &self,
        slot: &Slot,
        scope: CacheScope,
        body: String,
        (now, until): (TrustedTime, TrustedTime),
    ) {
        if matches!(slot, Slot::Public(_)) && scope != CacheScope::Public || until <= now {
            return;
        }
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.capacity {
            entries.retain(|_, (u, _, _)| *u > now);
        }
        if entries.len() < self.capacity {
            entries.insert(slot.key(), (until, scope, body));
        }
    }
}
