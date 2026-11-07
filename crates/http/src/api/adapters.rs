//! In-process adapters of the management API's ports: the rate limiter, list cursors under
//! AES-256-GCM-SIV, an in-memory idempotency store for tests, and the fail-closed adapters a
//! process serves until the real ones are wired: no read token verifies, no write is proposed.

use std::collections::HashMap;
use std::sync::Mutex;

use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::verify::cose::PublicKey;
use suiss_crypto::envelope::{Dek, Sealed, Sealer};
use suiss_crypto::secret::Secret;

use super::domain::SurfaceScope;
use super::domain::rate::{BucketKey, Quota, Take, gcra};
use super::ports::{
    Begun, CursorSeal, IdempotencyStore, Presented, Proposal, Proposals, Proposed, RateLimiter,
    ReadToken, ReadTokens, Surfaces, Unavailable,
};

/// Most buckets kept; past it the oldest-idle are forgotten, which only ever admits.
pub const MAX_BUCKETS: usize = 100_000;

/// The rate limiter of one process (TN-127): GCRA buckets and concurrency counters.
#[derive(Default)]
pub struct MemoryLimiter {
    buckets: Mutex<HashMap<BucketKey, u64>>,
    slots: Mutex<HashMap<String, u32>>,
}

impl RateLimiter for MemoryLimiter {
    fn take(&self, key: &BucketKey, quota: Quota, now_ms: u64) -> Take {
        let Ok(mut buckets) = self.buckets.lock() else {
            return Take {
                allowed: false,
                remaining: 0,
                reset_s: 1,
            };
        };
        if buckets.len() >= MAX_BUCKETS && !buckets.contains_key(key) {
            buckets.retain(|_, tat| *tat > now_ms);
        }
        let tat = buckets.get(key).copied().unwrap_or(0);
        let (next, take) = gcra(tat, now_ms, quota);
        if take.allowed {
            buckets.insert(key.clone(), next);
        }
        take
    }

    fn enter(&self, key: &str, max: u32) -> bool {
        let Ok(mut slots) = self.slots.lock() else {
            return false;
        };
        let n = slots.entry(key.to_owned()).or_insert(0);
        if *n >= max {
            return false;
        }
        *n = n.saturating_add(1);
        true
    }

    fn leave(&self, key: &str) {
        let Ok(mut slots) = self.slots.lock() else {
            return;
        };
        if let Some(n) = slots.get_mut(key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                slots.remove(key);
            }
        }
    }
}

/// List cursors sealed with AES-256-GCM-SIV under a key the process derives from the HSM, bound
/// to the list by the context (OP-65, OP-135).
pub struct SivCursors(Mutex<Sealer>);

impl SivCursors {
    /// Cursors under `key`.
    #[must_use]
    pub fn new(key: Secret<[u8; 32]>) -> Self {
        Self(Mutex::new(Sealer::new(Dek::from_secret(key), 0)))
    }
}

impl CursorSeal for SivCursors {
    fn seal(&self, context: &[u8], position: &[u8]) -> Result<String, Unavailable> {
        let mut guard = self.0.lock().map_err(|_| Unavailable)?;
        let sealed = guard.seal(context, position).map_err(|_| Unavailable)?;
        let mut out = sealed.nonce.to_vec();
        out.extend_from_slice(&sealed.ciphertext);
        Ok(b64url_encode(&out))
    }

    fn open(&self, context: &[u8], cursor: &str) -> Option<Vec<u8>> {
        if cursor.len() > 1024 {
            return None;
        }
        let bytes = b64url_decode(cursor).ok()?;
        let (nonce, ciphertext) = bytes.split_first_chunk::<12>()?;
        let sealed = Sealed {
            nonce: *nonce,
            ciphertext: ciphertext.to_vec(),
        };
        let guard = self.0.lock().ok()?;
        guard.open(context, &sealed).ok().map(|p| p.to_vec())
    }
}

/// Idempotency answers in process memory, for tests and a single node; the server keeps them
/// in PostgreSQL.
#[derive(Default)]
pub struct MemoryIdempotency(Mutex<HashMap<[u8; 32], Kept>>);

type Kept = ([u8; 32], Option<Vec<u8>>);

impl IdempotencyStore for MemoryIdempotency {
    fn begin(
        &self,
        scope: [u8; 32],
        request: [u8; 32],
        _now_ms: u64,
    ) -> impl Future<Output = Result<Begun, Unavailable>> + Send {
        let r = self
            .0
            .lock()
            .map_err(|_| Unavailable)
            .map(|mut m| match m.get(&scope) {
                Some((r, _)) if *r != request => Begun::Reused,
                Some((_, Some(a))) => Begun::Replay(a.clone()),
                Some((_, None)) => Begun::Running,
                None => {
                    m.insert(scope, (request, None));
                    Begun::Run
                }
            });
        std::future::ready(r)
    }

    fn finish(
        &self,
        scope: [u8; 32],
        request: [u8; 32],
        answer: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send {
        let r = self.0.lock().map_err(|_| Unavailable).map(|mut m| {
            if m.get(&scope)
                .is_some_and(|(r, a)| *r == request && a.is_none())
            {
                match answer {
                    Some(a) => {
                        m.insert(scope, (request, Some(a)));
                    }
                    None => {
                        m.remove(&scope);
                    }
                }
            }
        });
        std::future::ready(r)
    }
}

/// No read token verifies: every read is `401` until a verifier is wired (fail closed, MD-8).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoReadTokens;

impl ReadTokens for NoReadTokens {
    fn verify(
        &self,
        _presented: Presented<'_>,
    ) -> impl Future<Output = Result<Option<ReadToken>, Unavailable>> + Send {
        std::future::ready(Ok(None))
    }
}

/// No write is proposed: every write is `503` until the write path is wired (fail closed).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoProposals;

impl Proposals for NoProposals {
    fn propose(
        &self,
        _proposal: Proposal,
    ) -> impl Future<Output = Result<Proposed, Unavailable>> + Send {
        std::future::ready(Err(Unavailable))
    }
}

/// No surface resolves: every request is `404` until the surfaces are wired.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSurfaces;

impl Surfaces for NoSurfaces {
    fn domain(
        &self,
        _scope: &SurfaceScope,
    ) -> impl Future<Output = Result<Option<Digest>, Unavailable>> + Send {
        std::future::ready(Ok(None))
    }

    fn instance_key(
        &self,
        _domain: Digest,
        _kid: [u8; 32],
        _at_ms: u64,
    ) -> impl Future<Output = Result<Option<PublicKey>, Unavailable>> + Send {
        std::future::ready(Ok(None))
    }
}
