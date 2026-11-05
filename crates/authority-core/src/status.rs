//! Token Status Lists (OP-150 m.3 (a), (s), §11.20, T24): a projection family's entry, and the
//! publisher that signs each list of a domain with the position it reflects.
//!
//! A family takes the next entry of the domain's newest list when it opens; its entry is set
//! when the family is revoked, so a list at a position is read from the families revoked at or
//! before it. A publication's `iat` is that position's `recorded_at`, never the time of
//! signing: a publisher never signs old content with a fresh `iat` (G43). A list is an
//! information channel, never the safety mechanism (§9.12.4, PI-9).

pub mod adapters;

use std::future::Future;

use access_kernel::digest::Digest;
use access_kernel::status::ListToken;
use access_kernel::verify::cose::parse_sign1;
use access_store::status::{List, Publication, Snapshot};

use crate::CoreError;

/// Entries of one list (PD): 2^20 one-bit entries, 128 KiB inflated.
pub const CAPACITY: u64 = 1 << 20;

/// How long a verifier may use a list before fetching it again, seconds (the CWT `ttl`, PD).
pub const TTL_S: u64 = 300;

/// The longest a list goes without a new publication while its domain's head moves, so its
/// `iat` follows the heartbeat checkpoints (T16, PD).
pub const HEARTBEAT_MS: u64 = 300_000;

/// The path of a list under the API base, without the list number.
pub const PATH: &str = "/access/v1/status-lists/";

/// A `DomainID` in its text form (L0-ENC-20).
#[must_use]
pub fn domain_text(domain: &Digest) -> String {
    format!("sha-256:{}", access_kernel::json::b64url_encode(&domain.0))
}

/// The URI of list `list_no` of `domain` under `api_base`: the address it is served at, and
/// the `sub` of its token.
#[must_use]
pub fn list_uri(api_base: &str, domain: &Digest, list_no: u64) -> String {
    format!(
        "{}{PATH}{list_no}?domain={}",
        api_base.trim_end_matches('/'),
        domain_text(domain)
    )
}

/// Why a list cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// An entry lies past the list's capacity, or the capacity has no byte size.
    #[error("status-entry")]
    Entry,
    /// The token payload does not encode.
    #[error("status-encode")]
    Encode,
}

/// The inflated bits of a list of `capacity` entries with `revoked` set (L2-STL-3): entry `i`
/// is bit `i mod 8` of byte `i div 8`, least significant first.
///
/// # Errors
/// [`BuildError::Entry`].
pub fn bits(capacity: u64, revoked: &[u64]) -> Result<Vec<u8>, BuildError> {
    let len = usize::try_from(capacity.div_ceil(8)).map_err(|_| BuildError::Entry)?;
    let mut out = vec![0_u8; len.max(1)];
    for &idx in revoked {
        if idx >= capacity {
            return Err(BuildError::Entry);
        }
        let byte = usize::try_from(idx / 8).map_err(|_| BuildError::Entry)?;
        let bit = u32::try_from(idx % 8).map_err(|_| BuildError::Entry)?;
        let b = out.get_mut(byte).ok_or(BuildError::Entry)?;
        *b |= 1_u8.checked_shl(bit).ok_or(BuildError::Entry)?;
    }
    Ok(out)
}

/// The token payload of `list` as `snapshot` shows it (OP-150 m.6 (d)): `iat` is the
/// snapshot position's `recorded_at` in seconds, `as_of` is that position (OP-150 m.3 (l)).
///
/// # Errors
/// [`BuildError`].
pub fn token(list: &List, snapshot: &Snapshot) -> Result<ListToken, BuildError> {
    let raw = bits(list.capacity, &snapshot.revoked)?;
    Ok(ListToken {
        uri: list.uri.clone(),
        iat: snapshot.recorded_at / 1_000,
        exp: None,
        ttl: Some(TTL_S),
        lst: miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6),
        aggregation_uri: None,
        as_of: snapshot.pos,
    })
}

/// The number of set entries of a signed list, read without verifying it: the publisher's own
/// last publication, to see whether the list changed.
#[must_use]
pub fn set_entries(signed: &[u8]) -> Option<u64> {
    let payload = parse_sign1(signed).ok()?.payload?;
    let t = ListToken::from_bytes(&payload).ok()?;
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&t.lst, 1 << 22).ok()?;
    Some(raw.iter().map(|b| u64::from(b.count_ones())).sum())
}

/// What the publisher does with one list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Sign and record it as publication `seq`.
    Publish {
        /// The publication number.
        seq: u64,
    },
    /// Nothing to publish.
    Skip(Skip),
}

/// Why a list is not published now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// The last publication already reflects this position or a later one: a list never goes
    /// back, and old content is never signed again with a fresh `iat` (G43, T24).
    NotNewer,
    /// Nothing changed and the last publication is younger than [`HEARTBEAT_MS`].
    Unchanged,
}

/// Whether to publish `snapshot` after `last`, at `now` (T24, G43): a list whose entries
/// changed is published at once (a revocation first); one that did not is published again only
/// when its domain's head moved and the last publication is [`HEARTBEAT_MS`] old.
#[must_use]
pub fn plan(last: Option<(&Publication, Option<u64>)>, snapshot: &Snapshot, now: u64) -> Plan {
    let Some((last, set)) = last else {
        return Plan::Publish { seq: 0 };
    };
    if snapshot.pos <= last.applied_pos {
        return Plan::Skip(Skip::NotNewer);
    }
    let Some(seq) = last.seq.checked_add(1) else {
        return Plan::Skip(Skip::NotNewer);
    };
    let changed = set != u64::try_from(snapshot.revoked.len()).ok();
    let aged = now.saturating_sub(last.iat_ms) >= HEARTBEAT_MS;
    if changed || aged {
        Plan::Publish { seq }
    } else {
        Plan::Skip(Skip::Unchanged)
    }
}

/// A domain's lists, publications and the snapshot a list is built from.
pub trait Lists: Send + Sync {
    /// The lists of `domain`.
    fn lists(&self, domain: Digest) -> impl Future<Output = Result<Vec<List>, CoreError>> + Send;
    /// The list at `uri` at the domain's head.
    fn snapshot(
        &self,
        domain: Digest,
        uri: &str,
    ) -> impl Future<Output = Result<Option<Snapshot>, CoreError>> + Send;
    /// The latest publication of the list at `uri`.
    fn latest(
        &self,
        domain: Digest,
        uri: &str,
    ) -> impl Future<Output = Result<Option<Publication>, CoreError>> + Send;
    /// Records a publication: `true` the first time.
    fn record(
        &self,
        domain: Digest,
        p: &Publication,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send;
}

/// Signs a list token under the domain's `status-list` key.
pub trait ListSigner: Send + Sync {
    /// The `COSE_Sign1` of `payload` signed at `at` and the binding-signed excerpt of its key,
    /// or the signer's stable reason.
    fn sign(
        &self,
        domain: Digest,
        payload: Vec<u8>,
        at: u64,
    ) -> impl Future<Output = Result<(Vec<u8>, Vec<u8>), &'static str>> + Send;
}

/// One list the publisher signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// The list.
    pub uri: String,
    /// Its publication number.
    pub seq: u64,
    /// The position it reflects.
    pub as_of: u64,
}

/// The publisher of a domain's lists.
pub struct Publisher<L, S> {
    lists: L,
    signer: S,
}

impl<L: Lists, S: ListSigner> Publisher<L, S> {
    /// A publisher over `lists`, signing with `signer`.
    pub const fn new(lists: L, signer: S) -> Self {
        Self { lists, signer }
    }

    /// Publishes every list of `domain` that [`plan`] says to, at `now`. Without a snapshot
    /// nothing is published: a list never claims a position it was not read at.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the lists cannot be read, built or signed; lists
    /// published before the failure stay published.
    pub async fn publish(&self, domain: Digest, now: u64) -> Result<Vec<Published>, CoreError> {
        let mut out = Vec::new();
        for list in self.lists.lists(domain).await? {
            if let Some(p) = self.publish_list(domain, &list, now).await? {
                out.push(p);
            }
        }
        Ok(out)
    }

    async fn publish_list(
        &self,
        domain: Digest,
        list: &List,
        now: u64,
    ) -> Result<Option<Published>, CoreError> {
        let Some(snapshot) = self.lists.snapshot(domain, &list.uri).await? else {
            return Err(CoreError::Unavailable("status-head"));
        };
        let previous = self.lists.latest(domain, &list.uri).await?;
        let set = previous.as_ref().and_then(|p| set_entries(&p.token));
        let Plan::Publish { seq } = plan(previous.as_ref().map(|p| (p, set)), &snapshot, now)
        else {
            return Ok(None);
        };
        let payload = token(list, &snapshot)
            .map_err(|_| CoreError::Unavailable("status-build"))?
            .to_bytes()
            .map_err(|_| CoreError::Unavailable("status-build"))?;
        let (signed, excerpt) = self
            .signer
            .sign(domain, payload, now)
            .await
            .map_err(CoreError::Unavailable)?;
        let p = Publication {
            uri: list.uri.clone(),
            seq,
            applied_pos: snapshot.pos,
            iat_ms: snapshot.recorded_at,
            entries: list.capacity,
            token: signed,
            excerpt: Some(excerpt),
        };
        self.lists.record(domain, &p).await?;
        Ok(Some(Published {
            uri: p.uri,
            seq,
            as_of: snapshot.pos,
        }))
    }
}

#[cfg(test)]
mod tests;
