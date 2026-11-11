//! The Federation Verifier's caches and read federation (§16.5 T29, T30, §9.15A.5, §5.13,
//! INV-21, TI-RT5, OP-158 m.3 (u)).
//!
//! - Foreign Domain Metadata is a derived cache. Its freshness is measured by an independent
//!   witness's cosign within Δ, or, without one, by when this domain verified it, at most one
//!   hour; the document's own `iat` is never the proof.
//! - The hub cache holds viewer-scoped read snapshots: served only to the viewer it was read for,
//!   each row with its `as_of`, never for a consequential read (that is a recorded Exercise), and
//!   never a projection or a source of authority. There is no global registry.
//! - A foreign domain's record is read with its checkpoint and an RFC 9162 inclusion proof.
//! - A target domain reconciles what it drew from a home domain's offline slice: a draw past the
//!   slice is refused, and what it reports home is what it drew.

use std::collections::HashMap;
use std::sync::Mutex;

use access_kernel::digest::Digest;
use access_kernel::model::Id;

/// The freshness ceiling of foreign metadata without an independent witness cosign (T29,
/// TI-RT5).
pub const UNWITNESSED_MS: u64 = access_kernel::foreign::FRESHNESS_MS;

#[derive(Clone, Debug)]
struct Foreign {
    metadata: Vec<u8>,
    verified_at: u64,
    cosigned_at: Option<u64>,
}

/// Verified foreign Domain Metadata by `DomainID` (T29).
#[derive(Debug, Default)]
pub struct ForeignMetadata {
    entries: Mutex<HashMap<Digest, Foreign>>,
}

impl ForeignMetadata {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps `metadata` of `domain`, verified under its pinned binding keys at `now`.
    pub fn verified(&self, domain: Digest, metadata: Vec<u8>, now: u64) {
        if let Ok(mut e) = self.entries.lock() {
            e.insert(
                domain,
                Foreign {
                    metadata,
                    verified_at: now,
                    cosigned_at: None,
                },
            );
        }
    }

    /// Notes a cosign at `at` by a witness independent of the pinned set over a checkpoint that
    /// commits to the kept metadata. A cosign by a witness that is not independent proves
    /// nothing here and is ignored (TI-RT5).
    pub fn cosigned(&self, domain: Digest, at: u64, independent: bool) {
        if !independent {
            return;
        }
        if let Ok(mut e) = self.entries.lock()
            && let Some(f) = e.get_mut(&domain)
        {
            f.cosigned_at = Some(f.cosigned_at.map_or(at, |c| c.max(at)));
        }
    }

    /// The kept metadata of `domain` when it is fresh at `now`: an independent cosign at most
    /// `delta_ms` old, else verified at most [`UNWITNESSED_MS`] ago. `None` sends the verifier to
    /// fetch it again.
    #[must_use]
    pub fn fresh(&self, domain: &Digest, now: u64, delta_ms: u64) -> Option<Vec<u8>> {
        let e = self.entries.lock().ok()?;
        let f = e.get(domain)?;
        let witnessed = f
            .cosigned_at
            .is_some_and(|c| now.saturating_sub(c) <= delta_ms);
        let recent = now.saturating_sub(f.verified_at) <= UNWITNESSED_MS;
        (witnessed || recent).then(|| f.metadata.clone())
    }
}

/// One row of a hub snapshot with the position it was read at (T30: `as_of` per row).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row<T> {
    /// What was read.
    pub value: T,
    /// The position of the domain it was read at.
    pub as_of: u64,
}

/// What a hub read is for (T30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// Showing the viewer its own authority: the cache may answer.
    View,
    /// A consequential read or export: a recorded `access.read` / `access.audit.export`
    /// Exercise, never the cache.
    Consequential,
}

/// One kept snapshot: its rows and when they were read.
type Snapshot<T> = (Vec<Row<T>>, u64);

/// Viewer-scoped hub snapshots, at most one per (viewer, domain) (T30, SI-15).
#[derive(Debug)]
pub struct HubCache<T> {
    entries: Mutex<HashMap<(Id, Digest), Snapshot<T>>>,
}

impl<T> Default for HubCache<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<T: Clone> HubCache<T> {
    /// Keeps `rows` read for `viewer` in `domain` at `now`.
    pub fn keep(&self, viewer: Id, domain: Digest, rows: Vec<Row<T>>, now: u64) {
        if let Ok(mut e) = self.entries.lock() {
            e.insert((viewer, domain), (rows, now));
        }
    }

    /// The snapshot `viewer` read in `domain` no more than `max_age_ms` ago, for a [`Read::View`]
    /// only. Another viewer's snapshot is never returned.
    #[must_use]
    pub fn get(
        &self,
        viewer: &Id,
        domain: &Digest,
        read: Read,
        now: u64,
        max_age_ms: u64,
    ) -> Option<Vec<Row<T>>> {
        if read == Read::Consequential {
            return None;
        }
        let e = self.entries.lock().ok()?;
        let (rows, at) = e.get(&(*viewer, *domain))?;
        (now.saturating_sub(*at) <= max_age_ms).then(|| rows.clone())
    }
}

/// Why a foreign record is not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The inclusion proof does not put the record at its position in the checkpoint.
    #[error("record not in the checkpoint")]
    NotIncluded,
}

/// A foreign record (its canonical bytes) at `position` (1-based) read against a checkpoint of
/// `size` records with `root` that the caller verified (signature and cosigns), with its RFC 9162
/// inclusion `path` (§9.15A.5).
///
/// # Errors
/// [`ReadError::NotIncluded`].
pub fn read_record<'a>(
    record: &'a [u8],
    position: u64,
    (size, root): (u64, &[u8; 32]),
    path: &[[u8; 32]],
) -> Result<&'a [u8], ReadError> {
    let index = position.checked_sub(1).ok_or(ReadError::NotIncluded)?;
    let leaf = suiss_crypto::digest::leaf_hash(record);
    suiss_crypto::digest::verify_inclusion(index, size, &leaf, path, root)
        .map_err(|_| ReadError::NotIncluded)?;
    Ok(record)
}

/// A target domain's account of one home domain's offline slice (§5.13, INV-21).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Slice {
    /// What the home domain's PAP allows here.
    pub allowance: u64,
    /// What this domain has drawn.
    pub drawn: u64,
    /// What the home domain has acknowledged of this domain's reports.
    pub acknowledged: u64,
}

/// Why a draw is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SliceError {
    /// The draw would pass the slice (INV-21).
    #[error("slice exhausted")]
    Exhausted,
}

impl Slice {
    /// Draws `amount`, never past the allowance (INV-21).
    ///
    /// # Errors
    /// [`SliceError::Exhausted`]; nothing is drawn.
    pub fn draw(&mut self, amount: u64) -> Result<u64, SliceError> {
        let after = self
            .drawn
            .checked_add(amount)
            .filter(|a| *a <= self.allowance)
            .ok_or(SliceError::Exhausted)?;
        self.drawn = after;
        Ok(self.allowance.saturating_sub(after))
    }

    /// What is still to report home: drawn and not yet acknowledged.
    #[must_use]
    pub const fn unreported(&self) -> u64 {
        self.drawn.saturating_sub(self.acknowledged)
    }

    /// Takes in the home domain's acknowledgement of `upto` drawn units; an acknowledgement
    /// beyond what was drawn here is not taken (the home domain cannot count more than was
    /// drawn).
    pub fn acknowledge(&mut self, upto: u64) {
        self.acknowledged = self.acknowledged.max(upto.min(self.drawn));
    }
}

#[cfg(test)]
mod tests;
