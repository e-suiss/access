//! Domain Metadata the verifier holds (§9.10 steps 1 and 6, CR-58, TI-RT5): binding-signed
//! metadata verified against the pinned binding keys, and its freshness, measured by an
//! independent witness's cosignature over the domain's checkpoint, never by the metadata's own
//! `issued_at`.

use access_kernel::model::TrustedTime;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::KeySet;
use access_kernel::verify::key_scope::{self, DomainMetadata, KeyScopeError};
use suiss_crypto::note::{self, NoteError, Verifier};

use crate::caps::METADATA_FRESHNESS_MS;

/// Why a witness checkpoint does not refresh the metadata.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessError {
    /// The checkpoint note is rejected (L2-CKP-1 to L2-CKP-4).
    #[error("checkpoint: {0}")]
    Checkpoint(NoteError),
    /// No witness of the verifier's set cosigned it.
    #[error("unwitnessed")]
    Unwitnessed,
    /// The cosignature time does not fit in milliseconds.
    #[error("time out of range")]
    Range,
}

/// Verified Domain Metadata and the last witnessed time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataView {
    metadata: DomainMetadata,
    witnessed: Option<TrustedTime>,
}

impl MetadataView {
    /// Metadata the caller verified itself; it has no witness yet, so it is not fresh.
    #[must_use]
    pub const fn new(metadata: DomainMetadata) -> Self {
        Self {
            metadata,
            witnessed: None,
        }
    }

    /// Verifies binding-signed Domain Metadata against the pinned binding key set (CR-58).
    ///
    /// # Errors
    /// [`KeyScopeError`].
    pub fn verify(signed: &[u8], trusted: &KeySet) -> Result<Self, KeyScopeError> {
        key_scope::verify_metadata(&PureBackend, signed, trusted).map(Self::new)
    }

    /// The metadata.
    #[must_use]
    pub const fn metadata(&self) -> &DomainMetadata {
        &self.metadata
    }

    /// The latest witness cosignature time accepted, Unix milliseconds.
    #[must_use]
    pub const fn witnessed(&self) -> Option<TrustedTime> {
        self.witnessed
    }

    /// Accepts a signed checkpoint of the domain log at `origin` (L2-CKP-3, L2-CKP-4) and
    /// takes the newest cosignature of a witness in `witnesses` as the metadata's freshness
    /// (TI-RT5). The log's own signature is required but does not count as a witness.
    ///
    /// # Errors
    /// [`WitnessError`]; the previous freshness is kept.
    pub fn witness(
        &mut self,
        checkpoint: &str,
        origin: &str,
        log: &Verifier,
        witnesses: &[Verifier],
    ) -> Result<TrustedTime, WitnessError> {
        let (_, accepted) =
            note::verify_checkpoint(&PureBackend, checkpoint, origin, log, witnesses)
                .map_err(WitnessError::Checkpoint)?;
        let seconds = accepted
            .iter()
            .filter_map(|a| a.timestamp)
            .max()
            .ok_or(WitnessError::Unwitnessed)?;
        let at = seconds.checked_mul(1_000).ok_or(WitnessError::Range)?;
        let newest = self.witnessed.map_or(at, |w| w.max(at));
        self.witnessed = Some(newest);
        Ok(newest)
    }

    /// Whether the metadata is fresh at `now` for a contract with Δ `delta_ms` (§13.7.2): a
    /// witness cosigned it no more than Δ ago, or one hour when the contract declares none. A
    /// cosignature from the future does not count.
    #[must_use]
    pub fn fresh(&self, now: TrustedTime, delta_ms: Option<u64>) -> bool {
        let limit = delta_ms.unwrap_or(METADATA_FRESHNESS_MS);
        self.witnessed
            .and_then(|w| now.checked_sub(w))
            .is_some_and(|age| age <= limit)
    }
}
