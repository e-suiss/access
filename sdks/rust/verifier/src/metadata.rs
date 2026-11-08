//! Domain Metadata the verifier holds (§9.10 steps 1 and 6, CR-58, TI-RT5): binding-signed
//! metadata verified against the pinned binding keys, and its freshness, measured by an
//! independent witness's cosignature over a domain checkpoint that names this metadata's digest,
//! never by the metadata's own `issued_at` (OP-152 m.5 (h)).

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
    /// The checkpoint names no Domain Metadata, or other metadata than the one held
    /// (OP-152 m.5 (h)): fetch the metadata it names first.
    #[error("other metadata")]
    OtherMetadata,
}

/// Digest context of the signed Domain Metadata a checkpoint names (OP-152 m.5 (h), L2-CKP-5).
pub const METADATA_CONTEXT: &str = "access/domain-metadata/v1";

/// The checkpoint extension line that names the Domain Metadata (L2-CKP-5).
const METADATA_LINE: &str = "metadata sha-256:";

/// The digest of signed Domain Metadata bytes a checkpoint names (L2-CKP-5).
#[must_use]
pub fn metadata_digest(signed: &[u8]) -> [u8; 32] {
    suiss_crypto::digest::context_digest(METADATA_CONTEXT, signed).0
}

/// Verified Domain Metadata and the last witnessed time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataView {
    metadata: DomainMetadata,
    digest: [u8; 32],
    witnessed: Option<TrustedTime>,
}

impl MetadataView {
    /// Metadata the caller verified itself from the binding-signed bytes `signed`; it has no
    /// witness yet, so it is not fresh.
    #[must_use]
    pub fn new(metadata: DomainMetadata, signed: &[u8]) -> Self {
        Self {
            metadata,
            digest: metadata_digest(signed),
            witnessed: None,
        }
    }

    /// Verifies binding-signed Domain Metadata against the pinned binding key set (CR-58).
    ///
    /// # Errors
    /// [`KeyScopeError`].
    pub fn verify(signed: &[u8], trusted: &KeySet) -> Result<Self, KeyScopeError> {
        key_scope::verify_metadata(&PureBackend, signed, trusted).map(|m| Self::new(m, signed))
    }

    /// The digest a checkpoint must name to refresh this metadata (L2-CKP-5).
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
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

    /// Accepts a signed checkpoint of the domain log at `origin` (L2-CKP-3, L2-CKP-4) that names
    /// this metadata (L2-CKP-5) and takes the newest cosignature of a witness in `witnesses` as
    /// the metadata's freshness (TI-RT5, OP-152 m.5 (h)). The log's own signature is required but
    /// does not count as a witness; a checkpoint of other metadata refreshes nothing.
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
        let (cp, accepted) =
            note::verify_checkpoint(&PureBackend, checkpoint, origin, log, witnesses)
                .map_err(WitnessError::Checkpoint)?;
        // OP-152 m.5 (h)
        let named = cp
            .extensions
            .iter()
            .find_map(|l| l.strip_prefix(METADATA_LINE))
            .and_then(|d| access_kernel::json::b64url_decode(d).ok());
        if named.as_deref() != Some(self.digest.as_slice()) {
            return Err(WitnessError::OtherMetadata);
        }
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
