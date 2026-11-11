//! The leader gate (OP-56, OP-31, §17.4.10, §17.10.2, G64, OP-158 m.3 (n), (q)): a process leads
//! a domain only when it evaluates every semantic version the domain has activated, and only
//! while the domain is neither sealed for a cell move nor waiting on a fenced continuation after
//! an async DR promote. In a mixed-version cell the older nodes therefore stop leading once the
//! activation record commits, and no two nodes commit under different semantics.

use access_kernel::verify::key_scope::SpecVersions;
use access_kernel::version::{VersionError, check_understood};
use access_store::Pool;
use access_store::cells::{Closed, closed};
use access_store::scope::DomainId;

use crate::SequencerError;

/// The semantic versions this build evaluates (OP-56, PI-21): core and meta-schema version 1
/// of this Kernel, no interop profile track.
#[must_use]
pub fn supported() -> SpecVersions {
    SpecVersions {
        core: access_kernel::version::CORE,
        meta_schema: 1,
        ..SpecVersions::default()
    }
}

/// Why this process does not lead the domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The domain activated a version this process does not evaluate.
    Version(VersionError),
    /// The cell refuses it (sealed, or a promoted copy not yet continued).
    Cell(Closed),
}

impl Refusal {
    /// The stable reason of the refusal.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Version(_) => "version-gate",
            Self::Cell(Closed::Sealed(_)) => "sealed",
            Self::Cell(Closed::PromotedCopy) => "promoted-copy",
        }
    }
}

/// The activated versions stored by the domain's `version_activate` records (the activation
/// record, OP-56); the Genesis versions when none committed.
///
/// # Errors
/// [`SequencerError::Diverged`] when the stored value does not decode.
pub async fn activated(
    app: &Pool,
    domain: &DomainId,
) -> Result<Option<SpecVersions>, SequencerError> {
    let key = access_kernel::recovery::versions_key();
    let rows = access_store::authority::state_of(app, domain, &[key]).await?;
    let Some(value) = rows.into_iter().find_map(|r| r.value) else {
        return Ok(None);
    };
    let value = suiss_crypto::dcbor::decode(&value, suiss_crypto::dcbor::Limits::CEILING)
        .map_err(|_| SequencerError::Diverged)?;
    let (_, activated, _) =
        access_kernel::recovery::versions_state(&value).map_err(|_| SequencerError::Diverged)?;
    Ok(Some(activated))
}

/// The gate before a lease is taken (OP-56, §17.4.10): `Ok(None)` when this process may lead.
///
/// # Errors
/// [`SequencerError`] when the gate could not be read; the caller does not lead then either.
pub async fn check(
    sequencer: &Pool,
    app: &Pool,
    domain: &DomainId,
    semantics: &SpecVersions,
) -> Result<Option<Refusal>, SequencerError> {
    if let Some(c) = closed(sequencer, domain).await? {
        return Ok(Some(Refusal::Cell(c)));
    }
    if let Some(v) = activated(app, domain).await?
        && let Err(e) = check_understood(&v, semantics)
    {
        tracing::warn!(
            event = "sequencer.version.gate",
            reason = "not-understood",
            "the domain activated a semantic version this process does not evaluate; it does not lead (OP-56)"
        );
        return Ok(Some(Refusal::Version(e)));
    }
    Ok(None)
}
