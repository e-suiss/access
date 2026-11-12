//! The post-quantum re-anchor of a domain's log (CR-45 RA-1…RA-6, §16.6.1 RB-0, OP-159 m.3
//! (f), (g)): who may cosign it, when it counts as anchored, what the Domain Metadata then
//! publishes and when a classical algorithm may be retired. A re-anchor without an independent
//! witness's ML-DSA cosign stays pending and is never called anchored.

use access_kernel::verify::key_scope::{Declarations, PqReanchor, Witness};
use access_kernel::verify::ml_dsa::is_ml_dsa;
use access_kernel::verify::reanchor::COSIGN_CONTENT_TYPE;
use suiss_crypto::cose::KeySet;
use suiss_crypto::sig::Backend;
use suiss_ledger::checkpoint::witness::PqCosign;

/// The RA-6 cadence: a re-anchor covers the head for one UTC day (OP-159 m.3 (g), PD).
pub const CADENCE_MS: u64 = 24 * 60 * 60 * 1000;

/// Why a re-anchor or a retirement is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReanchorError {
    /// No independent witness with a declared ML-DSA cosign key (RB-0).
    #[error("no independent post-quantum witness")]
    NoPqWitness,
    /// No anchored re-anchor covers the head within the cadence (RA-6).
    #[error("re-anchor required")]
    Required,
}

impl ReanchorError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoPqWitness => "reanchor-no-pq-witness",
            Self::Required => "reanchor-required",
        }
    }
}

/// Where a re-anchor stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// No independent witness has cosigned it yet.
    Pending,
    /// At least one independent witness cosigned it; what the metadata publishes (RR-35).
    Anchored(PqReanchor),
}

/// The witnesses whose ML-DSA cosign counts (RB-0, OP-159 m.3 (g)): declared, independent and
/// with an ML-DSA key. `canonical` are the root-term witnesses; one only the operator declares
/// never counts (OP-159 m.3 (j)).
///
/// # Errors
/// [`ReanchorError::NoPqWitness`] when there is none.
pub fn pq_witnesses<'a>(
    declared: &'a Declarations,
    canonical: Option<&[Witness]>,
) -> Result<Vec<&'a Witness>, ReanchorError> {
    let out: Vec<&Witness> = declared
        .witnesses
        .iter()
        .filter(|w| w.independent && is_ml_dsa(w.algorithm))
        .filter(|w| canonical.is_none_or(|c| c.contains(w)))
        .collect();
    if out.is_empty() {
        Err(ReanchorError::NoPqWitness)
    } else {
        Ok(out)
    }
}

/// Whether `cosign` is `witness`'s ML-DSA cosign of `body` (RA-3).
pub fn cosign_verifies(
    backend: &impl Backend,
    witness: &Witness,
    body: &str,
    cosign: &PqCosign,
) -> bool {
    let mut keys = KeySet::default();
    keys.allowed.insert(witness.algorithm);
    let kid = access_kernel::verify::key_scope::thumbprint(&witness.key);
    if witness.name != cosign.name || keys.insert(kid, witness.key.clone()).is_err() {
        return false;
    }
    access_kernel::verify::cose::verify_sign1(backend, &cosign.sign1, &keys, COSIGN_CONTENT_TYPE)
        .is_ok_and(|v| v.payload == PqCosign::message(body, cosign.timestamp))
}

/// The status of the re-anchor checkpoint of `size` over `body` with `cosigns` (RA-3,
/// RR-35): anchored by the independent ML-DSA witnesses whose cosign verifies, at the latest
/// of their cosign times.
pub fn status(
    backend: &impl Backend,
    witnesses: &[&Witness],
    (size, body): (u64, &str),
    cosigns: &[PqCosign],
) -> Status {
    let mut names = Vec::new();
    let mut time = 0_u64;
    for c in cosigns {
        if witnesses
            .iter()
            .any(|w| w.independent && cosign_verifies(backend, w, body, c))
            && !names.contains(&c.name)
        {
            names.push(c.name.clone());
            time = time.max(c.timestamp.saturating_mul(1000));
        }
    }
    if names.is_empty() {
        Status::Pending
    } else {
        names.sort();
        Status::Anchored(PqReanchor::new(size, time, names))
    }
}

/// The declarations with `anchored` as the last re-anchor (OP-159 m.3 (g), RR-35).
#[must_use]
pub fn declared_with(declared: &Declarations, anchored: PqReanchor) -> Declarations {
    let mut d = declared.clone();
    d.pq_reanchor = Some(anchored);
    d
}

/// `declared` with only the witnesses and replicas the canonical root-term sets name: what the
/// signer publishes (OP-158 m.11, OP-159 m.3 (j), m.16 (e)). One only the operator declares is
/// a proposal and is never published.
#[must_use]
pub fn canonical_only(
    declared: &Declarations,
    canonical: &access_kernel::meta::RootSets,
) -> Declarations {
    let mut d = declared.clone();
    d.witnesses.retain(|w| canonical.witnesses.contains(w));
    d.replicas.retain(|r| canonical.replicas.contains(r));
    d
}

/// The retirement gate (§15.16 step (c), RA-6, OP-159 m.3 (f)): the last anchored re-anchor
/// covers the committed head of `head_size` and was cosigned within the cadence before `now`.
///
/// # Errors
/// [`ReanchorError::Required`].
pub fn retire_gate(
    last: Option<&PqReanchor>,
    head_size: u64,
    now: u64,
) -> Result<(), ReanchorError> {
    match last {
        Some(r) if r.size >= head_size && now.saturating_sub(r.time) <= CADENCE_MS => Ok(()),
        _ => Err(ReanchorError::Required),
    }
}

/// One UTC day in milliseconds.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// RA-6 (OP-159 m.3 (g), PD): a domain whose allowlist names ML-DSA re-anchors the first
/// checkpoint of each UTC day; `last` is when its last re-anchor checkpoint was signed. An
/// operator request or a retirement runs one whatever this says.
#[must_use]
pub fn due(
    algorithms: &std::collections::BTreeSet<suiss_crypto::cose::Algorithm>,
    last: Option<u64>,
    now: u64,
) -> bool {
    algorithms.iter().any(|a| is_ml_dsa(*a)) && last.is_none_or(|l| l / DAY_MS < now / DAY_MS)
}

#[cfg(test)]
mod tests;
