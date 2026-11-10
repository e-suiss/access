//! What the cloud executor checks of a person's microVM before any of their work runs in it
//! (E61 (1), (2), OP-156 m.3 (w)): an SEV-SNP or TDX report whose measurement is one the
//! executor declares and whose report data binds that person and the TEE's own job key, the
//! only key a cloud key permission wraps DEKs to (E59 (1)). Checking the vendor's signature
//! chain is the adapter's; this decides nothing about authority.

use serde::{Deserialize, Serialize};
use suiss_crypto::digest::context_digest;

use super::b64;

/// The TEE kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tee {
    /// AMD SEV-SNP.
    SevSnp,
    /// Intel TDX.
    Tdx,
}

/// A microVM's report, as the adapter read and checked its signature chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The TEE kind.
    pub tee: Tee,
    /// The launch measurement: 48 bytes for both kinds.
    pub measurement: Vec<u8>,
    /// The report data the guest asked for: [`binding`] of the person and the job key.
    pub report_data: [u8; 64],
    /// The digest of the TEE's job key.
    pub job_key: [u8; 32],
}

/// What a job records of its microVM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Isolated {
    /// Whose microVM it is.
    #[serde(with = "b64::fixed")]
    pub person: [u8; 16],
    /// The TEE kind.
    pub tee: Tee,
    /// The digest of the measurement, as a cloud key permission names it.
    #[serde(with = "b64::fixed")]
    pub measurement: [u8; 32],
    /// The digest of the job key.
    #[serde(with = "b64::fixed")]
    pub job_key: [u8; 32],
}

/// Why a microVM is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IsolationError {
    /// The cloud executor has no isolation adapter (fail-closed).
    #[error("executor-isolation")]
    Missing,
    /// The measurement is not one the executor declares.
    #[error("executor-measurement")]
    Measurement,
    /// The report data does not bind this person and this job key: the microVM is someone
    /// else's, or the key is not the TEE's.
    #[error("executor-tee-binding")]
    Binding,
}

/// The digest of a launch measurement.
#[must_use]
pub fn measurement_digest(measurement: &[u8]) -> [u8; 32] {
    context_digest("access/executor/tee-measurement/v1", measurement).0
}

/// The report data a person's microVM must carry: the digest of the person and the job key,
/// then zeros.
#[must_use]
pub fn binding(person: &[u8; 16], job_key: &[u8; 32]) -> [u8; 64] {
    let mut bytes = person.to_vec();
    bytes.extend_from_slice(job_key);
    let d = context_digest("access/executor/tee-binding/v1", &bytes).0;
    let mut out = [0_u8; 64];
    for (o, b) in out.iter_mut().zip(d) {
        *o = b;
    }
    out
}

/// Checks `report` of `person`'s microVM against the declared measurement digests.
///
/// # Errors
/// [`IsolationError`].
pub fn verify(
    report: &Report,
    person: &[u8; 16],
    declared: &[[u8; 32]],
) -> Result<Isolated, IsolationError> {
    let measurement = measurement_digest(&report.measurement);
    if report.measurement.len() != 48 || !declared.contains(&measurement) {
        return Err(IsolationError::Measurement);
    }
    if report.report_data != binding(person, &report.job_key) {
        return Err(IsolationError::Binding);
    }
    Ok(Isolated {
        person: *person,
        tee: report.tee,
        measurement,
        job_key: report.job_key,
    })
}
