//! Receipts and PAPs as the decision point sends them (OP-159 m.15 (b), m.17 (a)): a single
//! `COSE_Sign1` or the hybrid carrier `[classic, pq]` with one key excerpt each, verified under
//! the Domain Metadata `hybrid` policy, and the inclusion evidence for a receipt signed under a
//! superseded binding key (5780). Every check is the Kernel's.

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::receipt::{self, Receipt, ReceiptError};
use access_kernel::record::Disclosure;
use access_kernel::verify::Backend;
use access_kernel::verify::cose::parse_sign1;
use access_kernel::verify::hybrid::{self, Component, HybridError};
use access_kernel::verify::key_scope::{
    DomainMetadata, Hybrid, Inclusion, InclusionEvidence, KeyUsage,
};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::note::Verifier;

/// The inclusion evidence of a record in the checkpoint a superseded binding key cites: the
/// inclusion proof bundle the domain serves (`GET .../checkpoints/{size}/inclusion/{pos}`), the
/// log key and the independent witness keys the verifier trusts, and, for a key superseded at
/// a later checkpoint, the consistency path to it (L0-SIG-80, U27).
#[derive(Clone, Debug)]
pub struct Evidence {
    record: Disclosure,
    path: Vec<[u8; 32]>,
    note: String,
    consistency: Option<(u64, [u8; 32], Vec<[u8; 32]>)>,
    origin: String,
    log: Verifier,
    witnesses: Vec<Verifier>,
}

fn hashes(v: &Value) -> Option<Vec<[u8; 32]>> {
    let Value::Array(items) = v else {
        return None;
    };
    items
        .iter()
        .map(|h| match h {
            Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).ok(),
            _ => None,
        })
        .collect()
}

impl Evidence {
    /// The evidence an inclusion proof `bundle` gives, with the note's cosignatures rebuilt for
    /// the `witnesses` it names; `None` when the bundle is not one.
    #[must_use]
    pub fn from_bundle(
        bundle: &[u8],
        (origin, log, witnesses): (&str, Verifier, Vec<Verifier>),
        consistency: Option<(u64, [u8; 32], Vec<[u8; 32]>)>,
    ) -> Option<Self> {
        let v = dcbor::decode(bundle, Limits::CEILING).ok()?;
        let (
            Some(Value::Text(note)),
            Some(Value::Bytes(record)),
            Some(path),
            Some(Value::Array(cosignatures)),
        ) = (
            v.get("checkpoint"),
            v.get("record"),
            v.get("inclusion"),
            v.get("cosignatures"),
        )
        else {
            return None;
        };
        let mut text = note.clone();
        for c in cosignatures {
            let (Some(Value::Text(name)), Some(Value::Unsigned(ts)), Some(Value::Bytes(sig))) =
                (c.get("name"), c.get("timestamp"), c.get("signature"))
            else {
                return None;
            };
            let Some(key) = witnesses.iter().find(|k| k.name() == name) else {
                continue;
            };
            let mut raw = key.id().to_be_bytes().to_vec();
            raw.extend_from_slice(&ts.to_be_bytes());
            raw.extend_from_slice(sig);
            text.push_str("\u{2014} ");
            text.push_str(name);
            text.push(' ');
            text.push_str(&suiss_crypto::note::base64_encode(&raw));
            text.push('\n');
        }
        Some(Self {
            record: Disclosure::from_bytes(record).ok()?,
            path: hashes(path)?,
            note: text,
            consistency,
            origin: String::from(origin),
            log,
            witnesses,
        })
    }

    /// The Kernel's evidence for the artefact with exact-content digest `artefact`.
    #[must_use]
    pub fn of(&self, artefact: Digest) -> InclusionEvidence<'_> {
        InclusionEvidence::new(
            artefact,
            Inclusion::new(
                &self.record,
                &self.path,
                &self.note,
                self.consistency
                    .as_ref()
                    .map(|(s, r, p)| (*s, *r, p.as_slice())),
            ),
            &self.origin,
            &self.log,
            &self.witnesses,
        )
    }
}

/// Why a receipt as sent is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SentError {
    /// The receipt is refused (L2-RCP-3).
    #[error("{}", .0.code())]
    Receipt(ReceiptError),
    /// The hybrid policy is not met (L0-SIG-75a, OP-159 m.15 (b)).
    #[error("{}", .0.code())]
    Hybrid(HybridError),
}

impl SentError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Receipt(e) => e.code(),
            Self::Hybrid(e) => e.code(),
        }
    }
}

/// The classical and the ML-DSA `COSE_Sign1` of an artefact, each when present.
pub type Components = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The classical and ML-DSA components of `sign1`: the two of a hybrid carrier (a CBOR array of
/// two), or `sign1` alone as the component of its own algorithm, which the Kernel then checks.
///
/// # Errors
/// [`HybridError::Carrier`] for a carrier that is not `[classic, pq]`.
pub fn components(sign1: &[u8]) -> Result<Components, HybridError> {
    if sign1.first() == Some(&0x82) {
        let (c, p) = hybrid::decode_carrier(sign1)?;
        return Ok((Some(c), Some(p)));
    }
    let pq = access_kernel::verify::ml_dsa::algorithm_of(sign1)
        .is_ok_and(access_kernel::verify::ml_dsa::is_ml_dsa);
    Ok(if pq {
        (None, Some(sign1.to_vec()))
    } else {
        (Some(sign1.to_vec()), None)
    })
}

/// Verifies a receipt as the decision point sends it (L2-RCP-3, OP-159 m.15 (b), m.17 (a)):
/// the components the metadata's `hybrid` policy requires verify over the same payload, a lone
/// component under `both` is `hybrid-missing`, and the receipt checks are the Kernel's on the
/// classical component (the ML-DSA one under `pq`), with `evidence` for a superseded binding key.
///
/// # Errors
/// [`SentError`].
pub fn receipt(
    backend: &impl Backend,
    metadata: &DomainMetadata,
    (sign1, excerpt, pq_excerpt): (&[u8], &[u8], Option<&[u8]>),
    expected: &receipt::Expected<'_>,
    evidence: Option<&Evidence>,
) -> Result<Receipt, SentError> {
    let (classic, pq) = components(sign1).map_err(SentError::Hybrid)?;
    let policy = metadata.hybrid.unwrap_or(Hybrid::Classic);
    let (one, key) = match policy {
        Hybrid::Pq => (pq.as_deref(), pq_excerpt.unwrap_or(excerpt)),
        Hybrid::Classic | Hybrid::Both => (classic.as_deref(), excerpt),
    };
    let one = one.ok_or(SentError::Hybrid(HybridError::Missing))?;
    let claimed = parse_sign1(one)
        .ok()
        .and_then(|s| s.payload)
        .and_then(|p| Receipt::from_bytes(&p).ok())
        .ok_or(SentError::Receipt(ReceiptError::Malformed))?;
    let mut checked = metadata.clone();
    if policy == Hybrid::Both {
        let pair = (
            classic.as_deref().map(|c| Component::new(c, excerpt)),
            pq.as_deref()
                .zip(pq_excerpt)
                .map(|(p, e)| Component::new(p, e)),
        );
        hybrid::verify(
            backend,
            metadata,
            pair.0,
            pair.1,
            &hybrid::Expected::new(
                &claimed.domain,
                KeyUsage::Receipt,
                claimed.iat,
                receipt::CONTENT_TYPE,
            ),
        )
        .map_err(SentError::Hybrid)?;
        checked.hybrid = Some(Hybrid::Classic);
    }
    let artefact = receipt::digest(&claimed).ok();
    let own = evidence.zip(artefact).map(|(e, a)| e.of(a));
    receipt::verify_with_evidence(backend, &checked, one, key, expected, own.as_ref())
        .map_err(SentError::Receipt)
}
