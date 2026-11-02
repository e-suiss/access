//! Decision receipts (§9.8, OP-143 m.5): the payload a decision point signs after an ALLOW
//! commit, and its offline verification. A receipt is never a credential (R4): it names one
//! Exercise, one intent and one audience.

use alloc::string::String;

use crate::codec::{Canonical, Fields, ModelError, map, uint};
use crate::combinator::Capacity;
use crate::digest::Digest;
use crate::meta::{ExerciseBasis, basis_value, capacity, capacity_value, exercise_basis};
use crate::model::{Id, TrustedTime};
use crate::verify::Backend;
use crate::verify::cose::{CoseError, parse_sign1, verify_sign1};
use crate::verify::key_scope::{DomainMetadata, KeyScopeError, KeyUsage, operational_key};

/// `COSE_Sign1` content type of a receipt.
pub const CONTENT_TYPE: &str = "application/access-receipt+cbor";

/// The receipt payload (§9.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// The domain whose decision it is.
    pub domain: Digest,
    /// The Exercise.
    pub exercise: Digest,
    /// Position of the decision record.
    pub record: u64,
    /// The intent digest the ALLOW is for.
    pub intent: Digest,
    /// The actor Instance; `None` for an anonymous actor.
    pub instance: Option<Id>,
    /// Digest of the actor's AIS.
    pub ais: Option<Digest>,
    /// Declared capacity.
    pub capacity: Capacity,
    /// Basis.
    pub basis: ExerciseBasis,
    /// The PEP that applies the decision.
    pub audience: String,
    /// Trusted evaluation time; also the signing time.
    pub iat: TrustedTime,
    /// Whether the ALLOW drew from a budget.
    pub drawn: bool,
}

impl Canonical for Receipt {
    fn to_value(&self) -> suiss_crypto::dcbor::Value {
        use suiss_crypto::dcbor::Value;
        map([
            ("domain", Some(self.domain.to_value())),
            ("exercise", Some(self.exercise.to_value())),
            ("record", Some(Value::Unsigned(self.record))),
            ("intent", Some(self.intent.to_value())),
            ("instance", self.instance.as_ref().map(Canonical::to_value)),
            ("ais", self.ais.as_ref().map(Digest::to_value)),
            ("capacity", Some(capacity_value(self.capacity))),
            ("basis", Some(basis_value(&self.basis))),
            ("audience", Some(Value::text(&self.audience))),
            ("iat", Some(Value::Unsigned(self.iat))),
            ("drawn", Some(Value::Bool(self.drawn))),
        ])
    }

    fn from_value(v: &suiss_crypto::dcbor::Value) -> Result<Self, ModelError> {
        use suiss_crypto::dcbor::Value;
        let mut f = Fields::of(v)?;
        let digest = |v: &Value| Digest::from_value(v).ok_or(ModelError::Shape);
        let r = Self {
            domain: digest(f.req("domain")?)?,
            exercise: digest(f.req("exercise")?)?,
            record: uint(f.req("record")?)?,
            intent: digest(f.req("intent")?)?,
            instance: f.opt("instance").map(Id::from_value).transpose()?,
            ais: f.opt("ais").map(digest).transpose()?,
            capacity: capacity(f.req("capacity")?)?,
            basis: exercise_basis(f.req("basis")?)?,
            audience: match f.req("audience")? {
                Value::Text(t) if !t.is_empty() => t.clone(),
                _ => return Err(ModelError::Shape),
            },
            iat: uint(f.req("iat")?)?,
            drawn: match f.req("drawn")? {
                Value::Bool(b) => *b,
                _ => return Err(ModelError::Shape),
            },
        };
        f.done()?;
        Ok(r)
    }
}

/// The digest a decision record carries in `artifacts` before the receipt is signed (TI-12).
///
/// # Errors
/// The receipt cannot be encoded.
pub fn digest(receipt: &Receipt) -> Result<Digest, suiss_crypto::dcbor::EncodeError> {
    Ok(Digest(
        suiss_crypto::digest::context_digest("access/receipt/v1", &receipt.to_bytes()?).0,
    ))
}

/// Why a receipt is not accepted. Each is a local DENY at the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    /// Not a receipt.
    #[error("receipt-malformed")]
    Malformed,
    /// The signing key is not one the domain declared for receipts at `iat`.
    #[error("receipt-key: {0}")]
    Key(KeyScopeError),
    /// The signature does not verify.
    #[error("receipt-signature")]
    Signature(CoseError),
    /// Another domain's receipt.
    #[error("receipt-domain")]
    Domain,
    /// Another PEP's receipt.
    #[error("receipt-audience")]
    Audience,
    /// Another intent's receipt.
    #[error("receipt-intent")]
    Intent,
    /// Signed after the verifier's time.
    #[error("receipt-future")]
    Future,
}

impl ReceiptError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "receipt-malformed",
            Self::Key(_) => "receipt-key",
            Self::Signature(_) => "receipt-signature",
            Self::Domain => "receipt-domain",
            Self::Audience => "receipt-audience",
            Self::Intent => "receipt-intent",
            Self::Future => "receipt-future",
        }
    }
}

/// What the verifier expects of a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected<'a> {
    /// The domain.
    pub domain: &'a Digest,
    /// The verifier's own PEP identity.
    pub audience: &'a str,
    /// The intent it is about to apply.
    pub intent: &'a Digest,
    /// The verifier's trusted time.
    pub now: TrustedTime,
}

/// Verifies a receipt and its key excerpt against verified Domain Metadata (§9.8, CR-58 m.5):
/// the key is the domain's receipt key at `iat`, the signature verifies, and the receipt is for
/// this domain, this PEP and this intent, signed no later than `now` plus the AIS skew.
///
/// # Errors
/// [`ReceiptError`].
pub fn verify(
    backend: &impl Backend,
    metadata: &DomainMetadata,
    sign1: &[u8],
    excerpt: &[u8],
    expected: &Expected<'_>,
) -> Result<Receipt, ReceiptError> {
    let unverified = parse_sign1(sign1)
        .ok()
        .and_then(|s| s.payload)
        .ok_or(ReceiptError::Malformed)?;
    let claimed = Receipt::from_bytes(&unverified).map_err(|_| ReceiptError::Malformed)?;
    let key = operational_key(
        backend,
        metadata,
        &claimed.domain,
        excerpt,
        KeyUsage::Receipt,
        claimed.iat,
    )
    .map_err(ReceiptError::Key)?;
    let verified = verify_sign1(backend, sign1, &key.key_set(), CONTENT_TYPE)
        .map_err(ReceiptError::Signature)?;
    let receipt = Receipt::from_bytes(&verified.payload).map_err(|_| ReceiptError::Malformed)?;
    if receipt.domain != *expected.domain || metadata.domain != *expected.domain {
        return Err(ReceiptError::Domain);
    }
    if receipt.audience != expected.audience {
        return Err(ReceiptError::Audience);
    }
    if receipt.intent != *expected.intent {
        return Err(ReceiptError::Intent);
    }
    if receipt.iat > expected.now.saturating_add(crate::ais::SKEW_MS) {
        return Err(ReceiptError::Future);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests;
