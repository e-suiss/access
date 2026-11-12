//! Portable Authority Proofs (§9.10, OP-143 m.6): the payload a domain signs for offline use,
//! the holder's proof of possession, and the verifier's rule (L2-PAP-3).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{EncodeError, Value};

use crate::algebra::Catalog;
use crate::codec::{Canonical, Fields, ModelError, map, set_of, set_value, text, uint};
use crate::combinator::Capacity;
use crate::digest::Digest;
use crate::intent::{IntentEnvelope, ParamValue, covers, intent_digest};
use crate::meta::{capacity, capacity_value};
use crate::model::{AuthoritySet, Id, RequirementTerm, TrustedTime};
use crate::validity::{self, ValidityContract, ValidityError, VerifierContext};
use crate::verify::Backend;
use crate::verify::cose::{CoseError, KeySet, PublicKey, parse_sign1, verify_sign1};
use crate::verify::key_scope::{
    DomainMetadata, KeyScopeError, KeyUsage, operational_key, thumbprint,
};

/// `COSE_Sign1` content type of a PAP.
pub const CONTENT_TYPE: &str = "application/access-pap+cbor";

/// `COSE_Sign1` content type of a holder's presentation.
pub const PRESENTATION_CONTENT_TYPE: &str = "application/access-pap-presentation+cbor";

/// The holder Instance and its key (L2-PAP-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    /// The Instance.
    pub instance: Id,
    /// Its public key.
    pub key: PublicKey,
}

/// The PAP payload (L2-PAP-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pap {
    /// The domain.
    pub domain: Digest,
    /// `ExerciseID` of the `projection.issue` that produced it.
    pub projection_exercise: Digest,
    /// The holder.
    pub holder: Holder,
    /// Capacity.
    pub capacity: Capacity,
    /// Bounds, catalog prefixes pinned.
    pub bounds: AuthoritySet,
    /// Requirements a verifier checks locally.
    pub local_requirements: BTreeSet<RequirementTerm>,
    /// The validity contract.
    pub validity: ValidityContract,
    /// Digest of the basis lineage.
    pub lineage_commitment: Digest,
    /// Signing time.
    pub iat: TrustedTime,
}

/// The holder's proof of possession for one use (L2-PAP-3 step 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    /// Digest of the signed PAP ([`pap_digest`]).
    pub pap: Digest,
    /// The intent digest.
    pub intent: Digest,
    /// The verifier.
    pub audience: String,
    /// The verifier's nonce.
    pub nonce: Vec<u8>,
    /// Signing time.
    pub iat: TrustedTime,
}

fn requirements_value(set: &BTreeSet<RequirementTerm>) -> Option<Value> {
    (!set.is_empty()).then(|| set_value(set.iter().map(Canonical::to_value)))
}

impl Canonical for Holder {
    fn to_value(&self) -> Value {
        map([
            ("instance", Some(self.instance.to_value())),
            ("key", Some(self.key.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let h = Self {
            instance: Id::from_value(f.req("instance")?)?,
            key: PublicKey::from_value(f.req("key")?)?,
        };
        f.done()?;
        Ok(h)
    }
}

impl Canonical for Pap {
    fn to_value(&self) -> Value {
        map([
            ("domain", Some(self.domain.to_value())),
            (
                "projection_exercise",
                Some(self.projection_exercise.to_value()),
            ),
            ("holder", Some(self.holder.to_value())),
            ("capacity", Some(capacity_value(self.capacity))),
            ("bounds", Some(self.bounds.to_value())),
            (
                "local_requirements",
                requirements_value(&self.local_requirements),
            ),
            ("validity", Some(self.validity.to_value())),
            (
                "lineage_commitment",
                Some(self.lineage_commitment.to_value()),
            ),
            ("iat", Some(Value::Unsigned(self.iat))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let p = Self {
            domain: Canonical::from_value(f.req("domain")?)?,
            projection_exercise: Canonical::from_value(f.req("projection_exercise")?)?,
            holder: Holder::from_value(f.req("holder")?)?,
            capacity: capacity(f.req("capacity")?)?,
            bounds: AuthoritySet::from_value(f.req("bounds")?)?,
            local_requirements: f
                .opt("local_requirements")
                .map(|s| set_of(s, true, RequirementTerm::from_value))
                .transpose()?
                .unwrap_or_default(),
            validity: ValidityContract::from_value(f.req("validity")?)?,
            lineage_commitment: Canonical::from_value(f.req("lineage_commitment")?)?,
            iat: uint(f.req("iat")?)?,
        };
        f.done()?;
        Ok(p)
    }
}

impl Canonical for Presentation {
    fn to_value(&self) -> Value {
        map([
            ("pap", Some(self.pap.to_value())),
            ("intent", Some(self.intent.to_value())),
            ("audience", Some(Value::text(&self.audience))),
            ("nonce", Some(Value::Bytes(self.nonce.clone()))),
            ("iat", Some(Value::Unsigned(self.iat))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let audience = text(f.req("audience")?)?;
        if audience.is_empty() || audience.len() > 255 {
            return Err(ModelError::Range);
        }
        let Value::Bytes(nonce) = f.req("nonce")? else {
            return Err(ModelError::Shape);
        };
        if !(16..=64).contains(&nonce.len()) {
            return Err(ModelError::Range);
        }
        let p = Self {
            pap: Canonical::from_value(f.req("pap")?)?,
            intent: Canonical::from_value(f.req("intent")?)?,
            audience: String::from(audience),
            nonce: nonce.clone(),
            iat: uint(f.req("iat")?)?,
        };
        f.done()?;
        Ok(p)
    }
}

/// The PAP digest: `access/pap/v1` over the signed `COSE_Sign1` bytes (L2-PAP-2).
#[must_use]
pub fn pap_digest(sign1: &[u8]) -> Digest {
    suiss_crypto::digest::context_digest("access/pap/v1", sign1)
}

/// The digest a contract's `holder` names: `access/holder/v1` over the holder (L2-PAP-1).
///
/// # Errors
/// The holder cannot be encoded.
pub fn holder_digest(holder: &Holder) -> Result<Digest, EncodeError> {
    Ok(suiss_crypto::digest::context_digest(
        "access/holder/v1",
        &holder.to_bytes()?,
    ))
}

/// Why a PAP is not accepted for a use (L2-PAP-3). Each is a local DENY at the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PapError {
    /// Not a PAP.
    #[error("pap-malformed")]
    Malformed,
    /// The signing key is not one the domain declared for PAPs at `iat`.
    #[error("pap-key: {0}")]
    Key(KeyScopeError),
    /// The signature does not verify.
    #[error("pap-signature")]
    Signature(CoseError),
    /// Another domain's PAP.
    #[error("pap-domain")]
    Domain,
    /// The contract does not allow this use now.
    #[error("pap-validity: {0}")]
    Validity(ValidityError),
    /// The contract names another holder.
    #[error("pap-holder")]
    Holder,
    /// The presentation is not the holder's proof for this use.
    #[error("pap-presentation")]
    Presentation,
    /// The intent is outside the bounds.
    #[error("pap-bounds")]
    Bounds,
    /// A local requirement is not satisfied.
    #[error("pap-requirements")]
    Requirements,
    /// The intent's demand exceeds what remains of the offline slice.
    #[error("pap-slice")]
    Slice,
    /// The verifier's Domain Metadata is not fresh.
    #[error("pap-stale")]
    Stale,
}

impl PapError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "pap-malformed",
            Self::Key(_) => "pap-key",
            Self::Signature(_) => "pap-signature",
            Self::Domain => "pap-domain",
            Self::Validity(_) => "pap-validity",
            Self::Holder => "pap-holder",
            Self::Presentation => "pap-presentation",
            Self::Bounds => "pap-bounds",
            Self::Requirements => "pap-requirements",
            Self::Slice => "pap-slice",
            Self::Stale => "pap-stale",
        }
    }
}

/// What the verifier knows and expects at the moment of use.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    /// The verifier's domain.
    pub domain: &'a Digest,
    /// The intent to apply.
    pub intent: &'a IntentEnvelope,
    /// The verifier's own audience identifier.
    pub audience: &'a str,
    /// The nonce the verifier gave the holder.
    pub nonce: &'a [u8],
    /// The verifier's trusted time.
    pub now: TrustedTime,
    /// Catalog for coverage.
    pub catalog: &'a Catalog,
    /// Local requirement terms the verifier reports satisfied.
    pub satisfied: &'a BTreeSet<RequirementTerm>,
    /// What remains of each offline slice, by budget-term digest; the verifier keeps it.
    pub remaining: &'a BTreeMap<Digest, u64>,
    /// Whether the verifier's Domain Metadata is fresh (TI-RT5).
    pub metadata_fresh: bool,
    /// Extensions the verifier understands.
    pub understood: &'a BTreeSet<String>,
    /// Last successful status refresh.
    pub last_refresh: Option<TrustedTime>,
    /// Whether the verifier obtains an online decision for this use.
    pub online: bool,
    /// Clock skew of this artefact class.
    pub skew_ms: u64,
    /// Effective horizon ceiling.
    pub horizon_cap_ms: u64,
}

/// What one use of `intent` draws from a slice in `unit` (L2-PAP-3 step 5): one for `count`,
/// else the sum of the intent's amounts in that unit; `None` when it does not fit.
#[must_use]
pub fn demand(unit: &str, intent: &IntentEnvelope) -> Option<u64> {
    if unit == "count" {
        return Some(1);
    }
    let mut total: u64 = 0;
    for v in intent.params.values() {
        if let ParamValue::Amount { value, unit: u } = v
            && u == unit
        {
            total = total.checked_add(u64::try_from(*value).ok()?)?;
        }
    }
    Some(total)
}

fn presentation_holds(
    backend: &impl Backend,
    metadata: &DomainMetadata,
    pap: &Pap,
    pap_sign1: &[u8],
    presentation_sign1: &[u8],
    expected: &Expected<'_>,
) -> bool {
    let mut keys = KeySet::default();
    if keys
        .insert(thumbprint(&pap.holder.key), pap.holder.key.clone())
        .is_err()
    {
        return false;
    }
    keys.allowed.extend(metadata.algorithms.iter().copied());
    let Ok(verified) = verify_sign1(
        backend,
        presentation_sign1,
        &keys,
        PRESENTATION_CONTENT_TYPE,
    ) else {
        return false;
    };
    let Ok(p) = Presentation::from_bytes(&verified.payload) else {
        return false;
    };
    let Ok(intent) = intent_digest(expected.intent) else {
        return false;
    };
    let Some(latest) = expected.now.checked_add(crate::ais::SKEW_MS) else {
        return false;
    };
    let earliest = expected.now.saturating_sub(crate::ais::SKEW_MS);
    p.pap == pap_digest(pap_sign1)
        && p.intent == intent
        && p.audience == expected.audience
        && p.nonce == expected.nonce
        && earliest <= p.iat
        && p.iat <= latest
}

/// Verifies a PAP, its key excerpt and the holder's presentation against verified Domain
/// Metadata for one intent, in the order of L2-PAP-3.
///
/// # Errors
/// [`PapError`], the first step that fails.
pub fn verify(
    backend: &impl Backend,
    metadata: &DomainMetadata,
    pap_sign1: &[u8],
    excerpt: &[u8],
    presentation_sign1: &[u8],
    expected: &Expected<'_>,
) -> Result<Pap, PapError> {
    // L2-PAP-3
    let unverified = parse_sign1(pap_sign1)
        .ok()
        .and_then(|s| s.payload)
        .ok_or(PapError::Malformed)?;
    let claimed = Pap::from_bytes(&unverified).map_err(|_| PapError::Malformed)?;
    let key = operational_key(
        backend,
        metadata,
        &claimed.domain,
        excerpt,
        KeyUsage::Pap,
        claimed.iat,
        None,
    )
    .map_err(PapError::Key)?;
    let verified = verify_sign1(backend, pap_sign1, &key.key_set(), CONTENT_TYPE)
        .map_err(PapError::Signature)?;
    let pap = Pap::from_bytes(&verified.payload).map_err(|_| PapError::Malformed)?;
    if pap.domain != *expected.domain || metadata.domain != *expected.domain {
        return Err(PapError::Domain);
    }
    validity::check(
        &pap.validity,
        &VerifierContext {
            now: expected.now,
            audience: expected.audience,
            understood: expected.understood,
            last_refresh: expected.last_refresh,
            online: expected.online,
            skew_ms: expected.skew_ms,
            iat: pap.iat,
            horizon_cap_ms: expected.horizon_cap_ms,
        },
    )
    .map_err(PapError::Validity)?;
    if holder_digest(&pap.holder).map_err(|_| PapError::Malformed)? != pap.validity.holder {
        return Err(PapError::Holder);
    }
    if !presentation_holds(
        backend,
        metadata,
        &pap,
        pap_sign1,
        presentation_sign1,
        expected,
    ) {
        return Err(PapError::Presentation);
    }
    if !covers(&pap.bounds, expected.intent, expected.catalog)
        || !covers(&pap.validity.bounds, expected.intent, expected.catalog)
    {
        return Err(PapError::Bounds);
    }
    if !pap.local_requirements.is_subset(expected.satisfied)
        || !pap
            .validity
            .local_requirements
            .is_subset(expected.satisfied)
    {
        return Err(PapError::Requirements);
    }
    for slice in &pap.validity.offline_slice {
        let kept = expected
            .remaining
            .get(&slice.budget_term)
            .copied()
            .ok_or(PapError::Slice)?;
        let need = demand(&slice.unit, expected.intent).ok_or(PapError::Slice)?;
        if need > kept.min(slice.amount) {
            return Err(PapError::Slice);
        }
    }
    if !expected.metadata_fresh {
        return Err(PapError::Stale);
    }
    Ok(pap)
}

#[cfg(test)]
mod tests;
