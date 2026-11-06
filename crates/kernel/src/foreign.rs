//! Foreign authority (§9.15A.2, OP-143 m.13): the foreign issuer of a `foreign-authority`
//! Acceptance, the gate it opens, and the use of a foreign domain's PAP behind a bridging Grant.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::algebra::Catalog;
use crate::codec::{Canonical, Fields, ModelError, ident, map, set_items, set_value, single, uint};
use crate::digest::Digest;
use crate::intent::IntentEnvelope;
use crate::model::{AuthoritySet, TrustedTime, Window};
use crate::pap::{self, Expected, Pap, PapError};
use crate::verify::Backend;
use crate::verify::cose::{KeySet, PublicKey};
use crate::verify::key_scope::{BindingKey, DomainMetadata, KeyScopeError, verify_metadata};

/// The use of an Acceptance whose issuer is a foreign domain.
pub const USE: &str = "foreign-authority";

/// Kind of the index of the `foreign-authority` Acceptances of a foreign domain.
pub const INDEX: &str = "foreign";

/// How old a foreign domain's metadata may be: the TI-RT5 ceiling without witnesses.
pub const FRESHNESS_MS: u64 = 3_600_000;

/// The issuer of a `foreign-authority` Acceptance: a foreign domain and its pinned binding keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignIssuer {
    /// The foreign `DomainID`.
    pub domain: Digest,
    /// Pinned binding keys by thumbprint (CR-58).
    pub binding: BTreeMap<[u8; 32], BindingKey>,
}

impl Canonical for ForeignIssuer {
    fn to_value(&self) -> Value {
        map([
            ("domain", Some(self.domain.to_value())),
            (
                "binding",
                Some(set_value(self.binding.values().map(Canonical::to_value))),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let domain = Digest::from_value(f.req("domain")?).ok_or(ModelError::Shape)?;
        let mut binding = BTreeMap::new();
        for b in set_items(f.req("binding")?, true)? {
            let b = BindingKey::from_value(b)?;
            if binding.insert(b.kid, b).is_some() {
                return Err(ModelError::SetOrder);
            }
        }
        f.done()?;
        Ok(Self { domain, binding })
    }
}

impl ForeignIssuer {
    /// The issuer of an Acceptance's content, when it is a foreign domain.
    ///
    /// # Errors
    /// [`ModelError`] for a `foreign` issuer that does not decode.
    pub fn of(content: &Value) -> Result<Option<Self>, ModelError> {
        match content.get("issuer") {
            Some(v @ Value::Map(_)) => match single(v)? {
                (INDEX, inner) => Self::from_value(inner).map(Some),
                _ => Err(ModelError::Unknown),
            },
            _ => Ok(None),
        }
    }

    /// The pinned binding keys as a key set.
    #[must_use]
    pub fn trusted(&self) -> KeySet {
        let mut set = KeySet::default();
        for b in self.binding.values() {
            set.keys.insert(b.kid, b.key.clone());
            set.allowed.insert(b.alg);
        }
        set
    }
}

/// `dCBOR(["foreign", DomainID])`: the `foreign-authority` Acceptances of a foreign domain.
#[must_use]
pub fn index_key(domain: &Digest) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![Value::text(INDEX), domain.to_value()]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// What a `foreign-authority` Acceptance admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignGate {
    /// The foreign domain and its pins.
    pub issuer: ForeignIssuer,
    /// The foreign authority classes, each an action namespace.
    pub classes: BTreeSet<String>,
    /// Validity.
    pub validity: Window,
    /// Last use time.
    pub ingest_until: Option<u64>,
    /// Last PAP signing time.
    pub issued_until: Option<u64>,
}

impl ForeignGate {
    /// The gate of an Acceptance's content; `None` for any other use.
    ///
    /// # Errors
    /// [`ModelError`] for content that does not decode.
    pub fn of(content: &Value) -> Result<Option<Self>, ModelError> {
        if content.get("use") != Some(&Value::text(USE)) {
            return Ok(None);
        }
        let issuer = ForeignIssuer::of(content)?.ok_or(ModelError::Shape)?;
        let classes = set_items(content.get("classes").ok_or(ModelError::Shape)?, true)?
            .iter()
            .map(ident)
            .collect::<Result<BTreeSet<_>, _>>()?;
        let at = |k: &str| content.get(k).map(uint).transpose();
        Ok(Some(Self {
            issuer,
            classes,
            validity: Window::from_value(content.get("validity").ok_or(ModelError::Shape)?)?,
            ingest_until: at("ingest_until")?,
            issued_until: at("issued_until")?,
        }))
    }

    /// Whether the gate covers class `class` of `domain` at time `now`.
    #[must_use]
    pub fn opens(&self, domain: &Digest, class: &str, now: TrustedTime) -> bool {
        self.issuer.domain == *domain
            && self.classes.contains(class)
            && self.validity.from <= now
            && now <= self.validity.until
            && self.ingest_until.is_none_or(|u| now <= u)
    }
}

/// The text form of a `DomainID` (L0-ENC-20), the audience a foreign PAP names for this domain.
#[must_use]
pub fn domain_text(domain: &Digest) -> String {
    alloc::format!("sha-256:{}", crate::json::b64url_encode(&domain.0))
}

fn in_namespace(class: &str, namespace: &str) -> bool {
    namespace
        .strip_prefix(class)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// Whether every action of `set`, named or by prefix, lies in the namespace `class`.
#[must_use]
pub fn within_class(class: &str, set: &AuthoritySet) -> bool {
    set.actions
        .exact
        .iter()
        .all(|a| in_namespace(class, &a.namespace))
        && set
            .actions
            .prefix
            .iter()
            .all(|(n, _)| in_namespace(class, n))
}

/// Why a foreign PAP is not used (OP-143 m.13 (d)). Each is a local DENY.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ForeignError {
    /// The metadata does not verify under the pinned binding keys.
    #[error("foreign-metadata: {0}")]
    Metadata(KeyScopeError),
    /// The metadata is another domain's.
    #[error("foreign-metadata-domain")]
    MetadataDomain,
    /// The metadata is older than [`FRESHNESS_MS`].
    #[error("foreign-stale")]
    Stale,
    /// The PAP is not accepted for this use (L2-PAP-3).
    #[error("{0}")]
    Pap(PapError),
    /// The PAP's holder key is not the actor Instance's key here.
    #[error("foreign-holder-key")]
    HolderKey,
    /// An action of the bounds lies outside the class.
    #[error("foreign-class")]
    Class,
    /// The PAP was signed after the Acceptance's `issued_until`.
    #[error("foreign-cutoff")]
    Cutoff,
}

impl ForeignError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Metadata(_) => "foreign-metadata",
            Self::MetadataDomain => "foreign-metadata-domain",
            Self::Stale => "foreign-stale",
            Self::Pap(e) => e.code(),
            Self::HolderKey => "foreign-holder-key",
            Self::Class => "foreign-class",
            Self::Cutoff => "foreign-cutoff",
        }
    }
}

/// A foreign PAP as a request carries it.
#[derive(Clone, Copy, Debug)]
pub struct Presented<'a> {
    /// The foreign domain's binding-signed Domain Metadata.
    pub metadata: &'a [u8],
    /// The PAP's `COSE_Sign1`.
    pub pap: &'a [u8],
    /// The key excerpt of the operational key that signed it.
    pub excerpt: &'a [u8],
    /// The holder's presentation.
    pub presentation: &'a [u8],
}

/// The use the verifying domain makes of it.
#[derive(Clone, Copy, Debug)]
pub struct Use<'a> {
    /// The verifying domain.
    pub domain: &'a Digest,
    /// The intent.
    pub intent: &'a IntentEnvelope,
    /// The request nonce.
    pub nonce: &'a [u8],
    /// Trusted time.
    pub now: TrustedTime,
    /// The catalog the intent is evaluated against.
    pub catalog: &'a Catalog,
    /// The actor Instance's registered key in the verifying domain.
    pub actor_key: &'a PublicKey,
    /// The class the bridging Grant names.
    pub class: &'a str,
    /// What remains of each offline slice of the PAP at this domain, by budget-term digest: the
    /// slice amount less what earlier uses here drew (§9.15A.3, INV-21). A term not kept is not
    /// usable.
    pub remaining: &'a BTreeMap<Digest, u64>,
}

/// Verifies a foreign PAP for one use under a `foreign-authority` gate, in the order of
/// OP-143 m.13 (d): metadata under the pinned binding keys, its freshness, L2-PAP-3 with this
/// domain as audience and the request nonce, the holder key, the class and the cutoff. The
/// verifying domain checks no local requirement, so a PAP that carries one is refused by
/// L2-PAP-3; the home domain's offline slice is honoured against `remaining`, what this domain
/// has left of it (§9.15A.3, INV-21). The verified PAP comes back with the verified metadata,
/// for the status and key checks that follow.
///
/// # Errors
/// [`ForeignError`], the first step that fails.
pub fn verify(
    backend: &impl Backend,
    gate: &ForeignGate,
    presented: &Presented<'_>,
    used: &Use<'_>,
) -> Result<(Pap, DomainMetadata), ForeignError> {
    // OP-143 m.13 (d)
    let mut metadata = verify_metadata(backend, presented.metadata, &gate.issuer.trusted())
        .map_err(ForeignError::Metadata)?;
    if metadata.domain != gate.issuer.domain {
        return Err(ForeignError::MetadataDomain);
    }
    metadata.binding.retain(|kid, b| {
        gate.issuer
            .binding
            .get(kid)
            .is_some_and(|p| p.key == b.key && p.alg == b.alg)
    });
    if metadata.issued_at.saturating_add(FRESHNESS_MS) < used.now {
        return Err(ForeignError::Stale);
    }
    let audience = domain_text(used.domain);
    let pap = pap::verify(
        backend,
        &metadata,
        presented.pap,
        presented.excerpt,
        presented.presentation,
        &Expected {
            domain: &gate.issuer.domain,
            intent: used.intent,
            audience: &audience,
            nonce: used.nonce,
            now: used.now,
            catalog: used.catalog,
            satisfied: &BTreeSet::new(),
            remaining: used.remaining,
            metadata_fresh: true,
            understood: &BTreeSet::new(),
            last_refresh: None,
            online: false,
            skew_ms: crate::ais::SKEW_MS,
            horizon_cap_ms: crate::tier::validity_ceiling(crate::tier::Tier::Ct1),
        },
    )
    .map_err(ForeignError::Pap)?;
    if pap.holder.key != *used.actor_key {
        return Err(ForeignError::HolderKey);
    }
    if !within_class(used.class, &pap.bounds) || !within_class(used.class, &pap.validity.bounds) {
        return Err(ForeignError::Class);
    }
    if gate.issued_until.is_some_and(|u| pap.iat > u) {
        return Err(ForeignError::Cutoff);
    }
    Ok((pap, metadata))
}

/// The PAP payload's domain, read before verification to pick the gate.
#[must_use]
pub fn claimed_domain(pap_sign1: &[u8]) -> Option<Digest> {
    let payload = crate::verify::cose::parse_sign1(pap_sign1).ok()?.payload?;
    Pap::from_bytes(&payload).ok().map(|p| p.domain)
}

#[cfg(test)]
mod tests;
