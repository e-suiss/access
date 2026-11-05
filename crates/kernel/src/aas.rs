//! Approval Act Statements (E32, §9.14, L2-AAS-1 to L2-AAS-4): the statement one user act
//! approves, its digest H(AAS), and how a decision point checks it. A WebAuthn assertion signs
//! H(AAS) as its challenge; an Instance key signs the statement as a `COSE_Sign1`. Either way the
//! result enters a decision as an `authentication` Claim whose `statement` is H(AAS).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::codec::{Canonical, Fields, ModelError, ident, map, set_of, set_value, text, uint};
use crate::combinator::Capacity;
use crate::digest::Digest;
use crate::meta::{capacity, capacity_value};
use crate::model::Id;
use crate::verify::PureBackend;
use crate::verify::cose::{self, Algorithm, KeySet, PublicKey};
use crate::verify::key_scope::thumbprint;

/// Content type of a signed statement.
pub const CONTENT_TYPE: &str = "application/access-aas+cbor";
/// Digest context of H(AAS) (L2-AAS-1).
pub const CONTEXT: &str = "access/aas/v1";

/// What the act is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Act {
    /// A `contribute` of this class to the target intent.
    Contribution(String),
    /// The approver's own meta-Exercise.
    AuthorityAct,
}

/// The statement (CDDL `approval-act-statement`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalAct {
    /// The act.
    pub act: Act,
    /// The approving Instance.
    pub instance: Id,
    /// Its Party.
    pub party: Id,
    /// Capacity.
    pub capacity: Capacity,
    /// The intent digest approved.
    pub target: Digest,
    /// The domain of the Exercise.
    pub domain: Digest,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// Work Gate and Work Declaration, when a Gate waits on it.
    pub work_gate: Option<(Digest, Digest)>,
    /// Approval Surface profile.
    pub surface_profile: String,
    /// Its version.
    pub surface_version: u64,
    /// Digest of the render shown.
    pub render_digest: Digest,
    /// Material fields shown.
    pub material_fields: BTreeSet<String>,
    /// Signing time.
    pub issued_at: u64,
    /// End of validity.
    pub expires_at: u64,
}

fn digest_of(v: &Value) -> Result<Digest, ModelError> {
    Digest::from_value(v).ok_or(ModelError::Shape)
}

impl Canonical for ApprovalAct {
    fn to_value(&self) -> Value {
        let (act, class) = match &self.act {
            Act::Contribution(c) => ("contribution", Some(Value::text(c))),
            Act::AuthorityAct => ("authority-act", None),
        };
        map([
            ("act", Some(Value::text(act))),
            ("contribution_class", class),
            (
                "approver",
                Some(map([
                    ("instance", Some(self.instance.to_value())),
                    ("party", Some(self.party.to_value())),
                ])),
            ),
            ("capacity", Some(capacity_value(self.capacity))),
            ("target", Some(self.target.to_value())),
            (
                "exercise_ref",
                Some(Value::Array(alloc::vec![
                    self.domain.to_value(),
                    Value::Bytes(self.nonce.clone())
                ])),
            ),
            (
                "work_gate",
                self.work_gate.as_ref().map(|(gate, declaration)| {
                    map([
                        ("gate", Some(gate.to_value())),
                        ("declaration", Some(declaration.to_value())),
                    ])
                }),
            ),
            (
                "surface",
                Some(map([
                    ("profile", Some(Value::text(&self.surface_profile))),
                    ("version", Some(Value::Unsigned(self.surface_version))),
                ])),
            ),
            ("render_digest", Some(self.render_digest.to_value())),
            (
                "material_fields",
                Some(set_value(
                    self.material_fields.iter().map(|m| Value::text(m)),
                )),
            ),
            ("issued_at", Some(Value::Unsigned(self.issued_at))),
            ("expires_at", Some(Value::Unsigned(self.expires_at))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let act = match (text(f.req("act")?)?, f.opt("contribution_class")) {
            ("contribution", Some(c)) => Act::Contribution(ident(c)?),
            ("authority-act", None) => Act::AuthorityAct,
            ("contribution" | "authority-act", _) => return Err(ModelError::Range),
            _ => return Err(ModelError::Unknown),
        };
        let mut approver = Fields::of(f.req("approver")?)?;
        let instance = Id::from_value(approver.req("instance")?)?;
        let party = Id::from_value(approver.req("party")?)?;
        approver.done()?;
        let (domain, nonce) = match f.req("exercise_ref")? {
            Value::Array(items) => match items.as_slice() {
                [d, Value::Bytes(n)] if (16..=64).contains(&n.len()) => (digest_of(d)?, n.clone()),
                _ => return Err(ModelError::Shape),
            },
            _ => return Err(ModelError::Shape),
        };
        let work_gate = match f.opt("work_gate") {
            None => None,
            Some(w) => {
                let mut wf = Fields::of(w)?;
                let out = (
                    digest_of(wf.req("gate")?)?,
                    digest_of(wf.req("declaration")?)?,
                );
                wf.done()?;
                Some(out)
            }
        };
        let mut surface = Fields::of(f.req("surface")?)?;
        let surface_profile = text(surface.req("profile")?)?;
        if surface_profile.is_empty() || surface_profile.len() > 255 {
            return Err(ModelError::Range);
        }
        let surface_profile = String::from(surface_profile);
        let surface_version = uint(surface.req("version")?)?;
        surface.done()?;
        let out = Self {
            act,
            instance,
            party,
            capacity: capacity(f.req("capacity")?)?,
            target: digest_of(f.req("target")?)?,
            domain,
            nonce,
            work_gate,
            surface_profile,
            surface_version,
            render_digest: digest_of(f.req("render_digest")?)?,
            material_fields: set_of(f.req("material_fields")?, false, ident)?,
            issued_at: uint(f.req("issued_at")?)?,
            expires_at: uint(f.req("expires_at")?)?,
        };
        f.done()?;
        Ok(out)
    }
}

/// H(AAS): the digest of the statement under `access/aas/v1` (L2-AAS-1).
///
/// # Errors
/// The statement cannot be encoded.
pub fn digest(aas: &ApprovalAct) -> Result<Digest, dcbor::EncodeError> {
    Ok(Digest(context_digest(CONTEXT, &aas.to_bytes()?).0))
}

/// Why a statement is not accepted (L2-AAS-2 to L2-AAS-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AasError {
    /// Not a statement.
    #[error("aas-malformed")]
    Malformed,
    /// The signature does not verify under the approver's key.
    #[error("aas-signature")]
    Signature,
    /// Another domain's Exercise.
    #[error("aas-domain")]
    Domain,
    /// Another intent.
    #[error("aas-target")]
    Target,
    /// Another approver Instance.
    #[error("aas-approver")]
    Approver,
    /// Another render than the one the decision point produced.
    #[error("aas-render")]
    Render,
    /// Signed after the decision point's time.
    #[error("aas-future")]
    Future,
    /// Past `expires_at`, or `expires_at` before `issued_at`.
    #[error("aas-expired")]
    Expired,
}

impl AasError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "aas-malformed",
            Self::Signature => "aas-signature",
            Self::Domain => "aas-domain",
            Self::Target => "aas-target",
            Self::Approver => "aas-approver",
            Self::Render => "aas-render",
            Self::Future => "aas-future",
            Self::Expired => "aas-expired",
        }
    }
}

/// What the decision point expects of a statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected<'a> {
    /// The domain.
    pub domain: &'a Digest,
    /// The intent digest the approval is for.
    pub target: &'a Digest,
    /// The approver Instance.
    pub instance: &'a Id,
    /// The render digest the decision point computed from the action schema.
    pub render_digest: &'a Digest,
    /// Trusted time.
    pub now: u64,
}

/// Checks a statement's content against what the decision point expects (L2-AAS-3, L2-AAS-4),
/// in this order: domain, target, approver, render, then time (`issued_at` no later than `now`
/// plus the AIS skew; `now` no later than `expires_at`, which is not before `issued_at`).
///
/// # Errors
/// [`AasError`].
pub fn check(aas: &ApprovalAct, expected: &Expected<'_>) -> Result<(), AasError> {
    if aas.domain != *expected.domain {
        return Err(AasError::Domain);
    }
    if aas.target != *expected.target {
        return Err(AasError::Target);
    }
    if aas.instance != *expected.instance {
        return Err(AasError::Approver);
    }
    if aas.render_digest != *expected.render_digest {
        return Err(AasError::Render);
    }
    if aas.issued_at > expected.now.saturating_add(crate::ais::SKEW_MS) {
        return Err(AasError::Future);
    }
    if aas.expires_at < aas.issued_at || expected.now > aas.expires_at {
        return Err(AasError::Expired);
    }
    Ok(())
}

/// Verifies a statement an Instance key signed (L2-AAS-2) and checks it (L2-AAS-3,
/// L2-AAS-4). The key is the approver Instance's current key; `kid` is its RFC 7638 thumbprint.
///
/// # Errors
/// [`AasError`].
pub fn verify(
    sign1: &[u8],
    key: &PublicKey,
    expected: &Expected<'_>,
) -> Result<(ApprovalAct, Digest), AasError> {
    let mut keys = KeySet::default();
    keys.insert(thumbprint(key), key.clone())
        .map_err(|_| AasError::Signature)?;
    keys.allowed
        .extend([Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256]);
    let verified = cose::verify_sign1(&PureBackend, sign1, &keys, CONTENT_TYPE)
        .map_err(|_| AasError::Signature)?;
    let value =
        dcbor::decode(&verified.payload, Limits::CEILING).map_err(|_| AasError::Malformed)?;
    let aas = ApprovalAct::from_value(&value).map_err(|_| AasError::Malformed)?;
    check(&aas, expected)?;
    let h = digest(&aas).map_err(|_| AasError::Malformed)?;
    Ok((aas, h))
}

#[cfg(test)]
mod tests;
