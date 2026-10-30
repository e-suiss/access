//! The Actor Intent Statement (PI-7, SI-1, CR-55 m.10, OP-141 m.7): what an actor Instance signs
//! to make an Exercise its own, and how a request is checked against it.

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::codec::{Canonical, Fields, ModelError, map, uint};
use crate::combinator::{Capacity, Mode};
use crate::digest::Digest;
use crate::meta::{ExerciseBasis, basis_value, capacity, capacity_value, exercise_basis};
use crate::verify::PureBackend;
use crate::verify::cose::{self, Algorithm, KeySet, PublicKey};
use crate::verify::key_scope::thumbprint;

/// Content type of the statement's `COSE_Sign1`.
pub const CONTENT_TYPE: &str = "application/access-ais+cbor";

/// Clock skew allowed between the actor and the domain (CR-55 m.9).
pub const SKEW_MS: u64 = 60_000;

/// What the actor signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// The domain the decision is in (P38).
    pub domain: Digest,
    /// The request nonce.
    pub nonce: Vec<u8>,
    /// The intent digest (L0-ENC-23).
    pub intent: Digest,
    /// The mode.
    pub mode: Mode,
    /// The PEP the actor addresses.
    pub pep: String,
    /// Declared capacity.
    pub capacity: Capacity,
    /// Declared basis.
    pub basis: ExerciseBasis,
    /// Signing time.
    pub iat: u64,
    /// The Exercise continued, for `continue`.
    pub exercise: Option<Digest>,
}

const MODES: [(&str, Mode); 3] = [
    ("commit", Mode::Commit),
    ("continue", Mode::Continue),
    ("check", Mode::Check),
];

impl Canonical for Statement {
    fn to_value(&self) -> Value {
        map([
            ("domain", Some(self.domain.to_value())),
            ("nonce", Some(Value::Bytes(self.nonce.clone()))),
            ("intent", Some(self.intent.to_value())),
            ("mode", Some(crate::codec::word_of(self.mode, &MODES))),
            ("pep", Some(Value::text(&self.pep))),
            ("capacity", Some(capacity_value(self.capacity))),
            ("basis", Some(basis_value(&self.basis))),
            ("iat", Some(Value::Unsigned(self.iat))),
            ("exercise", self.exercise.as_ref().map(Canonical::to_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let nonce = match f.req("nonce")? {
            Value::Bytes(b) if (16..=64).contains(&b.len()) => b.clone(),
            _ => return Err(ModelError::Range),
        };
        let pep = crate::codec::text(f.req("pep")?)?;
        if pep.is_empty() || pep.len() > 255 {
            return Err(ModelError::Range);
        }
        let s = Self {
            domain: Digest::from_value(f.req("domain")?).ok_or(ModelError::Shape)?,
            nonce,
            intent: Digest::from_value(f.req("intent")?).ok_or(ModelError::Shape)?,
            mode: crate::codec::word(f.req("mode")?, &MODES)?,
            pep: String::from(pep),
            capacity: capacity(f.req("capacity")?)?,
            basis: exercise_basis(f.req("basis")?)?,
            iat: uint(f.req("iat")?)?,
            exercise: f
                .opt("exercise")
                .map(|e| Digest::from_value(e).ok_or(ModelError::Shape))
                .transpose()?,
        };
        f.done()?;
        Ok(s)
    }
}

/// Why a statement does not make the request the actor's (protocol error, §9.5 k.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AisError {
    /// The signature, header or key does not verify.
    #[error("signature: {0}")]
    Signature(cose::CoseError),
    /// The payload is not an `actor-intent-statement`.
    #[error("payload: {0}")]
    Payload(ModelError),
    /// A signed field differs from the request.
    #[error("statement does not match the request: {0}")]
    Mismatch(&'static str),
    /// Signed in the future beyond the skew.
    #[error("signed in the future")]
    Future,
}

impl AisError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Signature(_) => "ais-signature",
            Self::Payload(_) => "ais-payload",
            Self::Mismatch(_) => "ais-mismatch",
            Self::Future => "ais-future",
        }
    }
}

/// The request the statement must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected<'a> {
    /// Domain addressed.
    pub domain: &'a Digest,
    /// Nonce.
    pub nonce: &'a [u8],
    /// Intent digest Access computed itself (TI-11).
    pub intent: &'a Digest,
    /// Mode.
    pub mode: Mode,
    /// The PEP's transport-authenticated identity.
    pub pep: &'a str,
    /// Declared capacity.
    pub capacity: Capacity,
    /// Declared basis.
    pub basis: &'a ExerciseBasis,
    /// The Exercise continued.
    pub exercise: Option<&'a Digest>,
}

/// Verifies `sign1` with the actor Instance's current `key` and checks every signed field
/// against the request. ECDSA must be low-S: the statement is signed by Access's own actor.
///
/// # Errors
/// [`AisError`].
pub fn verify(
    sign1: &[u8],
    key: &PublicKey,
    expected: &Expected<'_>,
    now: u64,
) -> Result<Statement, AisError> {
    let mut keys = KeySet::default();
    keys.insert(thumbprint(key), key.clone())
        .map_err(|e| AisError::Signature(cose::CoseError::Signature(e)))?;
    keys.allowed
        .extend([Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256]);
    let verified = cose::verify_sign1(&PureBackend, sign1, &keys, CONTENT_TYPE)
        .map_err(AisError::Signature)?;
    let value = dcbor::decode(&verified.payload, Limits::CEILING)
        .map_err(|e| AisError::Payload(ModelError::Cbor(e)))?;
    let s = Statement::from_value(&value).map_err(AisError::Payload)?;
    let checks: [(&'static str, bool); 8] = [
        ("domain", s.domain == *expected.domain),
        ("nonce", s.nonce == expected.nonce),
        ("intent", s.intent == *expected.intent),
        ("mode", s.mode == expected.mode),
        ("pep", s.pep == expected.pep),
        ("capacity", s.capacity == expected.capacity),
        ("basis", s.basis == *expected.basis),
        ("exercise", s.exercise.as_ref() == expected.exercise),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(AisError::Mismatch(field));
    }
    if s.iat > now.saturating_add(SKEW_MS) {
        return Err(AisError::Future);
    }
    Ok(s)
}

#[cfg(test)]
mod tests;
