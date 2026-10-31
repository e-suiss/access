//! Claims (§9.13, OP-141 m.19): a signed statement by an issuer Party about a subject Party,
//! how it is verified, and which Acceptance admits it (L2-CLM-1 to L2-CLM-3).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::codec::{Canonical, Fields, ModelError, assurance, ident, map, map_value, uint};
use crate::digest::Digest;
use crate::model::{EqValue, Id, ResourceRef, SubjectSelector, Window};
use crate::requirement::{check_assurance, meets_floor};
use crate::verify::PureBackend;
use crate::verify::cose::{self, Algorithm, KeySet, PublicKey};
use crate::verify::key_scope::thumbprint;

/// Content type of a Claim's `COSE_Sign1`.
pub const CONTENT_TYPE: &str = "application/access-claim+cbor";

/// Digest context of the Claim bytes (L2-CLM-1).
pub const CONTEXT: &str = "access/claim/v1";

/// The use under which a Claim is a proof.
pub const PREDICATE_INPUT: &str = "predicate-input";

/// The use under which a Claim is a group membership (OP-141 m.20).
pub const SUBJECT_SELECTION: &str = "subject-selection";

/// Kind of the membership index (OP-141 m.20 (b)).
pub const MEMBER: &str = "member";

/// `dCBOR(["member", class, subject, ClaimID])`: one admitted Claim's membership entry.
#[must_use]
pub fn member_key(class: &str, subject: &Id, claim: &Id) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![
            Value::text(MEMBER),
            Value::text(class),
            subject.to_value(),
            claim.to_value()
        ]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// The byte prefix shared by the membership entries of `subject` in `class`.
#[must_use]
pub fn member_prefix(class: &str, subject: &Id) -> Vec<u8> {
    let mut key = member_key(class, subject, &Id([0; 16]));
    // the ClaimID is the last item: a 16-byte string, header 0x50 and 16 bytes
    key.truncate(key.len().saturating_sub(17));
    key
}

/// Whether a recorded Claim makes its subject satisfy `conjunct` now (OP-141 m.20 (c)); the
/// Acceptance check is the caller's.
#[must_use]
pub fn satisfies(conjunct: &crate::model::Conjunct, state: &ClaimState, now: u64) -> bool {
    let s = &state.statement;
    state.ended.is_none()
        && s.class == conjunct.claim_class
        && conjunct
            .value
            .as_ref()
            .is_none_or(|v| s.value.as_ref() == Some(v))
        && s.validity.from <= now
        && now <= s.validity.until
}

/// How far `issued_at` may lie ahead of trusted time (OP-141 m.19 (c)).
pub const SKEW_MS: u64 = 60_000;

/// What the issuer signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// The domain the Claim is for.
    pub domain: Digest,
    /// The issuer Party.
    pub issuer: Id,
    /// The subject Party.
    pub subject: Id,
    /// The class.
    pub class: String,
    /// The value, if the class carries one.
    pub value: Option<EqValue>,
    /// Signing time.
    pub issued_at: u64,
    /// When it holds.
    pub validity: Window,
    /// Assurance levels.
    pub assurance: BTreeMap<String, u64>,
    /// Intent it is bound to.
    pub bound_intent: Option<Digest>,
    /// Instance it is bound to.
    pub bound_instance: Option<Id>,
    /// Resource it is bound to.
    pub bound_resource: Option<ResourceRef>,
    /// The Claim it replaces.
    pub supersedes: Option<Id>,
}

fn opt<T>(
    f: &mut Fields<'_>,
    k: &str,
    read: impl Fn(&Value) -> Result<T, ModelError>,
) -> Result<Option<T>, ModelError> {
    f.opt(k).map(read).transpose()
}

impl Statement {
    fn fields(&self) -> [(&'static str, Option<Value>); 12] {
        [
            ("domain", Some(self.domain.to_value())),
            ("issuer", Some(self.issuer.to_value())),
            ("subject", Some(self.subject.to_value())),
            ("class", Some(Value::text(&self.class))),
            ("value", self.value.as_ref().map(Canonical::to_value)),
            ("issued_at", Some(Value::Unsigned(self.issued_at))),
            ("validity", Some(self.validity.to_value())),
            (
                "assurance",
                map_value(&self.assurance, |v| Value::Unsigned(*v)),
            ),
            (
                "bound_intent",
                self.bound_intent.as_ref().map(Canonical::to_value),
            ),
            (
                "bound_instance",
                self.bound_instance.as_ref().map(Canonical::to_value),
            ),
            (
                "bound_resource",
                self.bound_resource.as_ref().map(Canonical::to_value),
            ),
            (
                "supersedes",
                self.supersedes.as_ref().map(Canonical::to_value),
            ),
        ]
    }
}

impl Canonical for Statement {
    fn to_value(&self) -> Value {
        map(self.fields())
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let assurance = assurance(f.opt("assurance"))?;
        check_assurance(&assurance)?;
        let s = Self {
            domain: Digest::from_value(f.req("domain")?).ok_or(ModelError::Shape)?,
            issuer: Id::from_value(f.req("issuer")?)?,
            subject: Id::from_value(f.req("subject")?)?,
            class: ident(f.req("class")?)?,
            value: opt(&mut f, "value", EqValue::from_value)?,
            issued_at: uint(f.req("issued_at")?)?,
            validity: Window::from_value(f.req("validity")?)?,
            assurance,
            bound_intent: opt(&mut f, "bound_intent", |v| {
                Digest::from_value(v).ok_or(ModelError::Shape)
            })?,
            bound_instance: opt(&mut f, "bound_instance", Id::from_value)?,
            bound_resource: opt(&mut f, "bound_resource", ResourceRef::from_value)?,
            supersedes: opt(&mut f, "supersedes", Id::from_value)?,
        };
        f.done()?;
        Ok(s)
    }
}

/// Why a Claim is refused (protocol error, not recorded; L2-CLM-1, L2-CLM-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// The signature, header or key does not verify.
    #[error("signature: {0}")]
    Signature(cose::CoseError),
    /// The payload is not a `claim-statement` for this domain.
    #[error("payload: {0}")]
    Payload(ModelError),
}

impl ClaimError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Signature(_) => "claim-signature",
            Self::Payload(_) => "claim-payload",
        }
    }
}

/// The `ClaimID`: the first 16 bytes of the digest of the bytes as received (L2-CLM-1).
#[must_use]
pub fn claim_id(sign1: &[u8]) -> Id {
    let d = context_digest(CONTEXT, sign1);
    let mut out = [0; 16];
    out.copy_from_slice(&d.0[..16]);
    Id(out)
}

/// The digest of the Claim bytes under `access/claim/v1`.
#[must_use]
pub fn claim_digest(sign1: &[u8]) -> Digest {
    Digest(context_digest(CONTEXT, sign1).0)
}

/// The `kid` of the protected header, to find the signing Instance.
///
/// # Errors
/// [`ClaimError::Signature`] when the message or header does not parse.
pub fn kid(sign1: &[u8]) -> Result<[u8; 32], ClaimError> {
    let msg = cose::parse_sign1(sign1).map_err(ClaimError::Signature)?;
    let Ok(Value::Map(header)) = dcbor::decode(&msg.protected, Limits::CEILING) else {
        return Err(ClaimError::Payload(ModelError::Shape));
    };
    header
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Unsigned(cose::KID), Value::Bytes(b)) => {
                <[u8; 32]>::try_from(b.as_slice()).ok()
            }
            _ => None,
        })
        .ok_or(ClaimError::Payload(ModelError::Shape))
}

/// Verifies `sign1` under the signing Instance's current `key`, which belongs to `party`, and
/// checks that the Claim is for `domain` and issued by `party` (L2-CLM-1, L2-CLM-2).
///
/// # Errors
/// [`ClaimError`].
pub fn verify(
    sign1: &[u8],
    key: &PublicKey,
    party: &Id,
    domain: &Digest,
) -> Result<Statement, ClaimError> {
    let mut keys = KeySet::default();
    keys.insert(thumbprint(key), key.clone())
        .map_err(|e| ClaimError::Signature(cose::CoseError::Signature(e)))?;
    keys.allowed
        .extend([Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256]);
    let verified = cose::verify_sign1(&PureBackend, sign1, &keys, CONTENT_TYPE)
        .map_err(ClaimError::Signature)?;
    let value = dcbor::decode(&verified.payload, Limits::CEILING)
        .map_err(|e| ClaimError::Payload(ModelError::Cbor(e)))?;
    let s = Statement::from_value(&value).map_err(ClaimError::Payload)?;
    if s.domain != *domain || s.issuer != *party {
        return Err(ClaimError::Payload(ModelError::Range));
    }
    Ok(s)
}

/// What decides whether a Claim is admitted: the parts of an `acceptance-content` (§9.13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate {
    /// Issuer Party; pinned key sets are not used in this version.
    pub issuer: Option<Id>,
    /// The use.
    pub use_: String,
    /// Classes.
    pub classes: Vec<String>,
    /// Subjects.
    pub subject: SubjectSelector,
    /// Assurance floor.
    pub floor: BTreeMap<String, u64>,
    /// Validity.
    pub validity: Window,
    /// Last ingest time.
    pub ingest_until: Option<u64>,
    /// Last signing time (OP-141 m.21 (c)).
    pub issued_until: Option<u64>,
    /// Declared quota: Claims per window of seconds (OP-141 m.21 (a)).
    pub quota: Option<(u64, u64)>,
}

/// Domain default quota when an Acceptance declares none: Claims per window (PD).
pub const DEFAULT_QUOTA: (u64, u64) = (1_000, 3_600);

/// Kind of the issuer quota counter (OP-141 m.21 (a)).
pub const QUOTA: &str = "quota";

impl Gate {
    /// The gate of an Acceptance's content.
    ///
    /// # Errors
    /// [`ModelError`] for content that is not an `acceptance-content`.
    pub fn of(content: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(content)?;
        let issuer = match f.req("issuer")? {
            v @ Value::Bytes(_) => Some(Id::from_value(v)?),
            _ => None,
        };
        let classes = crate::codec::set_items(f.req("classes")?, true)?
            .iter()
            .map(ident)
            .collect::<Result<Vec<_>, _>>()?;
        let g = Self {
            issuer,
            use_: String::from(crate::codec::text(f.req("use")?)?),
            classes,
            subject: SubjectSelector::from_value(f.req("subject")?)?,
            floor: assurance(f.opt("assurance_floor"))?,
            validity: Window::from_value(f.req("validity")?)?,
            ingest_until: f.opt("ingest_until").map(uint).transpose()?,
            issued_until: f.opt("issued_until").map(uint).transpose()?,
            quota: f.opt("quota").map(quota).transpose()?,
        };
        let _ = f.opt("anchor");
        f.done()?;
        Ok(g)
    }

    /// Whether this gate admits `s` as a predicate input at time `at` (L2-CLM-3).
    #[must_use]
    pub fn admits(&self, s: &Statement, at: u64) -> bool {
        self.admits_for(PREDICATE_INPUT, s, at)
    }

    /// Whether this gate admits `s` for `use_` at time `at` (L2-CLM-3, OP-141 m.20 (a)).
    #[must_use]
    pub fn admits_for(&self, use_: &str, s: &Statement, at: u64) -> bool {
        let subject = match &self.subject {
            SubjectSelector::Public => true,
            SubjectSelector::Party(p) => *p == s.subject,
            _ => false,
        };
        self.use_ == use_
            && self.issuer == Some(s.issuer)
            && self.classes.contains(&s.class)
            && subject
            && self.validity.from <= at
            && at <= self.validity.until
            && self.ingest_until.is_none_or(|u| at <= u)
            && self.issued_until.is_none_or(|u| s.issued_at <= u)
            && self.floor.iter().all(|(dim, floor)| {
                s.assurance
                    .get(dim)
                    .is_some_and(|level| meets_floor(dim, *floor, *level))
            })
    }
}

/// A Claim's disposition (L2-CLM-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Admitted: a proof.
    Admit,
    /// No Acceptance covers it.
    SourceNotAccepted,
    /// Signed too far ahead of trusted time.
    Future,
    /// The issuer's quota is used up (OP-141 m.21 (a)).
    Quota,
}

impl Disposition {
    /// The `claim-fields` word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::SourceNotAccepted => "quarantine:source-not-accepted",
            Self::Future => "quarantine:future",
            Self::Quota => "quarantine:quota",
        }
    }
}

/// The disposition of `s` at trusted time `now` under the domain's live `gates` (L2-CLM-3).
#[must_use]
pub fn disposition(s: &Statement, gates: &[Gate], now: u64) -> Disposition {
    if s.issued_at > now.saturating_add(SKEW_MS) {
        Disposition::Future
    } else if gates
        .iter()
        .any(|g| g.admits_for(PREDICATE_INPUT, s, now) || g.admits_for(SUBJECT_SELECTION, s, now))
    {
        Disposition::Admit
    } else {
        Disposition::SourceNotAccepted
    }
}

fn quota(v: &Value) -> Result<(u64, u64), ModelError> {
    let mut f = Fields::of(v)?;
    let q = (uint(f.req("count")?)?, uint(f.req("window_s")?)?);
    f.done()?;
    if q.0 == 0 || q.1 == 0 {
        return Err(ModelError::Range);
    }
    Ok(q)
}

/// The quota a Claim admitted by `gates` draws from: the most generous one among the gates that
/// admit it, the default when one of them declares none, as `(limit, window_ms)` with the
/// limit twice the declared count (§13.7.4, OP-141 m.21 (a)).
#[must_use]
pub fn quota_of(s: &Statement, gates: &[Gate], now: u64) -> Option<(u64, u64)> {
    gates
        .iter()
        .filter(|g| {
            g.admits_for(PREDICATE_INPUT, s, now) || g.admits_for(SUBJECT_SELECTION, s, now)
        })
        .map(|g| g.quota.unwrap_or(DEFAULT_QUOTA))
        .max()
        .map(|(count, window_s)| (count.saturating_mul(2), window_s.saturating_mul(1_000)))
}

/// `dCBOR(["quota", issuer, window start])`: the issuer's counter for the window holding `now`.
#[must_use]
pub fn quota_key(issuer: &Id, window_ms: u64, now: u64) -> Vec<u8> {
    let start = now.saturating_sub(now.checked_rem(window_ms).unwrap_or(0));
    dcbor::encode(
        &Value::Array(alloc::vec![
            Value::text(QUOTA),
            issuer.to_value(),
            Value::Unsigned(start)
        ]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// Whether `new` only narrows the Acceptance `old` (OP-141 m.21 (d)): then the amend is not
/// expansion class.
#[must_use]
pub fn narrows(old: &Gate, new: &Gate) -> bool {
    let earlier = |n: Option<u64>, o: Option<u64>| match (n, o) {
        (_, None) => true,
        (Some(n), Some(o)) => n <= o,
        (None, Some(_)) => false,
    };
    let quota = match (new.quota, old.quota) {
        (None, None) => true,
        (Some((nc, nw)), Some((oc, ow))) => nc <= oc && nw >= ow,
        (Some((nc, nw)), None) => nc <= DEFAULT_QUOTA.0 && nw >= DEFAULT_QUOTA.1,
        (None, Some(_)) => false,
    };
    new.classes.iter().all(|c| old.classes.contains(c))
        && crate::algebra::subject_le(&new.subject, &old.subject)
        && old.floor.iter().all(|(dim, f)| {
            new.floor
                .get(dim)
                .is_some_and(|nf| meets_floor(dim, *f, *nf))
        })
        && new.validity.from >= old.validity.from
        && new.validity.until <= old.validity.until
        && earlier(new.ingest_until, old.ingest_until)
        && earlier(new.issued_until, old.issued_until)
        && quota
}

/// A recorded Claim (`claim-state`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimState {
    /// What was claimed; `domain` is the record's, `issued_at` is 0 for a domain-issued Claim.
    pub statement: Statement,
    /// The Instance that signed it; `None` for a domain-issued Claim.
    pub instance: Option<Id>,
    /// Position of the record.
    pub since: u64,
    /// End.
    pub ended: Option<crate::meta::Ended>,
}

impl Canonical for ClaimState {
    fn to_value(&self) -> Value {
        let s = &self.statement;
        map([
            ("issuer", Some(s.issuer.to_value())),
            ("subject", Some(s.subject.to_value())),
            ("class", Some(Value::text(&s.class))),
            ("value", s.value.as_ref().map(Canonical::to_value)),
            ("validity", Some(s.validity.to_value())),
            (
                "assurance",
                map_value(&s.assurance, |v| Value::Unsigned(*v)),
            ),
            (
                "bound_intent",
                s.bound_intent.as_ref().map(Canonical::to_value),
            ),
            (
                "bound_instance",
                s.bound_instance.as_ref().map(Canonical::to_value),
            ),
            (
                "bound_resource",
                s.bound_resource.as_ref().map(Canonical::to_value),
            ),
            (
                "issued_at",
                (s.issued_at > 0).then_some(Value::Unsigned(s.issued_at)),
            ),
            ("instance", self.instance.as_ref().map(Canonical::to_value)),
            ("since", Some(Value::Unsigned(self.since))),
            ("ended", self.ended.as_ref().map(crate::meta::ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let assurance = assurance(f.opt("assurance"))?;
        let statement = Statement {
            domain: Digest([0; 32]),
            issuer: Id::from_value(f.req("issuer")?)?,
            subject: Id::from_value(f.req("subject")?)?,
            class: ident(f.req("class")?)?,
            value: opt(&mut f, "value", EqValue::from_value)?,
            issued_at: f.opt("issued_at").map(uint).transpose()?.unwrap_or(0),
            validity: Window::from_value(f.req("validity")?)?,
            assurance,
            bound_intent: opt(&mut f, "bound_intent", |v| {
                Digest::from_value(v).ok_or(ModelError::Shape)
            })?,
            bound_instance: opt(&mut f, "bound_instance", Id::from_value)?,
            bound_resource: opt(&mut f, "bound_resource", ResourceRef::from_value)?,
            supersedes: None,
        };
        let s = Self {
            statement,
            instance: opt(&mut f, "instance", Id::from_value)?,
            since: uint(f.req("since")?)?,
            ended: crate::meta::ended(f.opt("ended"))?,
        };
        f.done()?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests;
