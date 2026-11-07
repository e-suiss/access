//! Semantic events the authority plane derives from a committed record (§9.16, OP-130 m.9,
//! OP-149 m.7). The sequencer writes them to `authority_outbox` with the record; the identity
//! plane's transmitter reads them, signs them as SETs and delivers them. They are signals for a
//! re-query, never authority (PI-9).
//!
//! The outbox bytes are deterministic CBOR: a map with `type`, `domain`, `source`, `subject`,
//! `at`, and the fields the type adds.

use access_kernel::digest::Digest;
use access_kernel::model::Id;
use suiss_crypto::dcbor::{self, Limits, Value};

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// `grant_revoke`, `grant_renounce`: a Grant ended.
    AuthorityRevoked,
    /// `grant_amend`, a policy change: a Grant now allows less.
    AuthorityNarrowed,
    /// A Grant or Mandate reached the end of its validity.
    AuthorityExpired,
    /// `mandate_revoke`: a Mandate ended.
    MandateEnded,
    /// `instance_terminate`, `instance_recover`: an Instance ended.
    InstanceTerminated,
    /// A validity condition or policy changed: re-ask.
    RevalidationRequired,
    /// A projection's bounds no longer hold.
    ProjectionInvalidated,
    /// `acceptance_amend`, `acceptance_revoke`: what the domain takes from an issuer changed.
    AcceptanceChanged,
    /// `party_depart` or a suspension (OP-149 m.7).
    PartyDisabled,
    /// An admitted `party_compromise` Claim (OP-149 m.7, SI-9).
    PartyCompromised,
}

impl Kind {
    /// Every kind, in order.
    pub const ALL: [Self; 10] = [
        Self::AuthorityRevoked,
        Self::AuthorityNarrowed,
        Self::AuthorityExpired,
        Self::MandateEnded,
        Self::InstanceTerminated,
        Self::RevalidationRequired,
        Self::ProjectionInvalidated,
        Self::AcceptanceChanged,
        Self::PartyDisabled,
        Self::PartyCompromised,
    ];

    /// The event name; the type URN is `urn:suiss:access:event:<name>`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AuthorityRevoked => "authority-revoked",
            Self::AuthorityNarrowed => "authority-narrowed",
            Self::AuthorityExpired => "authority-expired",
            Self::MandateEnded => "mandate-ended",
            Self::InstanceTerminated => "instance-terminated",
            Self::RevalidationRequired => "revalidation-required",
            Self::ProjectionInvalidated => "projection-invalidated",
            Self::AcceptanceChanged => "acceptance-changed",
            Self::PartyDisabled => "party.disabled",
            Self::PartyCompromised => "party.compromised",
        }
    }

    /// The kind named `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// Where the event comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The Exercise whose decision recorded it.
    Exercise(Digest),
    /// The Claim whose record admitted it.
    Claim(Id),
}

/// What it is about: the reference a receiver re-queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A Grant.
    Grant(Id),
    /// A Mandate.
    Mandate(Id),
    /// An Instance.
    Instance(Id),
    /// A Party.
    Party(Id),
    /// A policy.
    Policy(Id),
    /// An Acceptance.
    Acceptance(Id),
    /// A projection, by its digest.
    Projection(Digest),
}

impl Subject {
    /// The subject kind's name.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Grant(_) => "grant",
            Self::Mandate(_) => "mandate",
            Self::Instance(_) => "instance",
            Self::Party(_) => "party",
            Self::Policy(_) => "policy",
            Self::Acceptance(_) => "acceptance",
            Self::Projection(_) => "projection",
        }
    }

    /// The reference bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Grant(i)
            | Self::Mandate(i)
            | Self::Instance(i)
            | Self::Party(i)
            | Self::Policy(i)
            | Self::Acceptance(i) => &i.0,
            Self::Projection(d) => &d.0,
        }
    }
}

/// Why a Party is disabled (OP-149 m.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasonClass {
    /// `party_depart`.
    Departed,
    /// Suspended.
    Suspended,
    /// Anything else.
    Other,
}

impl ReasonClass {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Departed => "departed",
            Self::Suspended => "suspended",
            Self::Other => "other",
        }
    }

    fn from_name(n: &str) -> Option<Self> {
        [Self::Departed, Self::Suspended, Self::Other]
            .into_iter()
            .find(|r| r.name() == n)
    }
}

/// What a kind adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detail {
    /// Nothing.
    None,
    /// `instance-terminated`: the Instance's Party.
    Instance {
        /// Its Party.
        party: Id,
    },
    /// `party.disabled`.
    Disabled {
        /// Reason class.
        reason: ReasonClass,
    },
    /// `party.compromised`: the window runs from `occurred_at` to the declaration's commit.
    Compromised {
        /// The Party's Instances the window covers, with their key's RFC 7638 thumbprint.
        keys: Vec<(Id, [u8; 32])>,
        /// When the compromise began, as declared; `None` when unknown.
        occurred_at: Option<u64>,
        /// Start of the window, Unix ms: the value the Kernel overlay uses (OP-149 m.17 (d),
        /// OP-141 m.31 (b)), so a consumer never computes it.
        window_from: u64,
        /// When the declaration committed, Unix ms.
        declared_at: u64,
        /// Digest of the declaring Claim.
        evidence: Digest,
    },
}

/// One semantic event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Its kind.
    pub kind: Kind,
    /// The domain whose record it derives from.
    pub domain: Digest,
    /// The Exercise or Claim it comes from.
    pub source: Source,
    /// What it is about.
    pub subject: Subject,
    /// Effective time, Unix ms.
    pub at: u64,
    /// What the kind adds.
    pub detail: Detail,
}

/// Bytes that are not an [`Event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed semantic event")]
pub struct Malformed;

/// The window start of a compromise declaration (OP-149 m.17 (d), OP-141 m.31 (b), SI-9): the
/// declared `occurred_at`, or the Claim's `issued_at` − 72 h when it is unknown; the Kernel
/// overlay and the `party.compromised` event both use it.
#[must_use]
pub const fn compromise_from(occurred_at: Option<u64>, issued_at: u64) -> u64 {
    match occurred_at {
        Some(t) => t,
        None => issued_at.saturating_sub(COMPROMISE_LOOKBACK_MS),
    }
}

/// The look-back of a compromise without a known start: 72 hours (SI-9, §13.7.7).
pub const COMPROMISE_LOOKBACK_MS: u64 = access_kernel::claim::COMPROMISE_LOOKBACK_MS;

fn text(s: &str) -> Value {
    Value::text(s)
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn get<'a>(v: &'a Value, k: &str) -> Result<&'a Value, Malformed> {
    v.get(k).ok_or(Malformed)
}

fn as_text(v: &Value) -> Result<&str, Malformed> {
    match v {
        Value::Text(t) => Ok(t),
        _ => Err(Malformed),
    }
}

fn as_bytes<const N: usize>(v: &Value) -> Result<[u8; N], Malformed> {
    match v {
        Value::Bytes(b) => <[u8; N]>::try_from(b.as_slice()).map_err(|_| Malformed),
        _ => Err(Malformed),
    }
}

fn as_u64(v: &Value) -> Result<u64, Malformed> {
    match v {
        Value::Unsigned(u) => Ok(*u),
        _ => Err(Malformed),
    }
}

fn pair(v: &Value) -> Result<(&str, &Value), Malformed> {
    match v {
        Value::Array(a) => match a.as_slice() {
            [k, b] => Ok((as_text(k)?, b)),
            _ => Err(Malformed),
        },
        _ => Err(Malformed),
    }
}

impl Event {
    /// `projection-invalidated` (§9.16, §9.9.3 k.6, P50): the projection family whose first
    /// `projection.issue` was `root` no longer holds, because of `source`, effective `at`. The one
    /// constructor every path that ends a family uses, so receivers see one shape.
    #[must_use]
    pub const fn projection_invalidated(
        domain: Digest,
        source: Source,
        root: Digest,
        at: u64,
    ) -> Self {
        Self {
            kind: Kind::ProjectionInvalidated,
            domain,
            source,
            subject: Subject::Projection(root),
            at,
            detail: Detail::None,
        }
    }

    /// `authority-expired` (§9.16): the Grant or Mandate `subject`, issued by `source`, reached
    /// the end of its validity `at`. Informational: expiry is deterministic and needs no signal.
    #[must_use]
    pub const fn authority_expired(
        domain: Digest,
        source: Source,
        subject: Subject,
        at: u64,
    ) -> Self {
        Self {
            kind: Kind::AuthorityExpired,
            domain,
            source,
            subject,
            at,
            detail: Detail::None,
        }
    }

    /// The canonical CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let source = match self.source {
            Source::Exercise(d) => Value::Array(vec![text("exercise"), bytes(&d.0)]),
            Source::Claim(i) => Value::Array(vec![text("claim"), bytes(&i.0)]),
        };
        let mut m = vec![
            (text("type"), text(self.kind.name())),
            (text("domain"), bytes(&self.domain.0)),
            (text("source"), source),
            (
                text("subject"),
                Value::Array(vec![text(self.subject.kind()), bytes(self.subject.bytes())]),
            ),
            (text("at"), Value::Unsigned(self.at)),
        ];
        match &self.detail {
            Detail::None => {}
            Detail::Instance { party } => m.push((text("party"), bytes(&party.0))),
            Detail::Disabled { reason } => m.push((text("reason"), text(reason.name()))),
            Detail::Compromised {
                keys,
                occurred_at,
                window_from,
                declared_at,
                evidence,
            } => {
                m.push((
                    text("keys"),
                    Value::Array(
                        keys.iter()
                            .map(|(i, k)| Value::Array(vec![bytes(&i.0), bytes(k)]))
                            .collect(),
                    ),
                ));
                if let Some(t) = occurred_at {
                    m.push((text("occurred_at"), Value::Unsigned(*t)));
                }
                m.push((text("window_from"), Value::Unsigned(*window_from)));
                m.push((text("declared_at"), Value::Unsigned(*declared_at)));
                m.push((text("evidence"), bytes(&evidence.0)));
            }
        }
        Value::Map(m)
    }

    /// The outbox bytes.
    ///
    /// # Errors
    /// [`Malformed`] when the value is outside the CBOR limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Malformed> {
        dcbor::encode(&self.to_value(), Limits::CEILING).map_err(|_| Malformed)
    }

    /// Reads outbox bytes.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Malformed> {
        let map = dcbor::decode(raw, Limits::CEILING).map_err(|_| Malformed)?;
        let kind = Kind::from_name(as_text(get(&map, "type")?)?).ok_or(Malformed)?;
        let source = match pair(get(&map, "source")?)? {
            ("exercise", raw) => Source::Exercise(Digest(as_bytes(raw)?)),
            ("claim", raw) => Source::Claim(Id(as_bytes(raw)?)),
            _ => return Err(Malformed),
        };
        let subject = match pair(get(&map, "subject")?)? {
            ("grant", raw) => Subject::Grant(Id(as_bytes(raw)?)),
            ("mandate", raw) => Subject::Mandate(Id(as_bytes(raw)?)),
            ("instance", raw) => Subject::Instance(Id(as_bytes(raw)?)),
            ("party", raw) => Subject::Party(Id(as_bytes(raw)?)),
            ("policy", raw) => Subject::Policy(Id(as_bytes(raw)?)),
            ("acceptance", raw) => Subject::Acceptance(Id(as_bytes(raw)?)),
            ("projection", raw) => Subject::Projection(Digest(as_bytes(raw)?)),
            _ => return Err(Malformed),
        };
        let detail = match kind {
            Kind::InstanceTerminated => match map.get("party") {
                Some(party) => Detail::Instance {
                    party: Id(as_bytes(party)?),
                },
                None => Detail::None,
            },
            Kind::PartyDisabled => Detail::Disabled {
                reason: ReasonClass::from_name(as_text(get(&map, "reason")?)?).ok_or(Malformed)?,
            },
            Kind::PartyCompromised => {
                let Value::Array(list) = get(&map, "keys")? else {
                    return Err(Malformed);
                };
                let keys = list
                    .iter()
                    .map(|entry| match entry {
                        Value::Array(item) => match item.as_slice() {
                            [instance, thumb] => Ok((Id(as_bytes(instance)?), as_bytes(thumb)?)),
                            _ => Err(Malformed),
                        },
                        _ => Err(Malformed),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Detail::Compromised {
                    keys,
                    occurred_at: map.get("occurred_at").map(as_u64).transpose()?,
                    window_from: as_u64(get(&map, "window_from")?)?,
                    declared_at: as_u64(get(&map, "declared_at")?)?,
                    evidence: Digest(as_bytes(get(&map, "evidence")?)?),
                }
            }
            _ => Detail::None,
        };
        Ok(Self {
            kind,
            domain: Digest(as_bytes(get(&map, "domain")?)?),
            source,
            subject,
            at: as_u64(get(&map, "at")?)?,
            detail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-149 m.7
    #[test]
    fn every_kind_round_trips() {
        let d = Digest([7; 32]);
        for kind in Kind::ALL {
            let detail = match kind {
                Kind::InstanceTerminated => Detail::Instance { party: Id([3; 16]) },
                Kind::PartyDisabled => Detail::Disabled {
                    reason: ReasonClass::Departed,
                },
                Kind::PartyCompromised => Detail::Compromised {
                    keys: vec![(Id([4; 16]), [5; 32])],
                    occurred_at: Some(1),
                    window_from: 1,
                    declared_at: 2,
                    evidence: Digest([6; 32]),
                },
                _ => Detail::None,
            };
            let e = Event {
                kind,
                domain: d,
                source: Source::Exercise(d),
                subject: Subject::Party(Id([1; 16])),
                at: 9,
                detail,
            };
            assert_eq!(Event::from_bytes(&e.to_bytes().unwrap()).unwrap(), e);
            assert_eq!(Kind::from_name(kind.name()), Some(kind));
        }
    }

    // OP-149 m.7, §9.16, §9.9.3 k.6, P50: the shared constructors give the kinds' one shape
    #[test]
    fn invalidated_and_expired_have_one_shape() {
        let d = Digest([7; 32]);
        let e = Event::projection_invalidated(d, Source::Exercise(d), Digest([2; 32]), 5);
        assert_eq!(
            (e.kind, e.subject, e.detail.clone()),
            (
                Kind::ProjectionInvalidated,
                Subject::Projection(Digest([2; 32])),
                Detail::None
            )
        );
        assert_eq!(Event::from_bytes(&e.to_bytes().unwrap()).unwrap(), e);
        let x = Event::authority_expired(d, Source::Exercise(d), Subject::Grant(Id([1; 16])), 6);
        assert_eq!(x.kind.name(), "authority-expired");
        assert_eq!(Event::from_bytes(&x.to_bytes().unwrap()).unwrap(), x);
    }

    // OP-149 m.7, SI-9
    #[test]
    fn compromise_window_falls_back_to_72_hours() {
        assert_eq!(compromise_from(Some(5), 1_000_000_000), 5);
        assert_eq!(
            compromise_from(None, 1_000_000_000),
            1_000_000_000 - 259_200_000
        );
        assert_eq!(compromise_from(None, 10), 0);
    }
}
