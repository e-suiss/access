//! Instance key lookup (OP-149 m.5, CR-24): a key's holder and state at a ledger position, from
//! the derived key index and the `party_compromise` overlay. The answer's canonical form is the
//! `key-lookup` payload of `conformance/cddl/key-lookup.cddl`, signed by the domain's operational
//! key with usage `key-lookup`.

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::meta::{self, InstanceState};
use access_kernel::model::Id;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_store::derived::{KeyChange, KeyRow};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::app::Compromise;

/// Most kids one batch asks for (OP-149 m.5, PD).
pub const MAX_KIDS: usize = 100;

/// Content type of the signed lookup payload.
pub const CONTENT_TYPE: &str = "application/access-key-lookup+cbor";

/// Where a lookup reads the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsOf {
    /// The head.
    Head,
    /// A ledger position.
    Position(u64),
    /// The last position recorded at or before this trusted time, in milliseconds.
    Time(u64),
}

/// A ledger position with its trusted time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    /// Position.
    pub pos: u64,
    /// Trusted time in milliseconds.
    pub at: u64,
}

/// The state of a key at the lookup's position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// Its Instance holds it.
    Active,
    /// Its Instance no longer holds it, or has ended.
    Ended,
    /// It was established inside a `party_compromise` window of its Party (SEC12).
    Compromised,
}

impl KeyState {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Ended => "ended",
            Self::Compromised => "compromised",
        }
    }
}

/// One key as the lookup answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    /// RFC 7638 thumbprint.
    pub kid: [u8; 32],
    /// The key.
    pub key: PublicKey,
    /// Its Instance's Party.
    pub party: Id,
    /// The Instance.
    pub instance: Id,
    /// From when the Instance holds it.
    pub since: Point,
    /// When it stopped holding it.
    pub ended: Option<Point>,
    /// The recovery successor, once ended.
    pub successor: Option<Id>,
    /// State.
    pub state: KeyState,
    /// The compromise that covers it.
    pub compromise: Option<Compromise>,
}

/// One lookup answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    /// Domain.
    pub domain: Digest,
    /// The ledger position it was answered at.
    pub pos: u64,
    /// Trusted time of the answer.
    pub iat: u64,
    /// The keys known at `pos`, in the order asked.
    pub keys: Vec<KeyEntry>,
    /// The kids not known at `pos`, in the order asked.
    pub unknown: Vec<[u8; 32]>,
}

/// The key index change one state effect at `pos`, recorded at `at`, makes: an Instance's
/// state puts its current key, and a removed thumbprint entry ends that key.
#[must_use]
pub fn change(
    kind: &str,
    id: &[u8],
    value: Option<&Value>,
    pos: u64,
    at: u64,
) -> Option<KeyChange> {
    match (kind, value) {
        (meta::kind::KEY, None) => Some(KeyChange::End {
            kid: <[u8; 32]>::try_from(id).ok()?,
            pos,
            at,
        }),
        (meta::kind::INSTANCE, Some(v)) => {
            let instance = <[u8; 16]>::try_from(id).ok()?;
            let state = InstanceState::from_value(v).ok()?;
            Some(KeyChange::Put(KeyRow {
                kid: thumbprint(&state.key),
                instance,
                party: state.party.0,
                public_key: dcbor::encode(&state.key.to_value(), Limits::CEILING).ok()?,
                since_pos: state.since,
                since_at: at,
                ended: state.ended.map(|e| (e.at, at)),
                successor: state.successor.map(|s| s.0),
                pos,
            }))
        }
        _ => None,
    }
}

/// `row` as it stood at `pos`, with the Party's `compromises`; `None` before it was held.
#[must_use]
pub fn entry(row: &KeyRow, pos: u64, compromises: &[Compromise]) -> Option<KeyEntry> {
    if row.since_pos > pos {
        return None;
    }
    let key = dcbor::decode(&row.public_key, Limits::CEILING)
        .ok()
        .and_then(|v| PublicKey::from_value(&v).ok())?;
    let ended = row
        .ended
        .filter(|(p, _)| *p <= pos)
        .map(|(pos, at)| Point { pos, at });
    let compromise = compromises
        .iter()
        .filter(|c| c.declared <= pos && row.since_at >= c.from)
        .min_by_key(|c| (c.from, c.declared))
        .copied();
    let state = match (compromise, ended) {
        (Some(_), _) => KeyState::Compromised,
        (None, Some(_)) => KeyState::Ended,
        (None, None) => KeyState::Active,
    };
    Some(KeyEntry {
        kid: row.kid,
        key,
        party: Id(row.party),
        instance: Id(row.instance),
        since: Point {
            pos: row.since_pos,
            at: row.since_at,
        },
        successor: ended.and(row.successor.map(Id)),
        ended,
        state,
        compromise,
    })
}

/// The COSE algorithm of `key` (RFC 9864).
#[must_use]
pub const fn alg(key: &PublicKey) -> i64 {
    match key {
        PublicKey::Ed25519(_) => -19,
        PublicKey::P256(_) => -9,
        PublicKey::MlDsa(a, _) => a.cose(),
    }
}

/// `key` as an RFC 9052 `COSE_Key`: OKP Ed25519, EC2 P-256 from its SEC1 point, or AKP.
#[must_use]
pub fn cose_key(key: &PublicKey) -> Value {
    let entries = match key {
        PublicKey::Ed25519(x) => vec![
            (Value::Unsigned(1), Value::Unsigned(1)),
            (Value::Unsigned(3), Value::int(-19)),
            (Value::int(-1), Value::Unsigned(6)),
            (Value::int(-2), Value::Bytes(x.to_vec())),
        ],
        PublicKey::P256(point) => {
            let (x, y) = point
                .get(1..33)
                .zip(point.get(33..65))
                .unwrap_or((&[][..], &[][..]));
            vec![
                (Value::Unsigned(1), Value::Unsigned(2)),
                (Value::Unsigned(3), Value::int(-9)),
                (Value::int(-1), Value::Unsigned(1)),
                (Value::int(-2), Value::Bytes(x.to_vec())),
                (Value::int(-3), Value::Bytes(y.to_vec())),
            ]
        }
        PublicKey::MlDsa(a, k) => vec![
            (Value::Unsigned(1), Value::Unsigned(7)),
            (Value::Unsigned(3), Value::int(a.cose())),
            (Value::int(-1), Value::Bytes(k.clone())),
        ],
    };
    Value::Map(entries)
}

fn text(k: &str, v: Value) -> (Value, Value) {
    (Value::text(k), v)
}

fn point(p: Point) -> Value {
    Value::Map(vec![
        text("pos", Value::Unsigned(p.pos)),
        text("at", Value::Unsigned(p.at)),
    ])
}

fn entry_value(e: &KeyEntry) -> Value {
    let mut m = vec![
        text("kid", Value::Bytes(e.kid.to_vec())),
        text("alg", Value::int(alg(&e.key))),
        text("public_key", cose_key(&e.key)),
        text("party", e.party.to_value()),
        text("instance", e.instance.to_value()),
        text("since", point(e.since)),
        text("key_state", Value::text(e.state.name())),
    ];
    if let Some(p) = e.ended {
        m.push(text("ended", point(p)));
    }
    if let Some(s) = e.successor {
        m.push(text("successor", s.to_value()));
    }
    if let Some(c) = e.compromise {
        m.push(text(
            "compromise",
            Value::Map(vec![
                text("from", Value::Unsigned(c.from)),
                text("declared_at", Value::Unsigned(c.declared_at)),
                text("source", c.claim.to_value()),
            ]),
        ));
    }
    Value::Map(m)
}

/// The `key-lookup` payload of `lookup` (`conformance/cddl/key-lookup.cddl`).
#[must_use]
pub fn payload(lookup: &Lookup) -> Vec<u8> {
    let value = Value::Map(vec![
        text("domain", lookup.domain.to_value()),
        text("pos", Value::Unsigned(lookup.pos)),
        text("iat", Value::Unsigned(lookup.iat)),
        text(
            "keys",
            Value::Array(lookup.keys.iter().map(entry_value).collect()),
        ),
        text(
            "unknown",
            Value::Array(
                lookup
                    .unknown
                    .iter()
                    .map(|k| Value::Bytes(k.to_vec()))
                    .collect(),
            ),
        ),
    ]);
    dcbor::encode(&value, Limits::CEILING).unwrap_or_default()
}

#[cfg(test)]
mod tests;
