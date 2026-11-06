//! Party status lookup (OP-149 m.28 (c)): a Party's actor kind and the ledger points that
//! admitted and ended it, read from the domain's state at a ledger position. The answer's
//! canonical form is the `party-lookup` payload of `conformance/cddl/party-lookup.cddl`, signed
//! by the domain's operational key with usage `party-lookup`; the key lookup's twin (m.5).

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::meta::{ActorKind, PartyState};
use access_kernel::model::Id;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::keys::{Point, point, text};

/// Most Parties one batch asks for (OP-149 m.28 (c); as `keys:batchGet`, PD).
pub const MAX_PARTIES: usize = 100;

/// Content type of the signed lookup payload.
pub const CONTENT_TYPE: &str = "application/access-party-lookup+cbor";

/// One Party as the lookup answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyEntry {
    /// The Party.
    pub party: Id,
    /// Its actor kind; `party_register` sets it and nothing changes it (OP-149 m.8).
    pub actor_kind: ActorKind,
    /// The record that admitted it.
    pub since: Point,
    /// The record that ended it (`party_depart`, termination), once it has.
    pub ended: Option<Point>,
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
    /// The Parties known at `pos`, in the order asked.
    pub parties: Vec<PartyEntry>,
    /// The Parties not known at `pos`, in the order asked.
    pub unknown: Vec<Id>,
}

/// `state` of `party` as it stood at `pos`, with the trusted times of its admitting record
/// (`since_at`) and its ending record (`ended_at`); `None` before it was admitted. An end after
/// `pos` has not happened at `pos`.
#[must_use]
pub fn entry(
    party: Id,
    state: &PartyState,
    pos: u64,
    since_at: u64,
    ended_at: Option<u64>,
) -> Option<PartyEntry> {
    if state.since > pos {
        return None;
    }
    let ended = state
        .ended
        .as_ref()
        .filter(|e| e.at <= pos)
        .zip(ended_at)
        .map(|(e, at)| Point { pos: e.at, at });
    Some(PartyEntry {
        party,
        actor_kind: state.actor_kind,
        since: Point {
            pos: state.since,
            at: since_at,
        },
        ended,
    })
}

fn entry_value(e: &PartyEntry) -> Value {
    let mut m = vec![
        text("party", e.party.to_value()),
        text("actor_kind", Value::text(e.actor_kind.name())),
        text("since", point(e.since)),
    ];
    if let Some(p) = e.ended {
        m.push(text("ended", point(p)));
    }
    Value::Map(m)
}

/// The `party-lookup` payload of `lookup` (`conformance/cddl/party-lookup.cddl`).
#[must_use]
pub fn payload(lookup: &Lookup) -> Vec<u8> {
    let value = Value::Map(vec![
        text("domain", lookup.domain.to_value()),
        text("pos", Value::Unsigned(lookup.pos)),
        text("iat", Value::Unsigned(lookup.iat)),
        text(
            "parties",
            Value::Array(lookup.parties.iter().map(entry_value).collect()),
        ),
        text(
            "unknown",
            Value::Array(lookup.unknown.iter().map(Canonical::to_value).collect()),
        ),
    ]);
    dcbor::encode(&value, Limits::CEILING).unwrap_or_default()
}

#[cfg(test)]
mod tests;
