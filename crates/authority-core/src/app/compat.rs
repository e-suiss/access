//! Compatibility mappings in force (E10, P24, PI-19, §9.13.4, SEC16, OP-157 m.3 (r)).
//!
//! A publisher declares mappings in its publication's compatibility declaration; that is a
//! statement only. A domain uses a mapping once a live `schema-definition` Acceptance of the
//! namespace pins its digest, which only a reserved `acceptance.amend` (or a new Acceptance) of
//! the domain does (C18). Pinning keeps the mapping's bytes with the record, so the decisions
//! that rely on it, and their explanations, read the same bytes. Revoking the Acceptance drops
//! the pin. For the probation days after a pin, a CT2+ Exercise covered only through the
//! mapping needs an approval (SEC16).

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::ports::DomainLog;
use access_kernel::codec::Canonical;
use access_kernel::compat::{self, Mapping};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::{self, ContentState, Payload, View as _, kind};
use access_kernel::model::{Id, Window};
use access_kernel::schema::{Spp, schemas_key};
use suiss_crypto::dcbor::Value;

use super::{Authority, MAX_PASSES};
use crate::CoreError;
use crate::domain::{Request, Snapshot, read};
use crate::ports::{Binding, Reader, Salts};

/// The policy default that sets the probation (OP-157 m.3 (n)).
pub const PROBATION_DAYS: &str = "mapping_probation_days";

/// Probation in days when the domain set none (SEC16, OP-157 m.8 (m), PD).
pub const PROBATION_DEFAULT_DAYS: u64 = 14;

const DAY_S: u64 = 86_400;

/// A pinned mapping with the time of its pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pinned {
    /// The mapping.
    pub mapping: Mapping,
    /// Its digest, the one the Acceptance pins.
    pub digest: Digest,
    /// When the Acceptance that pins it last widened, Unix milliseconds.
    pub at: u64,
}

fn live(state: &ContentState, now: u64) -> bool {
    state.ended.is_none()
        && state
            .content
            .get("validity")
            .and_then(|w| Window::from_value(w).ok())
            .is_some_and(|w| w.from <= now && now <= w.until)
}

fn digests(content: &Value) -> Vec<Digest> {
    match content.get("mappings") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|d| <Digest as Canonical>::from_value(d).ok())
            .collect(),
        _ => Vec::new(),
    }
}

/// The mapping digests the live `schema-definition` Acceptances of `namespace` pin at `now`,
/// each with the position its Acceptance last widened at (OP-157 m.3 (r)); a digest two of them
/// pin keeps the later position.
pub(crate) fn pins(view: &Snapshot, namespace: &str, now: u64) -> BTreeMap<Digest, u64> {
    let ids = match view.get(&schemas_key(namespace)) {
        Some(Value::Array(ids)) => ids,
        _ => Vec::new(),
    };
    let mut out = BTreeMap::new();
    for a in ids
        .iter()
        .filter_map(|v| Id::from_value(v).ok())
        .filter_map(|id| read::<ContentState>(view, kind::ACCEPTANCE, &id))
        .filter(|a| live(a, now))
    {
        let at = a.widened.unwrap_or(a.since);
        for d in digests(&a.content) {
            let e = out.entry(d).or_insert(at);
            *e = (*e).max(at);
        }
    }
    out
}

/// The probation of the domain `view` reads, in seconds (OP-157 m.3 (n), (r)).
pub(crate) fn probation_s(view: &Snapshot) -> u64 {
    match view.get(&meta::policy_default_key(PROBATION_DAYS)) {
        Some(Value::Unsigned(days)) => days,
        _ => PROBATION_DEFAULT_DAYS,
    }
    .saturating_mul(DAY_S)
}

/// `derived.mapping_pin_age_s` of `intent` (§16.5 (5), SEC16, OP-157 m.3 (o), (r)): the age in
/// seconds of the youngest pin still in probation of a mapping that applies to `intent`; −1 when
/// there is none.
#[must_use]
pub fn pin_age_s(pinned: &[Pinned], intent: &IntentEnvelope, probation_s: u64, now: u64) -> i64 {
    pinned
        .iter()
        .filter(|p| compat::apply(&p.mapping, intent).is_some())
        .map(|p| now.saturating_sub(p.at) / 1_000)
        .filter(|age| *age < probation_s)
        .min()
        .map_or(-1, |age| i64::try_from(age).unwrap_or(i64::MAX))
}

/// The mapping digests a `schema-definition` Acceptance content names, with the SPP it accepts.
fn named(content: &Value) -> Option<(Spp, Vec<Digest>)> {
    if content.get("use") != Some(&Value::text("schema-definition")) {
        return None;
    }
    let ds = digests(content);
    if ds.is_empty() {
        return None;
    }
    let spp = content.get("spp").and_then(|v| Spp::from_value(v).ok())?;
    Some((spp, ds))
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The mappings pinned for the action of `req` at `now`, with their pin times: none for a
    /// meta-action (OP-157 m.3 (r)). A pinned digest whose bytes were not kept is left out, so it
    /// changes no coverage.
    ///
    /// # Errors
    /// The reader's errors; [`CoreError::Passes`].
    pub(crate) async fn pinned_mappings(
        &self,
        req: &Request,
        now: u64,
    ) -> Result<Vec<Pinned>, CoreError> {
        let action = &req.intent.action;
        if req.payload.is_some() || action.namespace == meta::NAMESPACE {
            return Ok(Vec::new());
        }
        let mut snap = Snapshot::default();
        let mut found = None;
        for _ in 0..MAX_PASSES {
            snap.restart();
            let out = pins(&snap, &action.namespace, now);
            let keys = snap.missing();
            if keys.is_empty() {
                found = Some(out);
                break;
            }
            snap.fill(self.fetch(&keys).await?);
        }
        let pins = found.ok_or(CoreError::Passes)?;
        let mut out = Vec::new();
        for (digest, pos) in pins {
            let Some(bytes) = self.reader.proof(&digest.0).await? else {
                continue;
            };
            let Ok(mapping) = Mapping::from_bytes(&bytes) else {
                continue;
            };
            if compat::mapping_digest(&mapping).ok() != Some(digest) || mapping.to != *action {
                continue;
            }
            let at = self.reader.recorded_at(pos).await?.unwrap_or(now);
            out.push(Pinned {
                mapping,
                digest,
                at,
            });
        }
        Ok(out)
    }

    /// The bytes of each mapping a `schema-definition` Acceptance of `req` pins, kept with its
    /// record (OP-157 m.3 (r), C18): each pinned digest must be a mapping the namespace's
    /// publisher declared, into a version of the accepted package. Empty for any other request.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `mapping-unknown` for a digest no publication of the namespace
    /// declares; the reader's errors.
    pub(crate) async fn pinned_bodies(
        &self,
        req: &Request,
    ) -> Result<Vec<([u8; 32], Vec<u8>)>, CoreError> {
        let Some(Payload::AcceptanceEstablish(content) | Payload::AcceptanceAmend { content, .. }) =
            &req.payload
        else {
            return Ok(Vec::new());
        };
        let Some((spp, wanted)) = named(content) else {
            return Ok(Vec::new());
        };
        let targets: BTreeSet<_> = spp.refs().into_iter().map(|(r, _)| r).collect();
        let mut declared: BTreeMap<Digest, Vec<u8>> = BTreeMap::new();
        for bytes in self.reader.publications(&spp.namespace).await? {
            let Ok(p) = super::publishing::Publication::from_bytes(&bytes) else {
                continue;
            };
            if p.spp.publisher != spp.publisher || p.spp.namespace != spp.namespace {
                continue;
            }
            for m in p.compatibility.iter().flat_map(|c| c.mappings.iter()) {
                if !targets.contains(&m.to) {
                    continue;
                }
                if let (Ok(d), Ok(b)) = (compat::mapping_digest(m), m.to_bytes()) {
                    declared.insert(d, b);
                }
            }
        }
        wanted
            .into_iter()
            .map(|d| {
                declared
                    .get(&d)
                    .map(|b| (d.0, b.clone()))
                    .ok_or(CoreError::Protocol("mapping-unknown"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
