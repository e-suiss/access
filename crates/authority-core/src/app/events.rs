//! The semantic events a commit derives (§9.16, OP-130 m.9, OP-149 m.7). They go to the outbox
//! with the record, in the same batch; the identity plane's transmitter delivers them. An event
//! is a re-query signal, never authority (PI-9).

use std::collections::BTreeMap;

use access_authority_sequencer::ports::DomainLog;
use access_internal_api::events::{
    Detail, Event, Kind, ReasonClass, Source, Subject, compromise_from,
};
use access_kernel::claim;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::meta::{self, Disposition, InstanceState, Payload, kind};
use access_kernel::model::{EqValue, Id};
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::{Authority, Proofs};
use crate::domain::Request;
use crate::ports::{Binding, Reader, Salts};

/// The events of one commit: those of its decision, recorded only on ALLOW, and those of each
/// admitted Claim by its id; with them the holder Instances the commit ends (§9.9.3 k.6), whose
/// live projection families the adapter revokes once the record is in.
#[derive(Clone, Debug, Default)]
pub(crate) struct Derived {
    pub(crate) decision: Vec<Vec<u8>>,
    pub(crate) claims: BTreeMap<Id, Vec<Vec<u8>>>,
    /// Holders the decision ends; only an ALLOW ends them.
    pub(crate) ended: Vec<Id>,
    /// Holders the admitted Claims end, whatever the decision.
    pub(crate) ended_by_claims: Vec<Id>,
}

fn encode(e: &Event) -> Result<Vec<u8>, CoreError> {
    e.to_bytes().map_err(|_| CoreError::Protocol("event"))
}

fn revoked(disposition: &BTreeMap<Id, Disposition>) -> impl Iterator<Item = Subject> + '_ {
    disposition
        .iter()
        .filter(|(_, d)| **d == Disposition::Revoke)
        .map(|(g, _)| Subject::Grant(*g))
}

/// The Instances a `party.compromised` event names: the holders the compromise ends (§9.9.3 k.6).
fn compromised(e: &Event) -> Vec<Id> {
    match &e.detail {
        Detail::Compromised { keys, .. } => keys.iter().map(|(id, _)| *id).collect(),
        _ => Vec::new(),
    }
}

/// OP-149 m.7: a declared `occurred_at` is a non-negative integer value.
/// A `party_compromise` Claim's declared occurredAt: a non-negative integer value.
pub(crate) fn occurred(value: Option<&EqValue>) -> Option<u64> {
    match value {
        Some(EqValue::Int(t)) => u64::try_from(*t).ok(),
        _ => None,
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The events of committing `req` at `now` as Exercise `exercise` with the Claims of
    /// `resolved`.
    pub(crate) async fn derived(
        &self,
        req: &Request,
        resolved: &Proofs,
        exercise: Digest,
        now: u64,
    ) -> Result<Derived, CoreError> {
        let mut out = Derived::default();
        let domain = req.domain;
        let mut events = self.decision_events(req, exercise, now).await?;
        out.ended = self.ended_by_decision(req, &events).await?;
        let source = Source::Exercise(exercise);
        events.extend(self.invalidations(domain, source, &out.ended, now).await?);
        for e in &events {
            out.decision.push(encode(e)?);
        }
        (out.claims, out.ended_by_claims) = self.claim_events(domain, resolved, now).await?;
        Ok(out)
    }

    /// The holder Instances a committed decision ends (§9.9.3 k.6, P50): the terminated or
    /// recovered Instance, a departing Party's live Instances, the Instances its compromise
    /// declaration names in `events`.
    async fn ended_by_decision(
        &self,
        req: &Request,
        events: &[Event],
    ) -> Result<Vec<Id>, CoreError> {
        Ok(match &req.payload {
            Some(
                Payload::InstanceTerminate { instance } | Payload::InstanceRecover { instance, .. },
            ) => vec![*instance],
            Some(Payload::PartyDepart { party, .. }) => self
                .live_instances(party)
                .await?
                .into_iter()
                .map(|(id, _)| id)
                .collect(),
            Some(Payload::ClaimIssue { class, .. }) if class == claim::PARTY_COMPROMISE => {
                events.iter().flat_map(compromised).collect()
            }
            _ => Vec::new(),
        })
    }

    /// The events of the decision, by the meta-action it commits.
    async fn decision_events(
        &self,
        req: &Request,
        exercise: Digest,
        now: u64,
    ) -> Result<Vec<Event>, CoreError> {
        let domain = req.domain;
        let source = Source::Exercise(exercise);
        let base = |kind, subject, detail| Event {
            kind,
            domain,
            source,
            subject,
            at: now,
            detail,
        };
        let mut events: Vec<Event> = Vec::new();
        match &req.payload {
            // §9.16: grant.revoke / renounce
            Some(Payload::GrantRevoke { grant } | Payload::GrantRenounce { grant }) => {
                events.push(base(
                    Kind::AuthorityRevoked,
                    Subject::Grant(*grant),
                    Detail::None,
                ));
            }
            // §9.16: grant.amend
            Some(Payload::GrantAmend { grant, .. }) => {
                events.push(base(
                    Kind::AuthorityNarrowed,
                    Subject::Grant(*grant),
                    Detail::None,
                ));
            }
            // §9.16: policy change
            Some(
                Payload::PolicySet {
                    policy: Some(policy),
                    ..
                }
                | Payload::PolicyRetire { policy },
            ) => {
                events.push(base(
                    Kind::RevalidationRequired,
                    Subject::Policy(*policy),
                    Detail::None,
                ));
            }
            Some(Payload::MandateRevoke { mandate }) => {
                events.push(base(
                    Kind::MandateEnded,
                    Subject::Mandate(*mandate),
                    Detail::None,
                ));
            }
            Some(
                Payload::InstanceTerminate { instance } | Payload::InstanceRecover { instance, .. },
            ) => {
                let party = self.instance(instance).await?.map(|i| i.party);
                events.push(base(
                    Kind::InstanceTerminated,
                    Subject::Instance(*instance),
                    party.map_or(Detail::None, |party| Detail::Instance { party }),
                ));
            }
            // OP-149 m.7
            Some(Payload::PartyDepart { party, disposition }) => {
                events.push(base(
                    Kind::PartyDisabled,
                    Subject::Party(*party),
                    Detail::Disabled {
                        reason: ReasonClass::Departed,
                    },
                ));
                for g in revoked(disposition) {
                    events.push(base(Kind::AuthorityRevoked, g, Detail::None));
                }
            }
            Some(
                Payload::AnchorTransfer { disposition, .. }
                | Payload::AnchorRetire { disposition, .. },
            ) => {
                for g in revoked(disposition) {
                    events.push(base(Kind::AuthorityRevoked, g, Detail::None));
                }
            }
            // OP-149 m.7: a domain's own declaration
            Some(Payload::ClaimIssue {
                subject,
                class,
                value,
                ..
            }) if class == claim::PARTY_COMPROMISE => {
                events.push(
                    self.compromise(
                        domain,
                        source,
                        *subject,
                        (occurred(Some(value)), 0),
                        now,
                        exercise,
                    )
                    .await?,
                );
            }
            _ => {}
        }
        Ok(events)
    }

    /// OP-149 m.7: the events of the admitted signed declarations, and the holder Instances
    /// an admitted compromise declaration ends (§9.9.3 k.6).
    pub(crate) async fn claim_events(
        &self,
        domain: Digest,
        resolved: &Proofs,
        now: u64,
    ) -> Result<(BTreeMap<Id, Vec<Vec<u8>>>, Vec<Id>), CoreError> {
        let mut out: BTreeMap<Id, Vec<Vec<u8>>> = BTreeMap::new();
        let mut ended: Vec<Id> = Vec::new();
        for c in &resolved.claims {
            if c.disposition == claim::Disposition::Admit
                && c.statement.class == claim::PARTY_COMPROMISE
            {
                let source = Source::Claim(c.id);
                let e = self
                    .compromise(
                        domain,
                        source,
                        c.statement.subject,
                        (occurred(c.statement.value.as_ref()), c.statement.issued_at),
                        now,
                        claim::claim_digest(&c.bytes),
                    )
                    .await?;
                let holders = compromised(&e);
                let entry = out.entry(c.id).or_default();
                entry.push(encode(&e)?);
                for invalidated in self.invalidations(domain, source, &holders, now).await? {
                    entry.push(encode(&invalidated)?);
                }
                ended.extend(holders);
            }
            // OP-149 m.7, m.19 (f), TN-49: a narrowing account status disables the Party
            if c.disposition == claim::Disposition::Admit
                && c.statement.class == "account_status"
                && matches!(&c.statement.value, Some(EqValue::Text(t))
                    if ["suspended", "deactivated", "tombstone"].contains(&t.as_str()))
            {
                let e = Event {
                    kind: Kind::PartyDisabled,
                    domain,
                    source: Source::Claim(c.id),
                    subject: Subject::Party(c.statement.subject),
                    at: now,
                    detail: Detail::Disabled {
                        reason: ReasonClass::Suspended,
                    },
                };
                out.entry(c.id).or_default().push(encode(&e)?);
            }
        }
        Ok((out, ended))
    }

    /// One `projection-invalidated` per live projection family of each of `holders`, because
    /// of `source` (§9.9.3 k.6, §9.16, P50): the family's first `projection.issue` is its
    /// subject. Written with the record that ends the holders, so a receiver sees the end and
    /// the invalidations together.
    async fn invalidations(
        &self,
        domain: Digest,
        source: Source,
        holders: &[Id],
        now: u64,
    ) -> Result<Vec<Event>, CoreError> {
        let mut out = Vec::new();
        for h in holders {
            for root in self.reader.live_families(h).await? {
                out.push(Event::projection_invalidated(domain, source, root, now));
            }
        }
        Ok(out)
    }

    /// The live Instances of `party` with their states.
    async fn live_instances(&self, party: &Id) -> Result<Vec<(Id, InstanceState)>, CoreError> {
        let index = self.fetch(&[meta::key(kind::INSTANCES, party)]).await?;
        let ids: Vec<Id> = match index.into_iter().next().and_then(|(_, v, _)| v) {
            Some(Value::Array(list)) => {
                list.iter().filter_map(|v| Id::from_value(v).ok()).collect()
            }
            _ => Vec::new(),
        };
        let mut out = Vec::new();
        for id in ids {
            if let Some(state) = self.instance(&id).await?.filter(|s| s.ended.is_none()) {
                out.push((id, state));
            }
        }
        Ok(out)
    }

    async fn instance(&self, id: &Id) -> Result<Option<InstanceState>, CoreError> {
        let rows = self.fetch(&[meta::key(kind::INSTANCE, id)]).await?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|(_, v, _)| v)
            .and_then(|v| InstanceState::from_value(&v).ok()))
    }

    /// `party.compromised`: the window runs from `occurred_at`, or 72 hours before the Claim's
    /// `issued_at`, to its commit, as in the overlay (OP-149 m.7, m.17 (d), OP-141 m.31 (b),
    /// SI-9). It names the Party's live Instances established inside the window, the ones the
    /// overlay denies (OP-141 m.31 (c)).
    async fn compromise(
        &self,
        domain: Digest,
        source: Source,
        party: Id,
        (occurred_at, issued_at): (Option<u64>, u64),
        now: u64,
        evidence: Digest,
    ) -> Result<Event, CoreError> {
        let from = compromise_from(occurred_at, issued_at);
        let mut keys = Vec::new();
        for (id, state) in self.live_instances(&party).await? {
            let established = self.reader.recorded_at(state.since).await?;
            if established.is_none_or(|at| at >= from) {
                keys.push((id, thumbprint(&state.key)));
            }
        }
        Ok(Event {
            kind: Kind::PartyCompromised,
            domain,
            source,
            subject: Subject::Party(party),
            at: now,
            detail: Detail::Compromised {
                keys,
                occurred_at,
                window_from: from,
                declared_at: now,
                evidence,
            },
        })
    }
}
