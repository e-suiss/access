//! The external signals a decision reads (OP-156 m.3 (r), E38, CI-2, TN-46): the accepted
//! `risk_external` and `posture_mdm` Claims about the actor and the `data_label` Claims the
//! request carries for its resource, read from their bodies. They reach only the restriction
//! context, whose policies forbid or ask for more and never allow; a body Access cannot read
//! counts as the most severe statement of its class, and a missing signal is `none`.

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_internal_api::signals::{
    self, DATA_LABEL, POSTURE_MDM, Posture, RISK_EXTERNAL, RISK_HORIZON_MS, Reading,
};
use access_kernel::claim::{self, ClaimState, Statement};
use access_kernel::codec::Canonical;
use access_kernel::meta::{self, Actor, kind};
use access_kernel::model::{EqValue, Id, ProofKind};

use crate::CoreError;
use crate::app::Authority;
use crate::app::proofs::Resolved;
use crate::domain::{Request, Snapshot};
use crate::ports::{Binding, Reader, Salts};
use crate::restrict::Signals;

/// Most Claims of one signal class read about one Party per decision.
const MAX_PER_CLASS: usize = 64;

const fn current(s: &Statement, now: u64) -> bool {
    s.validity.from <= now && now <= s.validity.until
}

fn digest(s: &Statement) -> Option<&[u8]> {
    match &s.value {
        Some(EqValue::Bytes(d)) if d.len() == 32 => Some(d.as_slice()),
        _ => None,
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// What the Claim `s` says, read from the body its `value` names.
    async fn reading(&self, s: &Statement) -> Result<Reading, CoreError> {
        let Some(d) = digest(s) else {
            return Ok(Reading::Unreadable);
        };
        let Ok(key) = <[u8; 32]>::try_from(d) else {
            return Ok(Reading::Unreadable);
        };
        let body = self.reader.proof(&key).await?;
        Ok(signals::read(&s.class, Some(d), body.as_deref()))
    }

    /// The accepted (`predicate-input`), current, unsuperseded Claims of `class` about `party`.
    async fn accepted(
        &self,
        snap: &mut Snapshot,
        class: &str,
        party: &Id,
        now: u64,
    ) -> Result<Vec<Statement>, CoreError> {
        let mut out = Vec::new();
        for (_, value, _) in self.scan(&claim::member_prefix(class, party)).await? {
            if out.len() >= MAX_PER_CLASS {
                break;
            }
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|s| {
                    s.ended.is_none()
                        && s.statement.subject == *party
                        && s.statement.class == class
                        && current(&s.statement, now)
                })
            else {
                continue;
            };
            let gates = self.gates(snap, &state.statement.issuer).await?;
            if !gates
                .iter()
                .any(|g| g.admits_for(claim::PREDICATE_INPUT, &state.statement, now))
                || !self.unsuperseded(snap, &id, &state.statement).await?
            {
                continue;
            }
            out.push(state.statement);
        }
        Ok(out)
    }

    /// The signals of one request for the restriction context.
    pub(crate) async fn signals(
        &self,
        actor: Option<Actor>,
        req: &Request,
        resolved: &Resolved,
        now: u64,
    ) -> Result<Signals, CoreError> {
        let mut out = Signals::default();
        let mut snap = Snapshot::default();
        if let Some(actor) = actor {
            // TN-46
            for s in self
                .accepted(&mut snap, RISK_EXTERNAL, &actor.party, now)
                .await?
            {
                if s.issued_at.saturating_add(RISK_HORIZON_MS) < now {
                    continue;
                }
                let level = signals::risk_of(&self.reading(&s).await?);
                out.risk = Some(out.risk.map_or(level, |r| r.max(level)));
            }
            for s in self
                .accepted(&mut snap, POSTURE_MDM, &actor.party, now)
                .await?
            {
                if s.bound_instance.is_some_and(|i| i != actor.instance) {
                    continue;
                }
                out.posture = out.posture.max(Posture::of(&self.reading(&s).await?));
            }
        }
        // F11
        let mut labels = BTreeSet::new();
        for p in resolved.proofs.iter().filter(|p| {
            p.kind == ProofKind::Claim
                && p.class == DATA_LABEL
                && p.binding
                    .resource
                    .as_ref()
                    .is_some_and(|r| req.intent.resources.contains(r))
        }) {
            let reading = match resolved.claims.iter().find(|c| c.id == p.id) {
                Some(_) => Reading::Unreadable,
                None => match self
                    .get(&mut snap, &meta::key(kind::CLAIM, &p.id))
                    .await?
                    .and_then(|v| ClaimState::from_value(&v).ok())
                {
                    Some(state) => self.reading(&state.statement).await?,
                    None => Reading::Unreadable,
                },
            };
            labels.insert(signals::label_of(&reading));
        }
        out.labels = labels;
        Ok(out)
    }
}
