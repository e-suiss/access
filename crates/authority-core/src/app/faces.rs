//! Agents and reported effects in the hub (XI-17, A-12, §8.10, §8.17.7.4, E64, INV-18,
//! OP-154 m.3 (u)): a holder or actor that is an agent Party is shown as an agent, with the
//! operator an accepted `operated_by` Claim names; a use carries what executors reported about
//! its Exercise and the control states they confirmed. A report is a Claim, never truth, and
//! never touches the decision.

use std::collections::BTreeMap;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::body::{Body, Class, ControlState};
use access_kernel::claim::{self, ClaimState};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::meta::{self, kind};
use access_kernel::model::{EqValue, Id};
use access_kernel::record::{RecordEnvelope, RecordKind};

use crate::CoreError;
use crate::app::Authority;
use crate::app::outcome::{evidence_word, outcome_word};
use crate::domain::Snapshot;
use crate::ports::{Binding, Reader, Salts};

/// An agent as the hub shows it (XI-17, A-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentFace {
    /// The operator the accepted `operated_by` Claims agree on; `None` when none is accepted
    /// or they disagree.
    pub operator: Option<Id>,
}

/// One executor report about a use's Exercise (E64).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reported {
    /// Its position.
    pub position: u64,
    /// The reporter: the issuing Party.
    pub reporter: Id,
    /// `done`, `not-done` or `unknown`.
    pub outcome: &'static str,
    /// The evidence kinds.
    pub evidence: Vec<&'static str>,
    /// When the executor says it happened.
    pub at: u64,
    /// The digest of the parameters it applied.
    pub params: Digest,
    /// Whether they are the allowed intent's (INV-19); the window is the `outcome` search's,
    /// which holds the envelope.
    pub same_intent: bool,
}

/// One confirmed control state of a use's Exercise (U5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Controlled {
    /// Its position.
    pub position: u64,
    /// `on_hold` (a confirmed pause, worded as the surfaces word it, X24) or `stopped_confirmed`.
    pub state: &'static str,
    /// The reporter.
    pub reporter: Id,
}

/// What executors reported about one Exercise, in log order.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reports {
    /// The effect reports.
    pub attested: Vec<Reported>,
    /// The confirmed control states.
    pub control: Vec<Controlled>,
}

/// The reports of one walk over the log, by Exercise.
pub(crate) type ByExercise = BTreeMap<Digest, Reports>;

impl Reports {
    /// These reports as read against the allowed intent `intent`.
    #[must_use]
    pub fn against(mut self, intent: &Digest) -> Self {
        for a in &mut self.attested {
            a.same_intent = a.params == *intent;
        }
        self
    }
}

fn operator_of(s: &ClaimState) -> Option<Id> {
    match &s.statement.value {
        Some(EqValue::Bytes(b)) => <[u8; 16]>::try_from(b.as_slice()).ok().map(Id),
        _ => None,
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// `party` as the hub shows it when it is an agent at `now`; `None` for any other actor.
    ///
    /// # Errors
    /// The reader's errors.
    pub(crate) async fn agent_face(
        &self,
        party: &Id,
        now: u64,
    ) -> Result<Option<AgentFace>, CoreError> {
        // XI-17
        if !self
            .settled(|snap| meta::actor_is_agent(snap, party))
            .await?
        {
            return Ok(None);
        }
        let class = Class::OperatedBy.name();
        let mut snap = Snapshot::default();
        let mut operators = Vec::new();
        for (_, value, _) in self.scan(&claim::member_prefix(&class, party)).await? {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(s) = self
                .get(&mut snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
            else {
                continue;
            };
            let st = &s.statement;
            let live = s.ended.is_none()
                && st.subject == *party
                && st.class == class
                && st.validity.from <= now
                && now <= st.validity.until;
            if !live || !self.in_line(&mut snap, &id, st, now).await? {
                continue;
            }
            let accepted = self.gates(&mut snap, &st.issuer).await?.iter().any(|g| {
                [claim::PREDICATE_INPUT, claim::SUBJECT_SELECTION]
                    .iter()
                    .any(|u| g.admits_for(u, st, now))
            });
            if let (true, Some(op)) = (accepted, operator_of(&s)) {
                operators.push(op);
            }
        }
        operators.sort();
        operators.dedup();
        Ok(Some(AgentFace {
            operator: match operators.as_slice() {
                [one] => Some(*one),
                _ => None,
            },
        }))
    }

    /// Adds Claim record `r` to `out` when it is an executor report.
    pub(crate) async fn collect_report(
        &self,
        r: &RecordEnvelope,
        out: &mut ByExercise,
    ) -> Result<(), CoreError> {
        if r.header.kind != RecordKind::Claim {
            return Ok(());
        }
        let Some((s, body)) = self.statement_of(r).await? else {
            return Ok(());
        };
        match body {
            Body::EffectAttestation(a) => {
                out.entry(a.exercise).or_default().attested.push(Reported {
                    position: r.header.pos,
                    reporter: s.issuer,
                    outcome: outcome_word(a.outcome),
                    evidence: a.evidence.iter().copied().map(evidence_word).collect(),
                    at: a.at,
                    params: a.params,
                    same_intent: false,
                });
            }
            Body::ExecutorControl(c) => {
                out.entry(c.exercise).or_default().control.push(Controlled {
                    position: r.header.pos,
                    state: match c.state {
                        ControlState::Paused => "on_hold",
                        ControlState::StoppedConfirmed => "stopped_confirmed",
                    },
                    reporter: s.issuer,
                });
            }
            _ => {}
        }
        Ok(())
    }
}
