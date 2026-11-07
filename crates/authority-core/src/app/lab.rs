//! Decision lab back end (§8.17.10.4, X21, §9.7, INV-27): `check` is an advisory evaluation
//! that records nothing and promises nothing; `explain` is the structured explanation at a
//! developer's depth; `replay` evaluates a recorded decision again on the state before it and
//! says whether the outcome matches; `simulate` runs a candidate restriction policy over a sample
//! of intents. Each takes the request's own domain, so a sandbox domain (a separate
//! `AuthorityDomain` with its own Genesis) works the same way; there is no test mode.

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::codec::decision_value;
use access_kernel::combinator::{Blocker, BlockerClass, Capacity, Mode, Outcome, Unmet};
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::meta::{self, ContentState, ExerciseBasis, GrantBasis, GrantState, kind};
use access_kernel::model::{Id, SubjectSelector};
use access_kernel::record::{RecordEnvelope, RecordKind};
use access_kernel::restriction::RestrictionOutcome;
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::publishing::settle;
use crate::app::{Authority, Incoming, Past, Response, who};
use crate::domain::read;
use crate::ports::{Binding, Reader, Salts};
use crate::rate::Class;

/// Text key of the label every lab answer carries: "Advisory — not recorded, not a promise".
pub const ADVISORY: &str = "lab.advisory";

/// The word of a blocker class (§9.6); an SDK that does not know a subcode reads this class.
#[must_use]
pub const fn class_word(class: BlockerClass) -> &'static str {
    match class {
        BlockerClass::NoCoveringAuthority => "no-covering-authority",
        BlockerClass::OutsideInstanceLimits => "outside-instance-limits",
        BlockerClass::Restricted => "restricted",
        BlockerClass::BudgetExhausted => "budget-exhausted",
        BlockerClass::Ended => "ended",
        BlockerClass::CapacityMismatch => "capacity-mismatch",
        BlockerClass::SourceNotAccepted => "source-not-accepted",
        BlockerClass::SchemaNotAccepted => "schema-not-accepted",
        BlockerClass::NonceClosed => "nonce-closed",
        BlockerClass::ForeignStatusUnavailable => "foreign-status-unavailable",
    }
}

/// An advisory answer (§8.17.10.4 Check): never recorded, never a credential (C30).
#[derive(Clone, Debug, PartialEq)]
pub struct LabCheck {
    /// The decision as `check` returns it.
    pub response: Response,
    /// Always `true`.
    pub advisory: bool,
    /// Always `false`: `check` writes no record and opens no nonce (§9.7).
    pub recorded: bool,
    /// [`ADVISORY`].
    pub label: &'static str,
}

/// Why a rule-shaped holder is selected (§8.17.5.7, E-5): the second part of a two-part
/// reason, beside the authority path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Selection {
    /// The rule-shaped Grant.
    pub grant: Id,
    /// The claim classes its selector asks for.
    pub classes: Vec<String>,
    /// Position the holding episode opened.
    pub since: u64,
}

/// A structured explanation at developer depth (§8.17.10.4 Explain, §8.17.8): the reason
/// classes, the unmet terms and the authority path as far as the developer may see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation {
    /// The outcome.
    pub outcome: Outcome,
    /// Blockers of a DENY.
    pub blockers: Vec<Blocker>,
    /// Unmet terms of a `REQUIRE_ACTION`.
    pub unmet: Vec<Unmet>,
    /// The basis lineage, basis Grant first, when the developer views it.
    pub path: Vec<Id>,
    /// The developer does not view the basis; the path is left out.
    pub path_hidden: bool,
    /// The selection part of a two-part reason, for a rule-shaped basis (E-5).
    pub selection: Option<Selection>,
    /// Always `true`.
    pub advisory: bool,
    /// Always `false`.
    pub recorded: bool,
}

/// A replay (§8.17.10.4 Replay, INV-27): the recorded decision against the same request on the
/// state just before it. A mismatch is an evaluator-determinism finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replay {
    /// The decision record.
    pub record: u64,
    /// The recorded outcome.
    pub recorded: Outcome,
    /// The outcome evaluated again.
    pub rebuilt: Outcome,
    /// Whether the decisions are the same.
    pub matches: bool,
    /// The decision fields that differ (`outcome`, `blockers`, `unmet`, `relied_on`).
    pub differing: Vec<String>,
}

/// One intent of a simulation sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    /// The intent.
    pub intent: IntentEnvelope,
    /// The actor, `None` for anonymous.
    pub actor: Option<meta::Actor>,
    /// The capacity.
    pub capacity: Capacity,
}

/// A policy simulation report (§18.3 bulk simulation): counts only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Simulation {
    /// Intents evaluated.
    pub evaluated: u64,
    /// Same outcome under the candidate.
    pub unchanged: u64,
    /// Denied by the candidate, not before.
    pub newly_denied: u64,
    /// Asked for requirements by the candidate, not before.
    pub newly_requiring: u64,
    /// No longer denied or asked: the candidate widens.
    pub newly_allowed: u64,
    /// The engine refused the intent's input.
    pub refused: u64,
}

fn restriction_class(r: &[access_kernel::combinator::PolicyResult]) -> u8 {
    let mut class = 0;
    for p in r {
        class = class.max(match &p.outcome {
            RestrictionOutcome::NoObjection => 0,
            RestrictionOutcome::Require(_) => 1,
            RestrictionOutcome::Deny(_) => 2,
        });
    }
    class
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Check (§8.17.10.4): the request must be a `check`; the decision is advisory and nothing
    /// is recorded (§9.7).
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `lab-mode` for a request that is not a `check`; else as
    /// [`Authority::exercise`].
    pub async fn lab_check(&mut self, inc: &Incoming, now: u64) -> Result<LabCheck, CoreError> {
        if inc.request.mode != Mode::Check {
            return Err(CoreError::Protocol("lab-mode"));
        }
        let response = self.exercise(inc, now).await?;
        Ok(LabCheck {
            response,
            advisory: true,
            recorded: false,
            label: ADVISORY,
        })
    }

    /// Explain (§8.17.10.4): a `check` with its structured explanation; the authority path is
    /// included only when the developer views the basis (OP-141 m.38 (c)).
    ///
    /// # Errors
    /// As [`Authority::lab_check`].
    pub async fn lab_explain(
        &mut self,
        inc: &Incoming,
        now: u64,
    ) -> Result<Explanation, CoreError> {
        let checked = self.lab_check(inc, now).await?;
        let digest =
            intent_digest(&inc.request.intent).map_err(|_| CoreError::Protocol("intent"))?;
        let viewer = self.actor(inc, &digest, now).await?.map(|a| a.party);
        let basis = inc.request.basis;
        let (path, hidden, selection) = settle(&self.reader, |snap| {
            let sees = viewer.is_some_and(|p| crate::domain::views(snap, &basis, &p));
            let (grant, since) = match basis {
                ExerciseBasis::Holding(h) => (Some(h.grant), h.since),
                ExerciseBasis::Public(g) => (Some(g), 0),
                ExerciseBasis::Anchor(_) => (None, 0),
            };
            let selection = grant.and_then(|g| {
                let s: GrantState = read(snap, kind::GRANT, &g)?;
                match s.content.holder {
                    SubjectSelector::Pred(c) => Some(Selection {
                        grant: g,
                        classes: c.iter().map(|c| c.claim_class.clone()).collect(),
                        since,
                    }),
                    _ => None,
                }
            });
            let mut path = Vec::new();
            if sees && let Some(mut at) = grant {
                for _ in 0..meta::MAX_LINEAGE {
                    path.push(at);
                    match read::<GrantState>(snap, kind::GRANT, &at).map(|s| s.content.basis) {
                        Some(GrantBasis::Holding(h)) => at = h.grant,
                        _ => break,
                    }
                }
            }
            (path, !sees, selection)
        })
        .await?;
        let d = checked.response.decision;
        Ok(Explanation {
            outcome: d.outcome,
            blockers: d.blockers,
            unmet: d.unmet,
            path,
            path_hidden: hidden,
            selection,
            advisory: true,
            recorded: false,
        })
    }

    /// Replay (§8.17.10.4, INV-27): evaluates the decision recorded at `record` again with its
    /// request on the state just before it, for an auditor of the domain, and reports whether
    /// it matches. Nothing is recorded.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `replay-scope` for a caller without audit visibility,
    /// `replay-record` for a request that is not the recorded one; else as
    /// [`Authority::exercise`].
    pub async fn lab_replay(
        &mut self,
        inc: &Incoming,
        record: u64,
        now: u64,
    ) -> Result<Replay, CoreError> {
        let req = &inc.request;
        if req.domain != self.domain {
            return Err(CoreError::Protocol("domain"));
        }
        if req.mode == Mode::Check || record == 0 || record > self.head() {
            return Err(CoreError::Protocol("replay-record"));
        }
        Self::check_payload(req)?;
        let digest = intent_digest(&req.intent).map_err(|_| CoreError::Protocol("intent"))?;
        let actor = self.actor(inc, &digest, now).await?;
        if !self.limiter.admit(Class::Explain, who(inc, actor), now) {
            return Err(CoreError::Limited);
        }
        let auditor = match actor {
            Some(a) => self.audits(&a.party, now).await?,
            None => false,
        };
        if !auditor {
            return Err(CoreError::Protocol("replay-scope"));
        }
        let nonce = self.reader.nonce(&req.nonce).await?;
        if nonce.as_ref().is_none_or(|n| n.intent_digest != digest.0) {
            return Err(CoreError::Protocol("replay-record"));
        }
        let log = self.reader.log(0, record).await?;
        let recorded_value = log
            .last()
            .and_then(|b| RecordEnvelope::from_bytes(b).ok())
            .filter(|r| r.header.pos == record && r.header.kind == RecordKind::Decision)
            .and_then(|r| r.fields.get("outcome").map(|f| f.value.clone()))
            .ok_or(CoreError::Protocol("replay-record"))?;
        let (past, at, recorded, opening) = Past::before(&log, record, &req.nonce, &digest)
            .map_err(|_| CoreError::Protocol("replay-record"))?;
        if opening.basis != meta::basis_value(&req.basis)
            || opening.capacity != meta::capacity_value(req.capacity)
        {
            return Err(CoreError::Protocol("replay-record"));
        }
        let actor = match &opening.actor {
            Value::Bytes(b) => {
                let instance = Id::from_value(&Value::Bytes(b.clone()))
                    .map_err(|_| CoreError::Protocol("replay-record"))?;
                let state = past
                    .row(&meta::key(kind::INSTANCE, &instance))
                    .1
                    .and_then(|v| meta::InstanceState::from_value(&v).ok())
                    .ok_or(CoreError::Protocol("replay-record"))?;
                Some(meta::Actor {
                    party: state.party,
                    instance,
                })
            }
            _ => None,
        };
        let opened = self
            .reader
            .nonce_opened(&req.nonce)
            .await?
            .is_some_and(|p| p < record);
        self.past = Some(past);
        let rebuilt = self.rebuild(req, actor, digest, record, at, opened).await;
        self.past = None;
        let rebuilt = rebuilt?.decision;
        let rebuilt_value = decision_value(&rebuilt);
        let mut differing = Vec::new();
        for f in ["outcome", "blockers", "unmet", "relied_on"] {
            if recorded_value.get(f) != rebuilt_value.get(f) {
                differing.push(String::from(f));
            }
        }
        Ok(Replay {
            record,
            recorded,
            rebuilt: rebuilt.outcome,
            matches: differing.is_empty() && recorded == rebuilt.outcome,
            differing,
        })
    }

    /// Simulates `candidate` (a `policy_set` content) in place of `policy` (`None` for a new
    /// one) over `samples`, at `now`: each intent's restriction outcome under the policy in
    /// force and under the candidate, counted (§18.3). Only the domain's auditors may run it;
    /// nothing is recorded.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `lab-scope` for another caller, `lab-policy` for a candidate
    /// that does not compile; the reader's errors.
    pub async fn lab_simulate(
        &self,
        caller: Id,
        policy: Option<Id>,
        candidate: &Value,
        samples: &[Sample],
        now: u64,
    ) -> Result<Simulation, CoreError> {
        if !self.audits(&caller, now).await? {
            return Err(CoreError::Protocol("lab-scope"));
        }
        crate::restrict::compile(candidate).map_err(|_| CoreError::Protocol("lab-policy"))?;
        let current = match policy {
            None => None,
            Some(p) => {
                settle(&self.reader, |snap| {
                    read::<ContentState>(snap, kind::POLICY, &p).filter(|s| s.ended.is_none())
                })
                .await?
            }
        };
        let id = policy.unwrap_or(Id([0; 16]));
        let before: Vec<(Id, ContentState)> = current.into_iter().map(|s| (id, s)).collect();
        let after = vec![(
            id,
            ContentState {
                content: candidate.clone(),
                since: 0,
                widened: None,
                ended: None,
            },
        )];
        let cache = crate::restrict::Cache::default();
        let mut out = Simulation::default();
        let mut seen = BTreeSet::new();
        for s in samples {
            let Ok(d) = intent_digest(&s.intent) else {
                out.refused = out.refused.saturating_add(1);
                continue;
            };
            if !seen.insert(d) {
                continue;
            }
            out.evaluated = out.evaluated.saturating_add(1);
            let eval = |set: &[(Id, ContentState)]| {
                crate::restrict::results(set, &s.intent, s.actor.as_ref(), s.capacity, now, &cache)
                    .map(|r| restriction_class(&r))
            };
            match (eval(&before), eval(&after)) {
                (Ok(b), Ok(a)) if a == b => out.unchanged = out.unchanged.saturating_add(1),
                (Ok(b), Ok(a)) if a < b => out.newly_allowed = out.newly_allowed.saturating_add(1),
                (Ok(_), Ok(2)) => out.newly_denied = out.newly_denied.saturating_add(1),
                (Ok(_), Ok(_)) => out.newly_requiring = out.newly_requiring.saturating_add(1),
                _ => out.refused = out.refused.saturating_add(1),
            }
        }
        Ok(out)
    }
}
