//! The `outcome` search (OP-154 m.3 (u), E64, INV-18, EI-10): what the executors reported about
//! one Exercise, compared with the Exercise Access allowed. A report is a Claim, never truth,
//! and never touches the decision: the allowing position is read, not written, and an allowed
//! Exercise whose effect did not happen stays allowed with outcome `not-done`. An effect is
//! outside authority only when it was reported after the intent's window, outside the intent
//! envelope, or for no allowed Exercise at all (§8.10, INV-19).

use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::Statement;
use access_kernel::claim::body::{
    Body, Class, ControlState, EffectAttestation, EffectOutcome, EvidenceKind,
};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::meta::{self, ExerciseState, InstanceState, kind};
use access_kernel::model::{EqValue, Id};
use access_kernel::record::{RecordEnvelope, RecordKind};
use access_kernel::verify::cose::parse_sign1;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::app::Authority;
use crate::app::hub::LOG_WINDOW;
use crate::domain::read;
use crate::ports::{Binding, Reader, Salts};
use crate::query::{Found, Hit, Report};

/// Log records read per round trip.
const PAGE: u64 = 500;

/// How one reported effect compares with the allowed Exercise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Conformance {
    /// Inside the allowed Exercise: its intent, its action, its window.
    Conforming,
    /// Reported for no Exercise this domain allowed.
    NoExercise,
    /// Not the allowed intent or action.
    Envelope,
    /// Reported outside the intent's window.
    Window,
}

impl Conformance {
    /// The wire word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Conforming => "conforming",
            Self::NoExercise => "no-exercise",
            Self::Envelope => "outside-envelope",
            Self::Window => "outside-window",
        }
    }
}

/// One `effect_attestation` of the Exercise.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Attested {
    /// Its position.
    pub position: u64,
    /// The `ClaimID`.
    pub claim: Id,
    /// The reporter: the issuing Party.
    pub issuer: Id,
    /// The executor Instance named in the body.
    pub executor: Id,
    /// Ingest's disposition word.
    pub disposition: String,
    /// The `StepRef`.
    pub step: Digest,
    /// The idempotency key.
    pub idempotency_key: Digest,
    /// `done`, `not-done` or `unknown`.
    pub outcome: &'static str,
    /// The evidence kinds.
    pub evidence: Vec<&'static str>,
    /// When the executor says it happened.
    pub at: u64,
    /// How it compares with the Exercise.
    pub conformance: Conformance,
}

/// What an executor confirmed about the Exercise's job (U5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Control {
    /// Its position.
    pub position: u64,
    /// `paused` or `stopped_confirmed`.
    pub state: &'static str,
    /// The reporter.
    pub issuer: Id,
}

/// The `outcome` report of one Exercise.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Outcome {
    /// The Exercise.
    pub exercise: Digest,
    /// The position of the allowing decision, as recorded; `None` when the domain allowed no
    /// such Exercise.
    pub allowed_at: Option<u64>,
    /// The reports, in log order.
    pub attested: Vec<Attested>,
    /// The confirmed control states, in log order.
    pub control: Vec<Control>,
}

impl Outcome {
    /// `unattested` when an allowed Exercise has no report, `attested` otherwise.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        if self.attested.is_empty() {
            "unattested"
        } else {
            "attested"
        }
    }
}

const fn outcome_word(o: EffectOutcome) -> &'static str {
    match o {
        EffectOutcome::Done => "done",
        EffectOutcome::NotDone => "not-done",
        EffectOutcome::Unknown => "unknown",
    }
}

const fn evidence_word(e: EvidenceKind) -> &'static str {
    match e {
        EvidenceKind::UpstreamConfirmation => "upstream-confirmation",
        EvidenceKind::IndependentRecheck => "independent-recheck",
        EvidenceKind::BrowserObservation => "browser-observation",
    }
}

fn field<'a>(r: &'a RecordEnvelope, name: &str) -> Option<&'a Value> {
    r.fields.get(name).map(|f| &f.value)
}

/// Adds one Claim record's report to `report` when it is about the report's Exercise.
fn add(
    report: &mut Outcome,
    (r, s, body): (&RecordEnvelope, &Statement, Body),
    allowed: Option<&ExerciseState>,
    envelope: &IntentEnvelope,
) {
    let disposition = match field(r, "disposition") {
        Some(Value::Text(t)) => t.clone(),
        _ => String::new(),
    };
    let claim = field(r, "id")
        .and_then(|v| Id::from_value(v).ok())
        .unwrap_or(Id([0; 16]));
    match body {
        Body::EffectAttestation(a) if a.exercise == report.exercise => {
            report.attested.push(Attested {
                position: r.header.pos,
                claim,
                issuer: s.issuer,
                executor: a.executor,
                disposition,
                step: a.step,
                idempotency_key: a.idempotency_key,
                outcome: outcome_word(a.outcome),
                evidence: a.evidence.iter().copied().map(evidence_word).collect(),
                at: a.at,
                conformance: conformance(&a, allowed, envelope),
            });
        }
        Body::ExecutorControl(c) if c.exercise == report.exercise => {
            report.control.push(Control {
                position: r.header.pos,
                state: match c.state {
                    ControlState::Paused => "paused",
                    ControlState::StoppedConfirmed => "stopped_confirmed",
                },
                issuer: s.issuer,
            });
        }
        _ => {}
    }
}

/// How one report compares with the allowed Exercise and the intent the viewer holds.
#[must_use]
pub fn conformance(
    a: &EffectAttestation,
    allowed: Option<&ExerciseState>,
    envelope: &IntentEnvelope,
) -> Conformance {
    let Some(s) = allowed else {
        return Conformance::NoExercise;
    };
    if a.params != s.intent || a.action != envelope.action {
        return Conformance::Envelope;
    }
    if a.at < envelope.validity.from || a.at > envelope.validity.until {
        return Conformance::Window;
    }
    Conformance::Conforming
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    async fn statement_of(
        &self,
        r: &RecordEnvelope,
    ) -> Result<Option<(Statement, Body)>, CoreError> {
        let (Some(claim), Some(Value::Text(class))) = (field(r, "claim"), field(r, "class")) else {
            return Ok(None);
        };
        let Some(class) = Class::parse(class)
            .filter(|c| matches!(c, Class::EffectAttestation | Class::ExecutorControl))
        else {
            return Ok(None);
        };
        let Some(digest) = Digest::from_value(claim) else {
            return Ok(None);
        };
        let Some(bytes) = self.reader.proof(&digest.0).await? else {
            return Ok(None);
        };
        let Some(s) = parse_sign1(&bytes)
            .ok()
            .and_then(|m| m.payload)
            .and_then(|p| Statement::from_bytes(&p).ok())
        else {
            return Ok(None);
        };
        let Some(EqValue::Bytes(value)) = &s.value else {
            return Ok(None);
        };
        let Ok(value) = <[u8; 32]>::try_from(value.as_slice()) else {
            return Ok(None);
        };
        let Some(body) = self.reader.proof(&value).await? else {
            return Ok(None);
        };
        let Ok(v) = dcbor::decode(&body, Limits::CEILING) else {
            return Ok(None);
        };
        Ok(Body::from_value(class, &v).ok().map(|b| (s, b)))
    }

    /// The `outcome` report of `exercise` for `viewer` (OP-154 m.3 (u)): only the Exercise's
    /// actor Party sees it, and a reporter sees what it reported itself. `envelope` is the
    /// intent the viewer holds; it must be the allowed Exercise's.
    ///
    /// # Errors
    /// The reader's errors; [`CoreError::Protocol`] for a record that does not decode.
    pub(crate) async fn outcome(
        &self,
        viewer: Id,
        exercise: Digest,
        envelope: &IntentEnvelope,
        now: u64,
    ) -> Result<Found, CoreError> {
        let key = meta::exercise_key(kind::EXERCISE, &exercise);
        let allowed = self
            .reader
            .fetch(std::slice::from_ref(&key))
            .await?
            .into_iter()
            .find_map(|(_, v, _)| v)
            .and_then(|v| ExerciseState::from_value(&v).ok());
        let actor = match &allowed {
            Some(s) => {
                let digest = intent_digest(envelope).map_err(|_| CoreError::Protocol("intent"))?;
                if digest != s.intent {
                    return Ok(Found::default());
                }
                self.settled(|snap| {
                    read::<InstanceState>(snap, kind::INSTANCE, &s.actor).map(|i| i.party)
                })
                .await?
            }
            None => None,
        };
        let Some(last) = self.reader.position_at(now).await? else {
            return Ok(Found::default());
        };
        let first = allowed
            .as_ref()
            .map_or_else(|| last.saturating_sub(LOG_WINDOW), |s| s.since)
            .max(1);
        let last = last.min(first.saturating_add(LOG_WINDOW));
        let mut report = Outcome {
            exercise,
            allowed_at: allowed.as_ref().map(|s| s.since),
            attested: Vec::new(),
            control: Vec::new(),
        };
        let mut from = first;
        while from <= last {
            let to = from.saturating_add(PAGE).saturating_sub(1).min(last);
            for bytes in self.reader.log(from, to).await? {
                let r = RecordEnvelope::from_bytes(&bytes)
                    .map_err(|_| CoreError::Protocol("record"))?;
                if r.header.kind != RecordKind::Claim {
                    continue;
                }
                let Some((s, body)) = self.statement_of(&r).await? else {
                    continue;
                };
                // XI-9
                if actor != Some(viewer) && s.issuer != viewer {
                    continue;
                }
                add(&mut report, (&r, &s, body), allowed.as_ref(), envelope);
            }
            from = to.saturating_add(1);
        }
        if actor != Some(viewer) && report.attested.is_empty() && report.control.is_empty() {
            return Ok(Found::default());
        }
        if actor != Some(viewer) {
            report.allowed_at = None;
        }
        Ok(Found {
            hits: vec![Hit::Report(Box::new(Report::Outcome(Box::new(report))))],
            next: None,
            audited: None,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use std::collections::{BTreeMap, BTreeSet};

    use access_kernel::intent::ContextRefs;
    use access_kernel::model::{ActionRef, ResourceRef, Window};

    use super::*;

    fn envelope() -> IntentEnvelope {
        IntentEnvelope {
            provenance: BTreeMap::new(),
            action: ActionRef {
                namespace: String::from("mail"),
                name: String::from("send"),
                major: 1,
                schema: Digest([7; 32]),
            },
            resources: vec![ResourceRef {
                namespace: String::from("mail"),
                path: vec![String::from("outbox")],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window {
                from: 1_000,
                until: 2_000,
            },
        }
    }

    fn report(params: Digest, action: ActionRef, at: u64) -> EffectAttestation {
        EffectAttestation {
            exercise: Digest([1; 32]),
            step: Digest([2; 32]),
            idempotency_key: Digest([3; 32]),
            action,
            params,
            outcome: EffectOutcome::NotDone,
            evidence: BTreeSet::new(),
            refs: BTreeSet::new(),
            at,
            executor: Id([4; 16]),
            environment: None,
        }
    }

    // INV-19, INV-18, §8.10, Ek B 4280
    #[test]
    fn an_effect_is_outside_authority_only_after_the_window_outside_the_envelope_or_without_exercise()
     {
        let e = envelope();
        let intent = intent_digest(&e).unwrap();
        let allowed = ExerciseState {
            intent,
            actor: Id([5; 16]),
            since: 9,
            draws: Vec::new(),
            grounds: BTreeSet::new(),
        };
        let inside = report(intent, e.action.clone(), 1_500);
        assert_eq!(
            conformance(&inside, Some(&allowed), &e),
            Conformance::Conforming
        );
        assert_eq!(conformance(&inside, None, &e), Conformance::NoExercise);
        let elsewhere = report(Digest([9; 32]), e.action.clone(), 1_500);
        assert_eq!(
            conformance(&elsewhere, Some(&allowed), &e),
            Conformance::Envelope
        );
        let mut other = e.action.clone();
        other.name = String::from("delete");
        assert_eq!(
            conformance(&report(intent, other, 1_500), Some(&allowed), &e),
            Conformance::Envelope
        );
        let late = report(intent, e.action.clone(), 2_001);
        assert_eq!(conformance(&late, Some(&allowed), &e), Conformance::Window);
        let none = Outcome {
            exercise: Digest([1; 32]),
            allowed_at: Some(9),
            attested: Vec::new(),
            control: Vec::new(),
        };
        assert_eq!(none.status(), "unattested");
    }
}
