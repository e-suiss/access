//! The Claims an executor reports (E64, U5): an `effect_attestation` per step and an
//! `executor_control` per confirmed pause or stop, issued by the executor's operator Party and
//! signed by the executor Instance's key. A Claim is a report, never truth, and never changes a
//! decision (EI-10, INV-18).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::claim::Statement;
use access_kernel::claim::body::{
    Class, ControlState, EffectAttestation, EffectOutcome, EvidenceKind, EvidenceRef,
    ExecutorControl, body_digest,
};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::model::{EqValue, Id, Window};

use super::history::{Confirmed, Evidence, Job, Outcome};

/// How long a report Claim holds: a year (OP-154 m.9 (d) uses the same for agent Claims).
pub const VALIDITY_MS: u64 = 365 * 24 * 3_600_000;

/// Who reports: the executor Instance and its operator Party (Ek B 4340).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reporter {
    /// The operator Party: the Claim's issuer, never the actor.
    pub operator: Id,
    /// The executor Instance whose key signs.
    pub executor: Id,
}

/// A Claim ready to sign: the statement and its body's canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The statement.
    pub statement: Statement,
    /// The body.
    pub body: Vec<u8>,
}

const fn outcome(o: Outcome) -> EffectOutcome {
    match o {
        Outcome::Done => EffectOutcome::Done,
        Outcome::NotDone => EffectOutcome::NotDone,
        Outcome::Unknown => EffectOutcome::Unknown,
    }
}

const fn evidence(e: Evidence) -> EvidenceKind {
    match e {
        Evidence::UpstreamConfirmation => EvidenceKind::UpstreamConfirmation,
        Evidence::IndependentRecheck => EvidenceKind::IndependentRecheck,
        Evidence::BrowserObservation => EvidenceKind::BrowserObservation,
    }
}

fn statement(
    job: &Job,
    by: Reporter,
    class: Class,
    body: &access_kernel::claim::body::Body,
    at: u64,
) -> Option<Report> {
    let value = body.to_value();
    let digest = body_digest(class, &value).ok()?;
    let bytes = suiss_crypto::dcbor::encode(&value, suiss_crypto::dcbor::Limits::CEILING).ok()?;
    Some(Report {
        statement: Statement {
            domain: job.domain(),
            issuer: by.operator,
            subject: by.operator,
            class: class.name(),
            value: Some(EqValue::Bytes(digest.to_vec())),
            issued_at: at,
            validity: Window {
                from: at,
                until: at.saturating_add(VALIDITY_MS),
            },
            assurance: BTreeMap::new(),
            bound_intent: Some(job.intent),
            bound_instance: Some(by.executor),
            bound_resource: None,
            supersedes: None,
        },
        body: bytes,
    })
}

/// The `effect_attestation` of step `i` (E64): its Exercise, `StepRef`, idempotency key, the
/// action, the parameters applied (the intent's digest: a step applies the approved intent and
/// nothing else, INV-19), the outcome, the evidence kinds and the answer's digest as the one
/// evidence reference; the answer itself never enters Access.
#[must_use]
pub fn effect(job: &Job, i: usize, by: Reporter) -> Option<Report> {
    let s = job.steps.get(i)?;
    let (o, kinds, at) = s.outcome.as_ref()?;
    let refs = s
        .answered
        .map(|(_, body, _)| EvidenceRef {
            digest: Digest(body),
            reference: None,
        })
        .into_iter()
        .filter(|_| *o == Outcome::Done)
        .collect::<BTreeSet<_>>();
    let body = access_kernel::claim::body::Body::EffectAttestation(EffectAttestation {
        exercise: job.exercise(),
        step: s.step,
        idempotency_key: s.key,
        action: job.envelope.action.clone(),
        params: job.intent,
        outcome: outcome(*o),
        evidence: kinds.iter().copied().map(evidence).collect(),
        refs,
        at: *at,
        executor: by.executor,
        environment: None,
    });
    statement(job, by, Class::EffectAttestation, &body, *at)
}

/// The `executor_control` confirming `state` at `at` (U5).
#[must_use]
pub fn control(job: &Job, state: Confirmed, at: u64, by: Reporter) -> Option<Report> {
    let body = access_kernel::claim::body::Body::ExecutorControl(ExecutorControl {
        state: match state {
            Confirmed::Paused => ControlState::Paused,
            Confirmed::Stopped => ControlState::StoppedConfirmed,
        },
        exercise: job.exercise(),
        at,
    });
    statement(job, by, Class::ExecutorControl, &body, at)
}

/// The signed statement's payload.
#[must_use]
pub fn payload(r: &Report) -> Option<Vec<u8>> {
    r.statement.to_bytes().ok()
}
