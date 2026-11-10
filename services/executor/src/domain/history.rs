//! The append-only job history (E62 (1)) and its deterministic fold. Every time, random value
//! and upstream answer a job relied on is an event, so a replay reads them from here and never
//! from the world again.

use std::collections::VecDeque;

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use serde::{Deserialize, Serialize};

use super::Kind;
use super::b64;
use super::step::{StepSpec, idempotency_key, step_ref};

/// What an effect came to, as the executor reports it (E64 (1)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// It happened, with evidence.
    #[serde(rename = "done")]
    Done,
    /// It did not happen.
    #[serde(rename = "not-done")]
    NotDone,
    /// It could not be verified; never retried on its own (E62 (3)).
    #[serde(rename = "unknown")]
    Unknown,
}

/// The evidence kinds, strongest first (E64 (2)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Evidence {
    /// The upstream API's structured answer.
    #[serde(rename = "upstream-confirmation")]
    UpstreamConfirmation,
    /// A separate later read.
    #[serde(rename = "independent-recheck")]
    IndependentRecheck,
    /// Only a page observation.
    #[serde(rename = "browser-observation")]
    BrowserObservation,
}

/// How a driver read an upstream answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reading {
    /// The upstream confirmed the effect.
    Confirmed,
    /// The upstream refused it; nothing happened.
    Refused,
    /// The upstream blocks the agent; a person takes over (E51).
    Blocked,
    /// The upstream reports a changed state; the next step is asked again (§7.9.7.2).
    Conflict,
    /// The answer does not say; the outcome is unknown.
    Unclear,
}

/// A control request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Request {
    /// Pause at the next step.
    Pause,
    /// Stop: no further effect.
    Stop,
}

/// A confirmed control state (U5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confirmed {
    /// Paused.
    Paused,
    /// Stopped.
    Stopped,
}

/// The first event of a job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Started {
    /// The job.
    #[serde(with = "b64::fixed")]
    pub job: [u8; 16],
    /// The executor's kind.
    pub kind: Kind,
    /// The domain.
    #[serde(with = "b64::fixed")]
    pub domain: [u8; 32],
    /// The Exercise the job runs.
    #[serde(with = "b64::fixed")]
    pub exercise: [u8; 32],
    /// The intent envelope, canonical bytes.
    #[serde(with = "b64::bytes")]
    pub intent: Vec<u8>,
    /// The actor's commit statement the Exercise was allowed under.
    #[serde(with = "b64::bytes")]
    pub ais: Vec<u8>,
    /// The realm whose vault holds the connection.
    pub realm: String,
    /// The vault connection.
    pub connection: String,
    /// The steps.
    pub steps: Vec<StepSpec>,
    /// The delayed-commit window of an irreversible step; 0 when the person turned it off.
    pub commit_window_ms: u64,
    /// When.
    pub at: u64,
    /// The person's attested microVM the job runs in, for a cloud executor (E61).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<super::isolation::Isolated>,
}

/// One history event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// The job began under an allowed Exercise.
    Started(Box<Started>),
    /// `continue` statements the actor signed for the checkpoints ahead (Ek B 4340).
    Continuations {
        /// The statements.
        #[serde(with = "b64::list")]
        ais: Vec<Vec<u8>>,
    },
    /// Access's answer at a checkpoint; the executor applies it, never makes it (AG-40).
    Decided {
        /// The checkpoint.
        checkpoint: u32,
        /// Whether it was a verified ALLOW.
        allowed: bool,
        /// `allow`, `deny`, `require_action` or why the answer did not verify.
        code: String,
        /// When.
        at: u64,
    },
    /// An irreversible step's delayed-commit window opened.
    WindowOpened {
        /// The step.
        step: u32,
        /// When it may be sent.
        until: u64,
    },
    /// The vault released the Exercise's token to this executor; the token is never written.
    Released {
        /// The step.
        step: u32,
        /// The token's end of use.
        use_until: u64,
        /// When.
        at: u64,
    },
    /// The request is about to leave: committed before it does (TI-6).
    Outbox {
        /// The step.
        step: u32,
        /// The idempotency key.
        #[serde(with = "b64::fixed")]
        key: [u8; 32],
        /// Digest of the request, without credentials.
        #[serde(with = "b64::fixed")]
        request: [u8; 32],
        /// When.
        at: u64,
    },
    /// The one send again of a request whose answer a crash lost (TI-6).
    Resent {
        /// The step.
        step: u32,
        /// When.
        at: u64,
    },
    /// The upstream answered.
    Answered {
        /// The step.
        step: u32,
        /// The status.
        status: u16,
        /// Digest of the body, the evidence reference.
        #[serde(with = "b64::fixed")]
        body: [u8; 32],
        /// How the driver read it.
        reading: Reading,
        /// When.
        at: u64,
    },
    /// No answer came.
    Faulted {
        /// The step.
        step: u32,
        /// When.
        at: u64,
    },
    /// The step's outcome.
    Outcome {
        /// The step.
        step: u32,
        /// The outcome.
        outcome: Outcome,
        /// The evidence kinds.
        evidence: Vec<Evidence>,
        /// When.
        at: u64,
    },
    /// The step's `effect_attestation` Claim went to Claim Ingest.
    Attested {
        /// The step.
        step: u32,
        /// The `ClaimID`.
        #[serde(with = "b64::bytes")]
        claim: Vec<u8>,
        /// The refusal code when Ingest refused it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refused: Option<String>,
        /// When.
        at: u64,
    },
    /// A person takes over: a block, or an approval Access asked for (E51, E47 (4)).
    Handoff {
        /// The step.
        step: u32,
        /// `blocked` or `approval`.
        reason: String,
        /// When the job stops if nobody answered.
        until: u64,
        /// When.
        at: u64,
    },
    /// A semantic event: the next step is asked again (§7.9.7.2).
    Semantic {
        /// The step.
        step: u32,
        /// When.
        at: u64,
    },
    /// Pause or stop asked for.
    Requested {
        /// Which.
        control: Request,
        /// Why: `person`, `decision`, `horizon`, `envelope`, `silence`, `cancel`, `release`
        /// or `report`.
        reason: String,
        /// When.
        at: u64,
    },
    /// A step's cancel inside its window.
    Cancelled {
        /// The step.
        step: u32,
        /// When.
        at: u64,
    },
    /// The executor confirmed a pause or stop with an `executor_control` Claim (U5).
    Confirmed {
        /// Which.
        state: Confirmed,
        /// The `ClaimID`.
        #[serde(with = "b64::bytes")]
        claim: Vec<u8>,
        /// When.
        at: u64,
    },
    /// Resumed: going on is a new Access decision (E63 (2)).
    Resumed {
        /// When.
        at: u64,
    },
    /// The job was picked up again after a crash or a takeover (§7.9.7.2).
    Recovered {
        /// When.
        at: u64,
    },
}

/// One step as the history leaves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The spec.
    pub spec: StepSpec,
    /// The `StepRef`.
    pub step: Digest,
    /// The idempotency key.
    pub key: Digest,
    /// The delayed-commit window's end.
    pub window_until: Option<u64>,
    /// The outbox request digest.
    pub outbox: Option<[u8; 32]>,
    /// Whether it was sent again once.
    pub resent: bool,
    /// The upstream answer: status, body digest and reading.
    pub answered: Option<(u16, [u8; 32], Reading)>,
    /// Whether no answer came.
    pub faulted: bool,
    /// The outcome and its evidence, with its time.
    pub outcome: Option<(Outcome, Vec<Evidence>, u64)>,
    /// The attestation's `ClaimID`, and the refusal if Ingest refused it.
    pub attested: Option<(Vec<u8>, Option<String>)>,
    /// Whether a cancel was asked for.
    pub cancelled: bool,
}

/// A job as its history leaves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// The first event.
    pub started: Started,
    /// The intent envelope.
    pub envelope: IntentEnvelope,
    /// Its digest.
    pub intent: Digest,
    /// The steps.
    pub steps: Vec<Step>,
    /// Unused continuation statements, oldest first.
    pub continuations: VecDeque<Vec<u8>>,
    /// Checkpoints decided.
    pub checkpoints: u32,
    /// Whether Access must be asked before the next effect.
    pub recheck_due: bool,
    /// The refusal of the last checkpoint.
    pub refused: Option<String>,
    /// The open handoff: step, reason, deadline.
    pub handoff: Option<(u32, String, u64)>,
    /// Whether a pause was asked for and not yet resumed.
    pub pause_requested: bool,
    /// Whether a stop was asked for, and why.
    pub stop_requested: Option<String>,
    /// The confirmed control state.
    pub confirmed: Option<Confirmed>,
    /// The released token's end of use.
    pub released_until: Option<u64>,
    /// Events read.
    pub len: usize,
}

/// Why a history does not fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HistoryError {
    /// It does not begin with `Started`, or begins twice.
    #[error("executor-history-start")]
    Start,
    /// An event names a step the job does not have.
    #[error("executor-history-step")]
    Step,
    /// The envelope does not decode.
    #[error("executor-history-intent")]
    Intent,
}

impl Job {
    /// Folds a history (E62 (1)): the same events always give the same job.
    ///
    /// # Errors
    /// [`HistoryError`].
    pub fn replay(events: &[Event]) -> Result<Self, HistoryError> {
        let (first, rest) = events.split_first().ok_or(HistoryError::Start)?;
        let Event::Started(started) = first else {
            return Err(HistoryError::Start);
        };
        let envelope =
            IntentEnvelope::from_bytes(&started.intent).map_err(|_| HistoryError::Intent)?;
        let intent = intent_digest(&envelope).map_err(|_| HistoryError::Intent)?;
        let exercise = Digest(started.exercise);
        let steps = started
            .steps
            .iter()
            .enumerate()
            .map(|(i, spec)| {
                let index = u32::try_from(i).map_err(|_| HistoryError::Step)?;
                let step = step_ref(&exercise, index, spec);
                Ok(Step {
                    spec: spec.clone(),
                    step,
                    key: idempotency_key(&exercise, &step),
                    window_until: None,
                    outbox: None,
                    resent: false,
                    answered: None,
                    faulted: false,
                    outcome: None,
                    attested: None,
                    cancelled: false,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut job = Self {
            started: (**started).clone(),
            envelope,
            intent,
            steps,
            continuations: VecDeque::new(),
            checkpoints: 0,
            recheck_due: false,
            refused: None,
            handoff: None,
            pause_requested: false,
            stop_requested: None,
            confirmed: None,
            released_until: None,
            len: 1,
        };
        for e in rest {
            job.apply(e)?;
        }
        Ok(job)
    }

    fn step_mut(&mut self, step: u32) -> Result<&mut Step, HistoryError> {
        let i = usize::try_from(step).map_err(|_| HistoryError::Step)?;
        self.steps.get_mut(i).ok_or(HistoryError::Step)
    }

    /// Applies one more event.
    ///
    /// # Errors
    /// [`HistoryError`].
    pub fn apply(&mut self, e: &Event) -> Result<(), HistoryError> {
        match e {
            Event::Started(_) => return Err(HistoryError::Start),
            Event::Continuations { ais } => self.continuations.extend(ais.iter().cloned()),
            Event::Decided { allowed, code, .. } => {
                self.continuations.pop_front();
                self.checkpoints = self.checkpoints.saturating_add(1);
                if *allowed {
                    self.recheck_due = false;
                    self.refused = None;
                } else {
                    self.refused = Some(code.clone());
                }
            }
            Event::WindowOpened { step, until } => {
                self.step_mut(*step)?.window_until = Some(*until);
            }
            Event::Released { use_until, .. } => self.released_until = Some(*use_until),
            Event::Outbox { step, request, .. } => {
                self.step_mut(*step)?.outbox = Some(*request);
            }
            Event::Resent { step, .. } => {
                self.step_mut(*step)?.resent = true;
            }
            Event::Answered {
                step,
                status,
                body,
                reading,
                ..
            } => self.step_mut(*step)?.answered = Some((*status, *body, *reading)),
            Event::Faulted { step, .. } => self.step_mut(*step)?.faulted = true,
            Event::Outcome {
                step,
                outcome,
                evidence,
                at,
            } => self.step_mut(*step)?.outcome = Some((*outcome, evidence.clone(), *at)),
            Event::Attested {
                step,
                claim,
                refused,
                ..
            } => {
                let last = usize::try_from(*step)
                    .ok()
                    .and_then(|i| i.checked_add(1))
                    .is_some_and(|n| n >= self.steps.len());
                self.step_mut(*step)?.attested = Some((claim.clone(), refused.clone()));
                if !last {
                    self.recheck_due = true;
                }
            }
            Event::Handoff {
                step,
                reason,
                until,
                ..
            } => self.handoff = Some((*step, reason.clone(), *until)),
            Event::Requested {
                control, reason, ..
            } => match control {
                Request::Pause => self.pause_requested = true,
                Request::Stop => self.stop_requested = Some(reason.clone()),
            },
            Event::Cancelled { step, .. } => self.step_mut(*step)?.cancelled = true,
            Event::Confirmed { state, .. } => self.confirmed = Some(*state),
            Event::Resumed { .. } => {
                self.pause_requested = false;
                self.confirmed = None;
                self.handoff = None;
                self.refused = None;
                self.recheck_due = true;
            }
            Event::Semantic { .. } | Event::Recovered { .. } => self.recheck_due = true,
        }
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// The Exercise.
    #[must_use]
    pub const fn exercise(&self) -> Digest {
        Digest(self.started.exercise)
    }

    /// The domain.
    #[must_use]
    pub const fn domain(&self) -> Digest {
        Digest(self.started.domain)
    }

    /// The first step not yet reported, if any.
    #[must_use]
    pub fn current(&self) -> Option<usize> {
        self.steps.iter().position(|s| s.attested.is_none())
    }

    /// Whether every step is reported.
    #[must_use]
    pub fn completed(&self) -> bool {
        self.current().is_none()
    }

    /// Whether a request left and its answer is not in the history.
    #[must_use]
    pub fn in_flight(&self) -> bool {
        self.steps.iter().any(|s| {
            s.outbox.is_some() && s.answered.is_none() && !s.faulted && s.outcome.is_none()
        })
    }
}
