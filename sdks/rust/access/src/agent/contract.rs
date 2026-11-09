//! One intent under one nonce, as the agent contract has it (§8.18.2, A-1 to A-4, A-8 to A-10).

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::ais::Statement;
use access_kernel::combinator::{BlockerClass, Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, ParamValue, intent_digest};
use access_kernel::meta::{ExerciseBasis, exercise_id};
use access_kernel::model::{ActionRef, Id, ResourceRef};

use super::decision::{self, Answered, Blocker, Decision, Remediation, Route, Unmet, Unread};
use crate::authorize::{Actor, ExerciseRequest, MAX_NONCE, MIN_NONCE, adp_open};
use crate::transport::{Answer, Clock};

/// What an agent plans to do. Basis and capacity are options only so that a plan read from
/// configuration or a model's output is refused here when one is missing (A-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The exact intent.
    pub intent: IntentEnvelope,
    /// The declared basis.
    pub basis: Option<ExerciseBasis>,
    /// The declared capacity: `FOR(principal)` for the principal's work, `OWN` for the agent's own.
    pub capacity: Option<Capacity>,
}

/// Why the agent may not ask, or may not go on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// No capacity was declared (A-1).
    #[error("capacity")]
    Capacity,
    /// No basis was declared for a commit (A-1, §9.5 rule 4).
    #[error("basis")]
    Basis,
    /// The nonce is not 16 to 64 bytes, or a renewal reuses the old one.
    #[error("nonce")]
    Nonce,
    /// The intent cannot be encoded.
    #[error("intent")]
    Intent,
    /// The nonce was closed by a DENY (A-3, C30).
    #[error("nonce-closed")]
    NonceClosed,
    /// A new nonce without a change of state (A-3).
    #[error("no-state-change")]
    NoStateChange,
    /// The ALLOW was for another envelope (A-2, INV-19).
    #[error("envelope-changed")]
    EnvelopeChanged,
    /// A proof outside a `REQUIRE_ACTION` wait (A-4).
    #[error("not-waiting")]
    NotWaiting,
    /// The intent splits a refused one under its amount (A-9).
    #[error("structuring")]
    Structuring,
    /// The long-running work was stopped by its continuation (A-8).
    #[error("stopped")]
    Stopped,
    /// The Instance key did not sign.
    #[error("signature")]
    Signature,
    /// No trusted time.
    #[error("clock")]
    Clock,
}

/// The agent Instance's key: signs the Actor Intent Statement as `COSE_Sign1` (§9.5 k.2).
pub trait Signs {
    /// The signed statement; `None` when the key cannot sign.
    fn sign(&self, statement: &Statement) -> Option<Vec<u8>>;
}

/// The decision point port: one ADP evaluation body in, the answer out.
pub trait Adp {
    /// Sends the body; a fault is reported, never decided.
    fn evaluate(&self, body: &str) -> Answer;
}

/// A proof the agent adds to a waiting request (A-4, A-5): a recorded contribution, a Claim, or
/// a Claim reference. There is no proof made of text, a chat answer, an elicitation result or
/// an Approval Act Statement the agent writes itself: approval comes only from the user's own
/// Instance on a trusted surface (EI-18, AGI-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proof {
    /// The `contribute` Exercise a person recorded.
    Contribution(Digest),
    /// A signed Claim.
    Claim(Vec<u8>),
    /// A Claim already recorded.
    ClaimRef(Id),
}

/// A change of state that makes a new nonce meaningful after a DENY (A-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// A new basis, such as a Grant someone gave since.
    NewGrant(ExerciseBasis),
    /// A fresh Claim.
    FreshClaim(Vec<u8>),
    /// The budget window the DENY named has reset.
    BudgetReset,
}

/// A verified-by-Access ALLOW for exactly one envelope (A-2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowed {
    exercise: Digest,
    intent: Digest,
}

impl Allowed {
    /// The Exercise.
    #[must_use]
    pub const fn exercise(&self) -> &Digest {
        &self.exercise
    }

    /// The intent digest it allows.
    #[must_use]
    pub const fn intent(&self) -> &Digest {
        &self.intent
    }

    /// Whether `envelope` is the envelope allowed; any changed parameter is another intent.
    #[must_use]
    pub fn covers(&self, envelope: &IntentEnvelope) -> bool {
        intent_digest(envelope).is_ok_and(|d| d == self.intent)
    }

    /// The Exercise for an effect of `envelope`.
    ///
    /// # Errors
    /// [`AgentError::EnvelopeChanged`].
    pub fn effect(&self, envelope: &IntentEnvelope) -> Result<&Digest, AgentError> {
        if self.covers(envelope) {
            Ok(&self.exercise)
        } else {
            Err(AgentError::EnvelopeChanged)
        }
    }
}

/// A `REQUIRE_ACTION` the agent waits on, with the same nonce (A-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wait {
    /// Where each term goes.
    pub routes: Vec<Route>,
    /// The unmet terms.
    pub unmet: Vec<Unmet>,
    /// The waiting blockers.
    pub blockers: Vec<Blocker>,
}

/// A DENY: terminal for this nonce (A-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stopped {
    /// Every blocker.
    pub blockers: Vec<Blocker>,
}

impl Stopped {
    /// When a `budget-exhausted` window resets, if the DENY named one.
    #[must_use]
    pub fn resets_at(&self) -> Option<u64> {
        self.blockers
            .iter()
            .filter(|b| b.class == BlockerClass::BudgetExhausted)
            .filter_map(|b| match b.remediation {
                Some(Remediation::WaitUntil(t)) => Some(t),
                _ => None,
            })
            .max()
    }
}

/// What the agent does next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Proceed with this envelope only.
    Proceed(Allowed),
    /// Wait for a proof on the same nonce; send the typed request to the coordinator.
    Wait(Wait),
    /// Stop: the nonce is closed.
    Stop(Stopped),
    /// No decision: nothing happens.
    Unknown(Unread),
}

/// An advisory answer to `check` (A-10, L17): planning data that is never cached as a
/// credential and never turns into an [`Allowed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advisory {
    /// Whether the check said ALLOW.
    pub allowed: bool,
    /// The routes of a `REQUIRE_ACTION`.
    pub routes: Vec<Route>,
    /// The blocker classes of a DENY.
    pub classes: Vec<BlockerClass>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Open,
    Waiting,
    Allowed,
    Closed(Stopped),
}

/// One intent under one nonce.
#[derive(Clone, Debug)]
pub struct Exercise {
    domain: Digest,
    pep: String,
    envelope: IntentEnvelope,
    digest: Digest,
    basis: ExerciseBasis,
    capacity: Capacity,
    nonce: Vec<u8>,
    proofs: Vec<Proof>,
    state: State,
}

fn checked_nonce(nonce: Vec<u8>) -> Result<Vec<u8>, AgentError> {
    if (MIN_NONCE..=MAX_NONCE).contains(&nonce.len()) {
        Ok(nonce)
    } else {
        Err(AgentError::Nonce)
    }
}

fn proof_json(out: &mut crate::authorize::Out, p: &Proof) {
    out.0.push('{');
    match p {
        Proof::Contribution(d) => {
            out.key("contribution");
            out.digest(d);
        }
        Proof::Claim(b) => {
            out.key("claim");
            out.bytes(b);
        }
        Proof::ClaimRef(id) => {
            out.key("claim_ref");
            out.id(id);
        }
    }
    out.0.push('}');
}

impl Exercise {
    /// A request for `plan` under `nonce` in `domain`, through the PEP `pep` (A-1).
    ///
    /// # Errors
    /// [`AgentError::Capacity`], [`AgentError::Basis`], [`AgentError::Nonce`],
    /// [`AgentError::Intent`].
    pub fn new(domain: Digest, pep: &str, plan: Plan, nonce: Vec<u8>) -> Result<Self, AgentError> {
        let capacity = plan.capacity.ok_or(AgentError::Capacity)?;
        let basis = plan.basis.ok_or(AgentError::Basis)?;
        let digest = intent_digest(&plan.intent).map_err(|_| AgentError::Intent)?;
        Ok(Self {
            domain,
            pep: String::from(pep),
            envelope: plan.intent,
            digest,
            basis,
            capacity,
            nonce: checked_nonce(nonce)?,
            proofs: Vec::new(),
            state: State::Open,
        })
    }

    /// The intent digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The intent.
    #[must_use]
    pub const fn envelope(&self) -> &IntentEnvelope {
        &self.envelope
    }

    /// The nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// The domain.
    #[must_use]
    pub const fn domain(&self) -> &Digest {
        &self.domain
    }

    /// The declared capacity.
    #[must_use]
    pub const fn capacity(&self) -> Capacity {
        self.capacity
    }

    /// The declared basis.
    #[must_use]
    pub const fn basis(&self) -> &ExerciseBasis {
        &self.basis
    }

    /// The Exercise this nonce names.
    #[must_use]
    pub fn exercise_ref(&self) -> Option<Digest> {
        exercise_id(&self.domain, &self.nonce).ok()
    }

    /// The statement the Instance signs for `mode` at `now`, over `nonce`.
    #[must_use]
    pub fn statement(
        &self,
        mode: Mode,
        nonce: &[u8],
        continued: Option<Digest>,
        now: u64,
    ) -> Statement {
        Statement {
            domain: self.domain,
            nonce: nonce.to_vec(),
            intent: self.digest,
            mode,
            pep: self.pep.clone(),
            capacity: self.capacity,
            basis: self.basis,
            iat: now,
            exercise: continued,
        }
    }

    /// The ADP body for `mode` over `nonce`, signed by the Instance, with the proofs added so far.
    fn body(&self, statement: &Statement, ais: Vec<u8>) -> Option<String> {
        let actor = Actor::Statement(ais);
        let request = ExerciseRequest {
            domain: &self.domain,
            mode: statement.mode,
            nonce: &statement.nonce,
            intent: &self.digest,
            envelope: Some(&self.envelope),
            actor: &actor,
            basis: &self.basis,
            capacity: self.capacity,
            pep: &self.pep,
            exercise: statement.exercise.as_ref(),
        };
        let mut out = adp_open(&request)?;
        if !self.proofs.is_empty() && statement.mode != Mode::Continue {
            out.0.push(',');
            out.key("proofs");
            out.0.push('[');
            let mut first = true;
            for p in &self.proofs {
                out.comma(&mut first);
                proof_json(&mut out, p);
            }
            out.0.push(']');
        }
        out.0.push_str("}}");
        Some(out.0)
    }

    fn signed_body(
        &self,
        mode: Mode,
        nonce: &[u8],
        continued: Option<Digest>,
        signer: &impl Signs,
        clock: &impl Clock,
    ) -> Result<String, AgentError> {
        let now = clock.now().ok_or(AgentError::Clock)?;
        let statement = self.statement(mode, nonce, continued, now);
        let ais = signer.sign(&statement).ok_or(AgentError::Signature)?;
        self.body(&statement, ais).ok_or(AgentError::Intent)
    }

    /// Asks Access to `commit` this intent under its nonce and reads the answer.
    ///
    /// # Errors
    /// [`AgentError::NonceClosed`] after a DENY (A-3), [`AgentError::Clock`],
    /// [`AgentError::Signature`].
    pub fn ask(
        &mut self,
        adp: &impl Adp,
        signer: &impl Signs,
        clock: &impl Clock,
    ) -> Result<Step, AgentError> {
        if matches!(self.state, State::Closed(_)) {
            return Err(AgentError::NonceClosed);
        }
        let body = self.signed_body(Mode::Commit, &self.nonce, None, signer, clock)?;
        let answer = adp.evaluate(&body);
        Ok(self.answered(&answer))
    }

    fn answered(&mut self, answer: &Answer) -> Step {
        let read = match decision::read(answer) {
            Ok(a) => a,
            Err(e) => return Step::Unknown(e),
        };
        // A-10, L17
        if read.advisory {
            return Step::Unknown(Unread::Malformed);
        }
        let routes = read.decision.routes();
        match read.decision {
            Decision::Allow { exercise } => {
                let Some(own) = self.exercise_ref() else {
                    return Step::Unknown(Unread::Malformed);
                };
                if exercise.is_some_and(|e| e != own) {
                    return Step::Unknown(Unread::Malformed);
                }
                self.state = State::Allowed;
                Step::Proceed(Allowed {
                    exercise: own,
                    intent: self.digest,
                })
            }
            Decision::Deny { blockers } => {
                let stopped = Stopped { blockers };
                self.state = State::Closed(stopped.clone());
                Step::Stop(stopped)
            }
            Decision::RequireAction { unmet, blockers } => {
                self.state = State::Waiting;
                Step::Wait(Wait {
                    routes,
                    unmet,
                    blockers,
                })
            }
        }
    }

    /// Adds a proof to a waiting request; the next [`Exercise::ask`] uses the same nonce (A-4).
    ///
    /// # Errors
    /// [`AgentError::NotWaiting`].
    pub fn prove(&mut self, proof: Proof) -> Result<(), AgentError> {
        if self.state != State::Waiting {
            return Err(AgentError::NotWaiting);
        }
        if !self.proofs.contains(&proof) {
            self.proofs.push(proof);
        }
        Ok(())
    }

    /// A new request for the same plan under a new nonce, after a DENY and a change of state
    /// (A-3): a new basis different from the old one, a fresh Claim, or a budget window that
    /// has reset by `now`. Without one there is no retry.
    ///
    /// # Errors
    /// [`AgentError::NoStateChange`], [`AgentError::Nonce`].
    pub fn renew(&self, change: Change, nonce: Vec<u8>, now: u64) -> Result<Self, AgentError> {
        let State::Closed(stopped) = &self.state else {
            return Err(AgentError::NoStateChange);
        };
        let nonce = checked_nonce(nonce)?;
        if nonce == self.nonce {
            return Err(AgentError::Nonce);
        }
        let mut next = Self {
            nonce,
            proofs: Vec::new(),
            state: State::Open,
            ..self.clone()
        };
        match change {
            Change::NewGrant(basis) if basis != self.basis => next.basis = basis,
            Change::FreshClaim(claim) => next.proofs.push(Proof::Claim(claim)),
            Change::BudgetReset if stopped.resets_at().is_some_and(|t| now >= t) => {}
            _ => return Err(AgentError::NoStateChange),
        }
        Ok(next)
    }

    /// Asks Access `check` under `nonce` (A-10): advisory, never recorded, never an ALLOW for
    /// this request.
    ///
    /// # Errors
    /// [`AgentError::Clock`], [`AgentError::Signature`], [`AgentError::Nonce`]. An answer that
    /// cannot be read, or that is not advisory, is the inner [`Unread`].
    pub fn check(
        &self,
        nonce: Vec<u8>,
        adp: &impl Adp,
        signer: &impl Signs,
        clock: &impl Clock,
    ) -> Result<Result<Advisory, Unread>, AgentError> {
        let nonce = checked_nonce(nonce)?;
        let body = self.signed_body(Mode::Check, &nonce, None, signer, clock)?;
        let read = match decision::read(&adp.evaluate(&body)) {
            Ok(r) if r.advisory => r,
            Ok(_) => return Ok(Err(Unread::Malformed)),
            Err(e) => return Ok(Err(e)),
        };
        let routes = read.decision.routes();
        Ok(Ok(match read.decision {
            Decision::Allow { .. } => Advisory {
                allowed: true,
                routes,
                classes: Vec::new(),
            },
            Decision::Deny { blockers } => Advisory {
                allowed: false,
                routes,
                classes: blockers.iter().map(|b| b.class).collect(),
            },
            Decision::RequireAction { .. } => Advisory {
                allowed: false,
                routes,
                classes: Vec::new(),
            },
        }))
    }
}

/// A long-running effect's continuation (A-8, E31, AG-15): asked before the horizon, at the
/// half-way point, at each declared checkpoint and after a pause or a takeover. A DENY or an
/// unknown answer stops it for good: no new consequential effect starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation {
    exercise: Digest,
    started: u64,
    horizon: u64,
    checkpoints: Vec<u64>,
    last: u64,
    interrupted: bool,
    stopped: bool,
}

impl Continuation {
    /// The continuation of `allowed` from `now` until `horizon`, with `checkpoints`.
    #[must_use]
    pub fn new(allowed: &Allowed, now: u64, horizon: u64, mut checkpoints: Vec<u64>) -> Self {
        checkpoints.retain(|c| *c > now && *c < horizon);
        checkpoints.sort_unstable();
        Self {
            exercise: allowed.exercise,
            started: now,
            horizon,
            checkpoints,
            last: now,
            interrupted: false,
            stopped: false,
        }
    }

    /// The Exercise continued.
    #[must_use]
    pub const fn exercise(&self) -> &Digest {
        &self.exercise
    }

    /// The horizon.
    #[must_use]
    pub const fn horizon(&self) -> u64 {
        self.horizon
    }

    /// The work was paused or taken over; the next step needs a continuation first.
    pub const fn interrupted(&mut self) {
        self.interrupted = true;
    }

    /// Whether a `continue` is due at `now`.
    #[must_use]
    pub fn due(&self, now: u64) -> bool {
        let half = self
            .started
            .saturating_add(self.horizon.saturating_sub(self.started) / 2);
        self.interrupted
            || (self.last < half && now >= half)
            || self.checkpoints.iter().any(|c| *c > self.last && *c <= now)
            || now >= self.horizon
    }

    /// Whether a new consequential effect may start at `now`.
    #[must_use]
    pub fn may_start(&self, now: u64) -> bool {
        !self.stopped && now < self.horizon && !self.due(now)
    }

    /// Asks `continue` for `exercise` under a fresh `nonce`. Only an ALLOW keeps the work going;
    /// anything else stops it.
    ///
    /// # Errors
    /// [`AgentError::Stopped`] once stopped, [`AgentError::Clock`], [`AgentError::Signature`],
    /// [`AgentError::Nonce`].
    pub fn ask(
        &mut self,
        exercise: &Exercise,
        nonce: Vec<u8>,
        adp: &impl Adp,
        signer: &impl Signs,
        clock: &impl Clock,
    ) -> Result<bool, AgentError> {
        if self.stopped {
            return Err(AgentError::Stopped);
        }
        let nonce = checked_nonce(nonce)?;
        let now = clock.now().ok_or(AgentError::Clock)?;
        let body =
            exercise.signed_body(Mode::Continue, &nonce, Some(self.exercise), signer, clock)?;
        let go = matches!(
            decision::read(&adp.evaluate(&body)),
            Ok(Answered {
                decision: Decision::Allow { .. },
                advisory: false
            })
        ) && now < self.horizon;
        if go {
            self.last = now;
            self.interrupted = false;
        } else {
            self.stopped = true;
        }
        Ok(go)
    }
}

/// A refused intent, kept to refuse its splits (A-9).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Refused {
    action: ActionRef,
    resources: Vec<ResourceRef>,
    amounts: Vec<(String, String, i64)>,
}

fn amounts(e: &IntentEnvelope) -> Vec<(String, String, i64)> {
    e.params
        .iter()
        .filter_map(|(k, v)| match v {
            ParamValue::Amount { value, unit } => Some((k.clone(), unit.clone(), *value)),
            ParamValue::Count(n) => i64::try_from(*n)
                .ok()
                .map(|n| (k.clone(), String::from("count"), n)),
            _ => None,
        })
        .collect()
}

/// The agent's refused intents in one session (A-9): an intent of the same action on the same
/// resources whose amount is below a refused one is a split, and the agent sends the refused
/// request to its coordinator instead. Lineage budgets make a split useless on the Access side
/// as well (C27).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Refusals {
    refused: Vec<Refused>,
}

impl Refusals {
    /// No refusals yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            refused: Vec::new(),
        }
    }

    /// Records `exercise` when `step` refused it or made it wait.
    pub fn record(&mut self, exercise: &Exercise, step: &Step) {
        if matches!(step, Step::Stop(_) | Step::Wait(_)) {
            let e = exercise.envelope();
            self.refused.push(Refused {
                action: e.action.clone(),
                resources: e.resources.clone(),
                amounts: amounts(e),
            });
        }
    }

    /// Whether `plan` may be asked.
    ///
    /// # Errors
    /// [`AgentError::Structuring`].
    pub fn admit(&self, plan: &Plan) -> Result<(), AgentError> {
        let e = &plan.intent;
        let asked = amounts(e);
        let split = self.refused.iter().any(|r| {
            r.action == e.action
                && r.resources == e.resources
                && asked.iter().any(|(k, u, v)| {
                    r.amounts
                        .iter()
                        .any(|(rk, ru, rv)| rk == k && ru == u && v < rv)
                })
        });
        if split {
            Err(AgentError::Structuring)
        } else {
            Ok(())
        }
    }
}
