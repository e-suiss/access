//! The executor's use cases (B21, AG-40, E62–E64, U5): start a job under an allowed Exercise,
//! advance it one durable step at a time, report every outcome and confirm every pause and stop.
//! Every effect waits for a verified ALLOW from Access, asked with the actor's own statement;
//! the executor's operator is never the actor and the executor never decides (Ek B 4340, 4600).

use std::collections::BTreeMap;
use std::sync::Mutex;

use access_kernel::ais::Statement as Ais;
use access_kernel::claim::{CONTENT_TYPE, claim_id};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::exercise_id;
use access_kernel::verify::cose::{Algorithm, parse_sign1};
use access_kernel::verify::key_scope::{DomainMetadata, thumbprint};
use access_sdk::authorize::{
    Actor, Ask, AskDecision, Denied, ExerciseRequest, Intent, Nonce, Pep, Refusal, adp_body,
};
use access_sdk::transport::{Answer, FixedClock};
use serde_json::{Value, json};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer, sign_sign1};

use crate::domain::attest::{self, Report, Reporter};
use crate::domain::history::{Confirmed, Event, Job, Outcome, Request, Started};
use crate::domain::machine::{Follow, Next, next};
use crate::domain::step::{StepSpec, check_steps};
use crate::domain::webbot::{self, Params};
use crate::domain::{COMMIT_WINDOW_MS, HANDOFF_WAIT_MS, Kind, MAX_CONTINUATIONS};
use crate::drivers::{self, HttpRequest};
use crate::ports::{Access, Clock, Random, Upstream};
use crate::store::{Store, StoreError};

/// Why a call did not do what it asked; the job is as it was.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The request is out of shape.
    #[error("{0}")]
    Malformed(&'static str),
    /// Access did not allow the Exercise; no job was opened (AG-40).
    #[error("executor-not-allowed: {0}")]
    NotAllowed(String),
    /// No such job.
    #[error("executor-unknown-job")]
    Unknown,
    /// The job is not in a state that allows this.
    #[error("{0}")]
    Conflict(&'static str),
    /// Access, the vault, the clock or the store did not answer: nothing happened.
    #[error("executor-unavailable: {0}")]
    Unavailable(String),
    /// Another runner moved the job on; read it again.
    #[error("executor-stale")]
    Stale,
}

impl From<StoreError> for ExecError {
    fn from(e: StoreError) -> Self {
        Self::Unavailable(e.to_string())
    }
}

impl ExecError {
    /// The stable problem code.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Malformed(c) | Self::Conflict(c) => c,
            Self::NotAllowed(_) => "executor-not-allowed",
            Self::Unknown => "executor-unknown-job",
            Self::Unavailable(_) => "executor-unavailable",
            Self::Stale => "executor-stale",
        }
    }
}

/// The executor's fixed identity.
#[derive(Clone, Debug)]
pub struct Config {
    /// The PEP name Access knows this executor by: its client certificate's `x5t#S256`, the
    /// name a Resource lists among its executors (OP-154 m.12 (a)).
    pub pep: String,
    /// The kind.
    pub kind: Kind,
    /// The operator Party and the executor Instance.
    pub reporter: Reporter,
    /// The Web Bot Auth directory `Signature-Agent` names: Suiss's, never the person's.
    pub signature_agent: String,
}

/// Released tokens of this process, kept in memory only and never written (AG-40 (5)).
#[derive(Default)]
pub struct Tokens(Mutex<BTreeMap<[u8; 16], Held>>);

type Held = (Secret<String>, u64);

impl Tokens {
    fn live(&self, job: [u8; 16], now: u64) -> bool {
        self.0
            .lock()
            .is_ok_and(|m| m.get(&job).is_some_and(|(_, until)| now < *until))
    }

    fn get(&self, job: [u8; 16]) -> Option<String> {
        self.0
            .lock()
            .ok()?
            .get(&job)
            .map(|(t, _)| t.expose().clone())
    }

    fn put(&self, job: [u8; 16], token: String, until: u64) {
        if let Ok(mut m) = self.0.lock() {
            m.insert(job, (Secret::new(token), until));
        }
    }

    fn drop_job(&self, job: [u8; 16]) {
        if let Ok(mut m) = self.0.lock() {
            m.remove(&job);
        }
    }
}

/// A start request: the actor's commit statement for this executor as PEP, the envelope, the
/// vault connection and the steps.
#[derive(Clone, Debug)]
pub struct Start {
    /// The realm whose vault holds the connection.
    pub realm: String,
    /// The vault connection.
    pub connection: String,
    /// The envelope's canonical bytes.
    pub intent: Vec<u8>,
    /// The actor's `commit` AIS naming this executor as PEP.
    pub ais: Vec<u8>,
    /// The steps.
    pub steps: Vec<StepSpec>,
    /// `continue` statements for the checkpoints ahead.
    pub continuations: Vec<Vec<u8>>,
}

struct Prefetched(Answer);

impl AskDecision for Prefetched {
    fn ask(&self, _: &ExerciseRequest<'_>) -> Answer {
        self.0.clone()
    }
}

fn statement(ais: &[u8]) -> Result<Ais, ExecError> {
    parse_sign1(ais)
        .ok()
        .and_then(|s| s.payload)
        .and_then(|p| Ais::from_bytes(&p).ok())
        .ok_or(ExecError::Malformed("executor-ais"))
}

fn body_json(a: &Answer) -> Option<(u16, Value)> {
    match a {
        Answer::Response(r) => Some((
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )),
        Answer::Unanswered(_) => None,
    }
}

/// What a checkpoint decided.
enum Verdict {
    Allowed,
    Refused(String),
}

/// The executor over its ports.
pub struct Executor<A, U, C, R, S> {
    store: Store,
    access: A,
    upstream: U,
    clock: C,
    random: R,
    signer: S,
    config: Config,
    tokens: std::sync::Arc<Tokens>,
    metadata: Mutex<BTreeMap<[u8; 32], DomainMetadata>>,
}

impl<A: Access, U: Upstream, C: Clock, R: Random, S: Signer + Send + Sync> Executor<A, U, C, R, S> {
    /// An executor. `tokens` is this process's token memory; a new process starts empty, so a
    /// request whose answer a crash lost is then `unknown` (TI-6, AG-40 (5)).
    pub fn new(
        (store, access, upstream): (Store, A, U),
        (clock, random, signer): (C, R, S),
        config: Config,
        tokens: std::sync::Arc<Tokens>,
    ) -> Self {
        Self {
            store,
            access,
            upstream,
            clock,
            random,
            signer,
            config,
            tokens,
            metadata: Mutex::new(BTreeMap::new()),
        }
    }

    /// The configuration.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    fn now(&self) -> Result<u64, ExecError> {
        self.clock
            .now()
            .ok_or_else(|| ExecError::Unavailable(String::from("clock")))
    }

    async fn pinned(&self, domain: Digest) -> Result<DomainMetadata, ExecError> {
        if let Some(m) = self
            .metadata
            .lock()
            .ok()
            .and_then(|m| m.get(&domain.0).cloned())
        {
            return Ok(m);
        }
        let answer = self.access.metadata(b64url_encode(&domain.0)).await;
        let m = match answer {
            Answer::Response(r) if r.status == 200 => parse_sign1(&r.body)
                .ok()
                .and_then(|s| s.payload)
                .and_then(|p| DomainMetadata::from_bytes(&p).ok())
                .ok_or_else(|| ExecError::Unavailable(String::from("metadata")))?,
            _ => return Err(ExecError::Unavailable(String::from("metadata"))),
        };
        if let Ok(mut cache) = self.metadata.lock() {
            cache.insert(domain.0, m.clone());
        }
        Ok(m)
    }

    /// Asks Access for `ais` over `envelope` with this executor as PEP and verifies the answer
    /// (§9.5): only a verified ALLOW for this intent, this PEP and this Exercise is allowed.
    async fn decide(
        &self,
        ais: &[u8],
        s: &Ais,
        envelope: &IntentEnvelope,
        continued: Option<&Digest>,
        now: u64,
    ) -> Result<Verdict, ExecError> {
        let digest =
            intent_digest(envelope).map_err(|_| ExecError::Malformed("executor-intent"))?;
        let actor = Actor::Statement(ais.to_vec());
        let request = ExerciseRequest {
            domain: &s.domain,
            mode: if continued.is_some() {
                Mode::Continue
            } else {
                Mode::Commit
            },
            nonce: &s.nonce,
            intent: &digest,
            envelope: Some(envelope),
            actor: &actor,
            basis: &s.basis,
            capacity: s.capacity,
            pep: &self.config.pep,
            exercise: continued,
        };
        let body = adp_body(&request).ok_or(ExecError::Malformed("executor-request"))?;
        let metadata = self.pinned(s.domain).await?;
        let answer = self.access.evaluate(body.into_bytes()).await;
        let pep = Pep {
            audience: self.config.pep.clone(),
            domain: s.domain,
            metadata,
        };
        let intent = Intent::<(), ()>::named(envelope.clone())
            .map_err(|_| ExecError::Malformed("executor-intent"))?;
        let nonce =
            Nonce::new(s.nonce.clone()).map_err(|_| ExecError::Malformed("executor-nonce"))?;
        let ask = Ask {
            intent: &intent,
            nonce: &nonce,
            actor: &actor,
            basis: &s.basis,
            capacity: s.capacity,
            continued,
            content_position: None,
        };
        match pep.authorize(&ask, &FixedClock(now), &Prefetched(answer)) {
            Ok(_) => Ok(Verdict::Allowed),
            Err(Denied::Refused(Refusal::RequireAction)) => {
                Ok(Verdict::Refused(String::from("require_action")))
            }
            Err(Denied::Refused(_)) => Ok(Verdict::Refused(String::from("deny"))),
            Err(Denied::Status(s)) if s < 500 => Ok(Verdict::Refused(format!("status-{s}"))),
            Err(
                e
                @ (Denied::Clock | Denied::Unavailable(_) | Denied::Status(_) | Denied::Malformed),
            ) => Err(ExecError::Unavailable(String::from(e.code()))),
            Err(e) => Ok(Verdict::Refused(String::from(e.code()))),
        }
    }

    async fn load(&self, job: [u8; 16]) -> Result<Job, ExecError> {
        let rows = self.store.history(job).await?;
        if rows.is_empty() {
            return Err(ExecError::Unknown);
        }
        let events = rows
            .iter()
            .map(|r| serde_json::from_str::<Event>(r))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ExecError::Unavailable(String::from("history")))?;
        Job::replay(&events).map_err(|_| ExecError::Unavailable(String::from("history")))
    }

    /// A job's folded history.
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn job(&self, job: [u8; 16]) -> Result<Job, ExecError> {
        self.load(job).await
    }

    fn text(e: &Event) -> Result<String, ExecError> {
        serde_json::to_string(e).map_err(|_| ExecError::Unavailable(String::from("encode")))
    }

    /// Appends `e` right after what `job` has seen, or fails as stale (TI-6).
    async fn put(&self, job: &Job, e: &Event) -> Result<(), ExecError> {
        let seq =
            i32::try_from(job.len).map_err(|_| ExecError::Conflict("executor-history-full"))?;
        if self
            .store
            .append_at(job.started.job, seq, &Self::text(e)?)
            .await?
        {
            Ok(())
        } else {
            Err(ExecError::Stale)
        }
    }

    async fn record(&self, job: [u8; 16], e: &Event) -> Result<(), ExecError> {
        self.store.append(job, &Self::text(e)?).await?;
        Ok(())
    }

    /// Starts a job (AG-40, E62): the actor's commit statement must name this executor as PEP
    /// and the envelope; the Exercise is committed through Access and only a verified ALLOW
    /// opens the job. Starting the same Exercise again answers the job that runs it.
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn start(&self, req: Start) -> Result<[u8; 16], ExecError> {
        check_steps(&req.steps).map_err(|e| {
            ExecError::Malformed(if matches!(e, crate::domain::step::StepError::Count) {
                "executor-steps"
            } else {
                "executor-step"
            })
        })?;
        if req.continuations.len() > MAX_CONTINUATIONS
            || req.realm.is_empty()
            || req.connection.is_empty()
        {
            return Err(ExecError::Malformed("executor-malformed"));
        }
        let envelope = IntentEnvelope::from_bytes(&req.intent)
            .map_err(|_| ExecError::Malformed("executor-intent"))?;
        let s = statement(&req.ais)?;
        let digest =
            intent_digest(&envelope).map_err(|_| ExecError::Malformed("executor-intent"))?;
        // AG-40, Ek B 4340
        if s.mode != Mode::Commit
            || s.pep != self.config.pep
            || s.intent != digest
            || s.exercise.is_some()
        {
            return Err(ExecError::Malformed("executor-ais"));
        }
        for c in &req.continuations {
            let cs = statement(c)?;
            if cs.mode != Mode::Continue || cs.pep != self.config.pep || cs.intent != digest {
                return Err(ExecError::Malformed("executor-continuation"));
            }
        }
        let exercise =
            exercise_id(&s.domain, &s.nonce).map_err(|_| ExecError::Malformed("executor-nonce"))?;
        let now = self.now()?;
        // AG-40, Ek B 4600
        match self.decide(&req.ais, &s, &envelope, None, now).await? {
            Verdict::Allowed => {}
            Verdict::Refused(code) => return Err(ExecError::NotAllowed(code)),
        }
        let id = self
            .random
            .bytes()
            .ok_or_else(|| ExecError::Unavailable(String::from("random")))?;
        let first = Event::Started(Box::new(Started {
            job: id,
            kind: self.config.kind,
            domain: s.domain.0,
            exercise: exercise.0,
            intent: req.intent,
            ais: req.ais,
            realm: req.realm,
            connection: req.connection,
            steps: req.steps,
            commit_window_ms: COMMIT_WINDOW_MS,
            at: now,
        }));
        let (job, fresh) = self
            .store
            .create(
                id,
                (s.domain.0, exercise.0),
                self.config.kind.name(),
                &Self::text(&first)?,
            )
            .await?;
        if fresh && !req.continuations.is_empty() {
            self.record(
                job,
                &Event::Continuations {
                    ais: req.continuations,
                },
            )
            .await?;
        }
        Ok(job)
    }

    /// Asks for a pause at the next step (U5).
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn pause(&self, id: [u8; 16]) -> Result<(), ExecError> {
        let job = self.load(id).await?;
        if job.stop_requested.is_some() || job.completed() {
            return Err(ExecError::Conflict("executor-job-ended"));
        }
        let at = self.now()?;
        self.record(
            id,
            &Event::Requested {
                control: Request::Pause,
                reason: String::from("person"),
                at,
            },
        )
        .await
    }

    /// Asks for a stop: no further effect once confirmed (U5).
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn stop(&self, id: [u8; 16]) -> Result<(), ExecError> {
        let job = self.load(id).await?;
        if job.stop_requested.is_some() {
            return Ok(());
        }
        let at = self.now()?;
        self.record(
            id,
            &Event::Requested {
                control: Request::Stop,
                reason: String::from("person"),
                at,
            },
        )
        .await
    }

    /// Cancels an irreversible step that has not left (E47 (2)); the job then stops.
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn cancel(&self, id: [u8; 16], step: &[u8]) -> Result<(), ExecError> {
        let job = self.load(id).await?;
        let i = job
            .steps
            .iter()
            .position(|s| s.step.0[..] == *step)
            .ok_or(ExecError::Conflict("executor-unknown-step"))?;
        let s = job
            .steps
            .get(i)
            .ok_or(ExecError::Conflict("executor-unknown-step"))?;
        if s.outbox.is_some() || s.outcome.is_some() {
            return Err(ExecError::Conflict("executor-step-sent"));
        }
        let at = self.now()?;
        let step = u32::try_from(i).map_err(|_| ExecError::Conflict("executor-unknown-step"))?;
        self.record(id, &Event::Cancelled { step, at }).await
    }

    /// Resumes a paused job with new `continue` statements of the actor; going on is a new
    /// Access decision (E63 (2)).
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn resume(&self, id: [u8; 16], continuations: Vec<Vec<u8>>) -> Result<(), ExecError> {
        let job = self.load(id).await?;
        if job.stop_requested.is_some() || job.confirmed == Some(Confirmed::Stopped) {
            return Err(ExecError::Conflict("executor-job-ended"));
        }
        if job.confirmed != Some(Confirmed::Paused) && job.handoff.is_none() {
            return Err(ExecError::Conflict("executor-not-paused"));
        }
        if continuations.is_empty() || continuations.len() > MAX_CONTINUATIONS {
            return Err(ExecError::Malformed("executor-continuation"));
        }
        for c in &continuations {
            let cs = statement(c)?;
            if cs.mode != Mode::Continue
                || cs.pep != self.config.pep
                || cs.intent != job.intent
                || cs.exercise != Some(job.exercise())
            {
                return Err(ExecError::Malformed("executor-continuation"));
            }
        }
        let at = self.now()?;
        self.record(id, &Event::Continuations { ais: continuations })
            .await?;
        self.record(id, &Event::Resumed { at }).await
    }

    /// Picks a job up after a crash or a takeover: Access is asked again before its next
    /// effect (§7.9.7.2).
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn recover(&self, id: [u8; 16]) -> Result<(), ExecError> {
        let job = self.load(id).await?;
        if job.confirmed == Some(Confirmed::Stopped)
            || (job.completed() && job.stop_requested.is_none())
        {
            return Ok(());
        }
        let at = self.now()?;
        self.record(id, &Event::Recovered { at }).await
    }

    /// Advances the job until it waits, idles or is done.
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn drive(&self, id: [u8; 16]) -> Result<Next, ExecError> {
        for _ in 0..512 {
            match self.advance(id).await {
                Ok(n @ (Next::Done | Next::Idle | Next::Wait(_))) => return Ok(n),
                Ok(_) | Err(ExecError::Stale) => {}
                Err(e) => return Err(e),
            }
        }
        Err(ExecError::Unavailable(String::from("steps")))
    }

    /// Takes exactly one command of the job.
    ///
    /// # Errors
    /// [`ExecError`]; [`ExecError::Stale`] when another writer moved the job meanwhile.
    pub async fn advance(&self, id: [u8; 16]) -> Result<Next, ExecError> {
        let job = self.load(id).await?;
        let now = self.now()?;
        let n = next(&job, now, self.tokens.live(id, now));
        match &n {
            Next::Done => self.tokens.drop_job(id),
            Next::Idle | Next::Wait(_) => {}
            Next::ConfirmStop => self.confirm(&job, Confirmed::Stopped, now).await?,
            Next::ConfirmPause => self.confirm(&job, Confirmed::Paused, now).await?,
            Next::Stop(reason) => {
                self.put(
                    &job,
                    &Event::Requested {
                        control: Request::Stop,
                        reason: String::from(*reason),
                        at: now,
                    },
                )
                .await?;
            }
            Next::Pause(reason) => {
                self.put(
                    &job,
                    &Event::Requested {
                        control: Request::Pause,
                        reason: String::from(*reason),
                        at: now,
                    },
                )
                .await?;
            }
            Next::Recheck => self.recheck(&job, now).await?,
            Next::AwaitApproval(step) => {
                self.put(
                    &job,
                    &Event::Handoff {
                        step: *step,
                        reason: String::from("approval"),
                        until: now.saturating_add(HANDOFF_WAIT_MS),
                        at: now,
                    },
                )
                .await?;
            }
            Next::OpenWindow(step, until) => {
                self.put(
                    &job,
                    &Event::WindowOpened {
                        step: *step,
                        until: *until,
                    },
                )
                .await?;
            }
            Next::Release(step) => self.release(&job, *step, now).await?,
            Next::Outbox(step) => self.send(&job, *step, false, now).await?,
            Next::Resend(step) => self.send(&job, *step, true, now).await?,
            Next::Settle(step, outcome, evidence, follow) => {
                self.put(
                    &job,
                    &Event::Outcome {
                        step: *step,
                        outcome: *outcome,
                        evidence: evidence.clone(),
                        at: now,
                    },
                )
                .await?;
                if let Some(f) = follow {
                    self.follow(id, *step, *f, now).await?;
                }
            }
            Next::Attest(step) => self.attest(&job, *step).await?,
        }
        Ok(n)
    }

    async fn follow(&self, id: [u8; 16], step: u32, f: Follow, at: u64) -> Result<(), ExecError> {
        let e = match f {
            // E51, Ek B 4328
            Follow::Handoff => Event::Handoff {
                step,
                reason: String::from("blocked"),
                until: at.saturating_add(HANDOFF_WAIT_MS),
                at,
            },
            Follow::Semantic => Event::Semantic { step, at },
            Follow::Pause(reason) => Event::Requested {
                control: Request::Pause,
                reason: String::from(reason),
                at,
            },
            Follow::Stop(reason) => Event::Requested {
                control: Request::Stop,
                reason: String::from(reason),
                at,
            },
        };
        self.record(id, &e).await
    }

    /// A re-check point (§7.9.7.2, Ek B 4277): the next `continue` statement of the actor goes
    /// to Access; anything but a verified ALLOW leaves the job without a further effect.
    async fn recheck(&self, job: &Job, now: u64) -> Result<(), ExecError> {
        let ais = job
            .continuations
            .front()
            .ok_or(ExecError::Conflict("executor-no-continuation"))?;
        let verdict = match statement(ais) {
            Ok(s) if s.exercise == Some(job.exercise()) && s.domain == job.domain() => {
                let exercise = job.exercise();
                self.decide(ais, &s, &job.envelope, Some(&exercise), now)
                    .await?
            }
            _ => Verdict::Refused(String::from("continuation")),
        };
        let (allowed, code) = match verdict {
            Verdict::Allowed => (true, String::from("allow")),
            Verdict::Refused(c) => (false, c),
        };
        self.put(
            job,
            &Event::Decided {
                checkpoint: job.checkpoints,
                allowed,
                code,
                at: now,
            },
        )
        .await
    }

    /// The vault's release of the Exercise's token to this executor (OP-154 m.3 (t), m.12): one
    /// per Exercise, kept in memory only.
    async fn release(&self, job: &Job, step: u32, now: u64) -> Result<(), ExecError> {
        let body = json!({
            "domain": b64url_encode(&job.started.domain),
            "exercise": b64url_encode(&job.started.exercise),
            "intent": b64url_encode(&job.started.intent),
            "connection": job.started.connection,
            "delivery": "executor",
        });
        let answer = self
            .access
            .release(job.started.realm.clone(), body.to_string().into_bytes())
            .await;
        let Some((status, v)) = body_json(&answer) else {
            return Err(ExecError::Unavailable(String::from("release")));
        };
        if status >= 500 {
            return Err(ExecError::Unavailable(String::from("release")));
        }
        let token = v.get("access_token").and_then(Value::as_str);
        let until = v.get("use_until_ms").and_then(Value::as_u64);
        if let (200, Some(t), Some(u), Some("executor")) = (
            status,
            token,
            until,
            v.get("delivery").and_then(Value::as_str),
        ) {
            self.tokens.put(job.started.job, String::from(t), u);
            return self
                .put(
                    job,
                    &Event::Released {
                        step,
                        use_until: u,
                        at: now,
                    },
                )
                .await;
        }
        self.put(
            job,
            &Event::Outcome {
                step,
                outcome: Outcome::NotDone,
                evidence: Vec::new(),
                at: now,
            },
        )
        .await?;
        self.follow(job.started.job, step, Follow::Stop("release"), now)
            .await
    }

    fn webbot(&self, request: &mut HttpRequest, now: u64) -> Result<(), ExecError> {
        if self.signer.algorithm() != Algorithm::Ed25519 {
            return Err(ExecError::Unavailable(String::from("web-bot-auth-key")));
        }
        let authority = webbot::authority(&request.url)
            .ok_or(ExecError::Malformed("executor-step"))?
            .to_owned();
        let nonce = self
            .random
            .bytes()
            .ok_or_else(|| ExecError::Unavailable(String::from("random")))?;
        let p = Params {
            authority,
            agent: self.config.signature_agent.clone(),
            thumbprint: thumbprint(&self.signer.public_key()),
            created: now / 1000,
            nonce,
        };
        let signature = self
            .signer
            .sign(p.base().as_bytes())
            .map_err(|_| ExecError::Unavailable(String::from("web-bot-auth-key")))?;
        request.headers.extend(p.headers(&signature));
        Ok(())
    }

    /// Commits the outbox entry, then sends (TI-6): no request leaves before its entry is in
    /// the history, and a stop or a re-check recorded meanwhile fences it out.
    async fn send(&self, job: &Job, step: u32, again: bool, now: u64) -> Result<(), ExecError> {
        let i = usize::try_from(step).map_err(|_| ExecError::Conflict("executor-unknown-step"))?;
        let s = job
            .steps
            .get(i)
            .ok_or(ExecError::Conflict("executor-unknown-step"))?;
        let mut request = drivers::request(&s.spec, &s.key);
        let fence = if again {
            Event::Resent { step, at: now }
        } else {
            Event::Outbox {
                step,
                key: s.key.0,
                request: request.digest(),
                at: now,
            }
        };
        let token = self
            .tokens
            .get(job.started.job)
            .ok_or(ExecError::Conflict("executor-no-token"))?;
        request
            .headers
            .push((String::from("Authorization"), format!("Bearer {token}")));
        self.webbot(&mut request, now)?;
        self.put(job, &fence).await?;
        let answer = self.upstream.send(request).await;
        let at = self.now().unwrap_or(now);
        let e = match answer {
            Answer::Response(r) => Event::Answered {
                step,
                status: r.status,
                body: suiss_crypto::digest::sha256(&r.body),
                reading: drivers::read(&s.spec, r.status, &r.body),
                at,
            },
            Answer::Unanswered(_) => Event::Faulted { step, at },
        };
        self.record(job.started.job, &e).await
    }

    async fn ingest(
        &self,
        job: &Job,
        report: &Report,
    ) -> Result<(Vec<u8>, Option<String>), ExecError> {
        let payload =
            attest::payload(report).ok_or(ExecError::Unavailable(String::from("encode")))?;
        let kid = thumbprint(&self.signer.public_key());
        let claim = sign_sign1(&self.signer, kid, CONTENT_TYPE, &payload)
            .map_err(|_| ExecError::Unavailable(String::from("sign")))?;
        let id = claim_id(&claim);
        let body = json!({
            "domain": format!("sha-256:{}", b64url_encode(&job.started.domain)),
            "carrier": "cose",
            "claim": b64url_encode(&claim),
            "body": b64url_encode(&report.body),
        });
        let answer = self
            .access
            .ingest(b64url_encode(&id.0), body.to_string().into_bytes())
            .await;
        match body_json(&answer) {
            Some((200, _)) => Ok((id.0.to_vec(), None)),
            Some((status, v)) if (400..500).contains(&status) => Ok((
                id.0.to_vec(),
                Some(String::from(
                    v.get("code")
                        .and_then(Value::as_str)
                        .unwrap_or("claim-invalid"),
                )),
            )),
            _ => Err(ExecError::Unavailable(String::from("ingest"))),
        }
    }

    /// Reports step `step`'s outcome as an `effect_attestation` (E64); an attestation Ingest
    /// refuses stops the job, so no effect goes unreported.
    async fn attest(&self, job: &Job, step: u32) -> Result<(), ExecError> {
        let i = usize::try_from(step).map_err(|_| ExecError::Conflict("executor-unknown-step"))?;
        let report = attest::effect(job, i, self.config.reporter)
            .ok_or(ExecError::Unavailable(String::from("encode")))?;
        let at = report.statement.issued_at;
        let (claim, refused) = self.ingest(job, &report).await?;
        let halted = refused.is_some();
        self.put(
            job,
            &Event::Attested {
                step,
                claim,
                refused,
                at,
            },
        )
        .await?;
        if halted {
            self.follow(job.started.job, step, Follow::Stop("report"), at)
                .await?;
        }
        Ok(())
    }

    /// Confirms a pause or stop with an `executor_control` Claim (U5).
    async fn confirm(&self, job: &Job, state: Confirmed, now: u64) -> Result<(), ExecError> {
        let report = attest::control(job, state, now, self.config.reporter)
            .ok_or(ExecError::Unavailable(String::from("encode")))?;
        let (claim, _) = self.ingest(job, &report).await?;
        self.put(
            job,
            &Event::Confirmed {
                state,
                claim,
                at: now,
            },
        )
        .await?;
        if state == Confirmed::Stopped {
            self.tokens.drop_job(job.started.job);
        }
        Ok(())
    }

    /// The jobs a restarted process picks up.
    ///
    /// # Errors
    /// [`ExecError`].
    pub async fn open_jobs(&self) -> Result<Vec<[u8; 16]>, ExecError> {
        let mut out = Vec::new();
        for id in self.store.jobs(1000).await? {
            let job = self.load(id).await?;
            if job.confirmed != Some(Confirmed::Stopped)
                && !(job.completed() && job.stop_requested.is_none())
            {
                out.push(id);
            }
        }
        Ok(out)
    }
}

/// Decodes base64url.
///
/// # Errors
/// `executor-malformed`.
pub fn bytes(text: &str) -> Result<Vec<u8>, ExecError> {
    b64url_decode(text).map_err(|_| ExecError::Malformed("executor-malformed"))
}
