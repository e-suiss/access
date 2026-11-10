//! The commit path (§17.1.1, OP-141): actor from the AIS, nonce rule, evaluation over a
//! snapshot fetched as it is read, and the opening and decision records committed together.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::SequencerError;
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::domain::{Draft, Item, NonceUse, Outcome as Committed};
use access_authority_sequencer::ports::DomainLog;
use access_kernel::ais::{self, AisError, Expected};
use access_kernel::algebra::Catalog;
use access_kernel::claim::{self, ClaimState, Disposition};
use access_kernel::codec::Canonical;
use access_kernel::combinator::codec::decision_value;
use access_kernel::combinator::{
    Blocker, BlockerClass, Decision, Mode, Outcome, Position, Rejection, Remediation, Resolver,
};
use access_kernel::digest::Digest;
use access_kernel::fold::Effect;
use access_kernel::intent::{ParamValue, intent_digest};
use access_kernel::meta::{self, Actor, ExerciseState, InstanceState, Payload, kind};
use access_kernel::model::{AuthoritySet, Id, RequirementTerm, ResourceRef, SubjectSelector};
use access_kernel::record::{Opened, RecordEnvelope, RecordKind};
use access_kernel::verify::cose;
use access_store::authority::{Draw, Renewal};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::domain::{Evaluation, Frame, Pass, Request, Snapshot, pass};
use crate::ports::{Binding, Reader, Row, Salts};
use crate::rate::{Class, Limiter, Who};
use access_telemetry::oracle::{Advisory, ORACLE};
use access_telemetry::signals::{DECISIONS, REQUESTER_THROTTLED, VALIDATION_RETRIES};
use proofs::Resolved as Proofs;

/// Most snapshot passes before a request is refused (SI-20, PD).
pub const MAX_PASSES: usize = 32;
/// Evaluations of one request when serial validation refuses its batch (§17.1.1 step 9, PD).
pub const MAX_RETRIES: usize = 3;

/// What the PEP gets back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The decision.
    pub decision: Decision,
    /// The `ExerciseID`, for `commit` and `continue`.
    pub exercise: Option<Digest>,
    /// Position of the decision record; `None` in `check` (not recorded).
    pub record: Option<u64>,
    /// Whether this is a retry of a decision already recorded.
    pub replayed: bool,
    /// The opaque reference to the decision record, set by the decision point (OP-141 m.22
    /// (e)); the raw position stays inside.
    pub basis_ref: Option<String>,
    /// The head the answer was given at, as an opaque token (OP-141 m.22 (f)).
    pub consistency: Option<String>,
    /// The unsigned receipt payload of a new ALLOW; its digest is in the decision record and it
    /// is signed after the commit (§9.8, L2-RCP-2).
    pub receipt: Option<Vec<u8>>,
    /// The signed receipt and its key excerpt, once the signer has signed it.
    pub signed_receipt: Option<(Vec<u8>, Vec<u8>)>,
    /// The unsigned PAP payload of an allowed `projection.issue`; its digest is in the decision
    /// record and it is signed after the commit (L2-PAP-2).
    pub pap: Option<Vec<u8>>,
    /// The signed PAP and its key excerpt.
    pub signed_pap: Option<(Vec<u8>, Vec<u8>)>,
    /// The holder Instances this commit ended (§9.9.3 k.6, P50): their live projection
    /// families are revoked at `record` once it is in. Empty for a replay.
    pub ended: Vec<Id>,
    /// What an explanation of a recorded decision shows a viewer or an auditor beyond the
    /// requester's view (§9.6.1, §13.7.5); `None` for every other answer.
    pub explained: Option<Box<audit::Explained>>,
    /// For a request naming an upstream Exercise, whether its causal-bound allowance was
    /// enforced (§9.9.2, OP-152 m.7 (d) E11): `Some(true)` only when the domain declares it;
    /// `None` when the request names none or the answer was not evaluated now.
    pub causal: Option<bool>,
}

/// One request with what came with it on the wire.
#[derive(Clone, Debug)]
pub struct Incoming {
    /// The request.
    pub request: Request,
    /// The AIS bytes.
    pub ais: Option<Vec<u8>>,
    /// The PEP's transport-authenticated identity.
    pub pep: String,
    /// The end user the PEP forwards for, when it names one (a console session): an anonymous
    /// request or an eligibility check is counted in this user's bucket under the PEP, not in
    /// the PEP's own (OP-141 m.23 (a), OP-151 m.12 (e)).
    pub requester: Option<String>,
    /// Whether the request is an explanation, counted apart from `check` (OP-141 m.23).
    pub explain: bool,
    /// The Token Status List entry the decision point opened for a `projection.issue` commit
    /// before deciding it (OP-150 m.10 (a), §11.20): the PAP's contract names it, so the entry
    /// is committed with the PAP digest. `None` for every other request.
    pub status: Option<access_kernel::status::StatusRef>,
    /// The pseudonymous context the PEP names the request by (address-prefix pseudonym or
    /// attestation class): bootstrap Grants are counted per PEP, context and hour, and under the
    /// PEP alone without one (§13.7.4, OP-152 m.5 (b)).
    pub context: Option<access_internal_api::context::RateContext>,
}

const BOOTSTRAP: [&str; 2] = ["party_register", "instance_create"];

/// The core read action (§9.13.7, OP-141 m.39 (a)).
const READ_ACTION: &str = "read";

fn kid_of(sign1: &[u8]) -> Result<[u8; 32], CoreError> {
    let msg = cose::parse_sign1(sign1).map_err(|e| CoreError::Ais(AisError::Signature(e)))?;
    let Ok(Value::Map(header)) = dcbor::decode(&msg.protected, Limits::CEILING) else {
        return Err(CoreError::Protocol("ais-header"));
    };
    header
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Unsigned(cose::KID), Value::Bytes(b)) => {
                <[u8; 32]>::try_from(b.as_slice()).ok()
            }
            _ => None,
        })
        .ok_or(CoreError::Protocol("ais-kid"))
}

fn opened(salts: &mut impl Salts, value: Value) -> Result<Opened, CoreError> {
    Ok(Opened {
        value,
        salt: salts.salt()?,
    })
}

fn fields(
    salts: &mut impl Salts,
    entries: Vec<(&str, Value)>,
) -> Result<BTreeMap<String, Opened>, CoreError> {
    entries
        .into_iter()
        .map(|(k, v)| Ok((String::from(k), opened(salts, v)?)))
        .collect()
}

fn state_basis_value(reads: &[(Vec<u8>, u64)]) -> Value {
    Value::Map(vec![
        (Value::text("at"), Value::Unsigned(0)),
        (
            Value::text("reads"),
            Value::Array(
                reads
                    .iter()
                    .map(|(k, v)| Value::Array(vec![Value::Bytes(k.clone()), Value::Unsigned(*v)]))
                    .collect(),
            ),
        ),
    ])
}

fn effects_value(effects: &[Effect]) -> Value {
    Value::Array(
        effects
            .iter()
            .map(|(k, v)| {
                let mut e = vec![Value::Bytes(k.clone())];
                e.extend(v.clone());
                Value::Array(e)
            })
            .collect(),
    )
}

fn digest_value(d: &Digest) -> Value {
    d.to_value()
}

/// The authority core of one domain: its leader and its ports.
pub struct Authority<L: DomainLog, R: Reader, B: Binding, S: Salts> {
    leader: Leader<L>,
    pub(crate) reader: R,
    pub(crate) limiter: Limiter,
    policies: crate::restrict::Cache,
    binding: B,
    salts: S,
    domain: Digest,
    catalog: Catalog,
    past: Option<Past>,
    pseudonyms: Option<access_crypto::pseudonym::PseudonymKey>,
    pub(crate) analysis: std::sync::Arc<dyn crate::ports::PolicyAnalysis>,
}

/// The rebuilt decision of an explanation as a trace event (§9.7.1, §9.16.3): operator
/// telemetry under the subscriber's sampling, never a record; counts only, no content.
fn trace_rebuilt(scope: Scope, decision: &Decision) {
    tracing::debug!(
        target: "access::explain",
        scope = ?scope,
        outcome = ?decision.outcome,
        blockers = decision.blockers.len(),
        unmet = decision.unmet.len(),
        "decision rebuilt",
    );
}

/// Whose view an explanation of a recorded decision is (OP-141 m.38).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The recorded actor.
    Requester,
    /// A root or holder in the lineage of the recorded basis.
    Viewer,
    /// An auditor of the domain.
    Audit,
}

/// The opening record of a nonce: who acted, on which basis and in which capacity.
#[derive(Debug)]
struct Opening {
    actor: Value,
    basis: Value,
    capacity: Value,
}

/// The state and counters just before a recorded decision, read instead of the live state while
/// that decision is explained (OP-141 m.36 (d)).
#[derive(Debug, Default)]
struct Past {
    state: access_kernel::fold::State,
    counters: BTreeMap<Vec<u8>, u64>,
}

impl Past {
    /// Folds the records before `record` and returns them with the outcome of the decision at
    /// `record`, which must be of `nonce` and `intent` (OP-141 m.36 (c), (d)).
    fn before(
        log: &[Vec<u8>],
        record: u64,
        nonce: &[u8],
        intent: &Digest,
    ) -> Result<(Self, u64, Outcome, Opening), CoreError> {
        let bad = || CoreError::Protocol("explain-record");
        let mut past = Self::default();
        let mut folded: Option<access_kernel::fold::State> = None;
        let mut opening = None;
        for bytes in log {
            let r = RecordEnvelope::from_bytes(bytes).map_err(|_| bad())?;
            let field = |name: &str| r.fields.get(name).map(|f| &f.value);
            if r.header.kind == RecordKind::Opening
                && field("nonce") == Some(&Value::Bytes(nonce.to_vec()))
            {
                opening = Some(Opening {
                    actor: field("actor").cloned().ok_or_else(bad)?,
                    basis: field("basis").cloned().ok_or_else(bad)?,
                    capacity: field("capacity").cloned().ok_or_else(bad)?,
                });
            }
            if r.header.pos == record {
                if r.header.kind != RecordKind::Decision
                    || field("nonce") != Some(&Value::Bytes(nonce.to_vec()))
                    || field("intent") != Some(&intent.to_value())
                {
                    return Err(bad());
                }
                let outcome = match field("outcome").and_then(|d| d.get("outcome")) {
                    Some(Value::Text(t)) if t == "allow" => Outcome::Allow,
                    Some(Value::Text(t)) if t == "deny" => Outcome::Deny,
                    Some(Value::Text(t)) if t == "require_action" => Outcome::RequireAction,
                    _ => return Err(bad()),
                };
                past.state = folded.ok_or_else(bad)?;
                return Ok((
                    past,
                    r.header.recorded_at,
                    outcome,
                    opening.ok_or_else(bad)?,
                ));
            }
            if let Some(Value::Array(draws)) = field("consumption").and_then(|c| c.get("draws")) {
                for d in draws {
                    if let Value::Array(pair) = d
                        && let [Value::Bytes(k), Value::Unsigned(n)] = pair.as_slice()
                    {
                        let used = past.counters.entry(k.clone()).or_insert(0);
                        *used = used.saturating_add(*n);
                    }
                }
            }
            match folded.as_mut() {
                None => folded = Some(access_kernel::fold::genesis(&r).map_err(|_| bad())?),
                Some(state) => access_kernel::fold::apply(state, &r).map_err(|_| bad())?,
            }
        }
        Err(bad())
    }

    fn row(&self, key: &[u8]) -> Row {
        self.state.get(key).map_or_else(
            || (key.to_vec(), None, 0),
            |e| (key.to_vec(), e.value.clone(), e.version),
        )
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The core over a leader that holds the domain's lease.
    pub fn new(leader: Leader<L>, reader: R, binding: B, salts: S, domain: Digest) -> Self {
        Self {
            leader,
            reader,
            limiter: Limiter::default(),
            policies: crate::restrict::Cache::default(),
            binding,
            salts,
            domain,
            catalog: Catalog::default(),
            past: None,
            pseudonyms: None,
            analysis: std::sync::Arc::new(crate::ports::NoAnalysis),
        }
    }

    /// The control-plane analysis a policy change preview asks (OP-105); without one every
    /// change is [`crate::ports::PolicyRelation::Unknown`].
    #[must_use]
    pub fn with_analysis(
        mut self,
        analysis: std::sync::Arc<dyn crate::ports::PolicyAnalysis>,
    ) -> Self {
        self.analysis = analysis;
        self
    }

    /// The domain's pseudonym key; without one, a projection that names a Party is refused
    /// (P52, OP-143 m.15 (d)).
    #[must_use]
    pub fn with_pseudonyms(mut self, key: access_crypto::pseudonym::PseudonymKey) -> Self {
        self.pseudonyms = Some(key);
        self
    }

    /// A Party's pseudonym in this domain's projections.
    fn party_ref(&self, party: &Id) -> Result<Id, CoreError> {
        self.pseudonyms
            .as_ref()
            .ok_or(CoreError::Unavailable("pseudonym-key"))?
            .party_ref(&party.0)
            .map(Id)
            .map_err(|_| CoreError::Unavailable("pseudonym-key"))
    }

    /// `sel` with its Party replaced by its pseudonym.
    fn subject_ref(&self, sel: &SubjectSelector) -> Result<SubjectSelector, CoreError> {
        Ok(match sel {
            SubjectSelector::Party(p) => SubjectSelector::Party(self.party_ref(p)?),
            other => other.clone(),
        })
    }

    /// An authority set and requirement terms with every Party replaced by its pseudonym.
    fn pseudonymous(
        &self,
        set: &AuthoritySet,
        terms: &BTreeSet<RequirementTerm>,
    ) -> Result<(AuthoritySet, BTreeSet<RequirementTerm>), CoreError> {
        let mut set = set.clone();
        set.recipient = set
            .recipient
            .as_ref()
            .map(|r| self.subject_ref(r))
            .transpose()?;
        for b in set.params.values_mut() {
            if let access_kernel::model::Bound::Subject(sel) = b {
                *sel = self.subject_ref(sel)?;
            }
        }
        let mut out = BTreeSet::new();
        for t in terms {
            let mut t = t.clone();
            t.source = t.source.as_ref().map(|s| self.subject_ref(s)).transpose()?;
            out.insert(t);
        }
        Ok((set, out))
    }

    /// Current values and versions of `keys`, or those before the decision being explained.
    pub(crate) async fn fetch(&self, keys: &[Vec<u8>]) -> Result<Vec<Row>, CoreError> {
        match &self.past {
            Some(p) => Ok(keys.iter().map(|k| p.row(k)).collect()),
            None => self.reader.fetch(keys).await,
        }
    }

    /// The live rows under `prefix`, or those before the decision being explained.
    pub(crate) async fn scan(&self, prefix: &[u8]) -> Result<Vec<Row>, CoreError> {
        match &self.past {
            Some(p) => Ok(p
                .state
                .range(prefix.to_vec()..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .filter(|(_, e)| e.value.is_some())
                .map(|(k, _)| p.row(k))
                .collect()),
            None => self.reader.scan(prefix).await,
        }
    }

    /// A counter's used amount, or the amount before the decision being explained.
    pub(crate) async fn counter(&self, key: &[u8]) -> Result<u64, CoreError> {
        match &self.past {
            Some(p) => Ok(p.counters.get(key).copied().unwrap_or(0)),
            None => self.reader.counter(key).await,
        }
    }

    /// Explains the recorded decision at `record` by evaluating its request again on the state
    /// just before it; the rebuilt outcome must be the recorded one (L1-ADP-15, OP-141 m.36).
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `explain-record` or `explain-mismatch`, and as [`Self::exercise`].
    pub async fn explain_recorded(
        &mut self,
        inc: &Incoming,
        record: u64,
        scope: Scope,
        now: u64,
    ) -> Result<Response, CoreError> {
        let req = &inc.request;
        if req.domain != self.domain {
            return Err(CoreError::Protocol("domain"));
        }
        if req.mode == Mode::Check || record == 0 || record > self.head() {
            return Err(CoreError::Protocol("explain-record"));
        }
        Self::check_payload(req, false)?;
        let digest = intent_digest(&req.intent).map_err(|_| CoreError::Protocol("intent"))?;
        let actor = self.actor(inc, &digest, now).await?;
        if !self.limiter.admit(Class::Explain, who(inc, actor), now) {
            return Err(CoreError::Limited);
        }
        let actor_ref = actor.map_or_else(|| b"anonymous".to_vec(), |a| a.instance.0.to_vec());
        let viewer = actor.map(|a| a.party);
        let nonce = self.reader.nonce(&req.nonce).await?;
        if nonce.as_ref().is_none_or(|n| n.intent_digest != digest.0) {
            return Err(CoreError::Protocol("explain-record"));
        }
        let allowed_scope = match (scope, actor) {
            (Scope::Requester, _) => nonce.as_ref().is_some_and(|n| n.actor == actor_ref),
            (Scope::Viewer, Some(a)) => {
                self.settled(|snap| crate::domain::views(snap, &req.basis, &a.party))
                    .await?
            }
            (Scope::Audit, Some(a)) => self.audits(&a.party, now).await?,
            (_, None) => false,
        };
        if !allowed_scope {
            return Err(CoreError::Protocol(if scope == Scope::Requester {
                "explain-record"
            } else {
                "explain-scope"
            }));
        }
        let log = self.reader.log(0, record).await?;
        let (past, at, recorded, opening) = Past::before(&log, record, &req.nonce, &digest)?;
        // OP-141 m.38 (e)
        if opening.basis != meta::basis_value(&req.basis)
            || opening.capacity != meta::capacity_value(req.capacity)
        {
            return Err(CoreError::Protocol("explain-record"));
        }
        let actor = match &opening.actor {
            Value::Bytes(b) => {
                let instance = Id::from_value(&Value::Bytes(b.clone()))
                    .map_err(|_| CoreError::Protocol("explain-record"))?;
                let state = past
                    .row(&meta::key(kind::INSTANCE, &instance))
                    .1
                    .and_then(|v| meta::InstanceState::from_value(&v).ok())
                    .ok_or(CoreError::Protocol("explain-record"))?;
                Some(Actor {
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
        let past = self
            .past
            .take()
            .ok_or(CoreError::Protocol("explain-record"))?;
        let evaluation = rebuilt?;
        trace_rebuilt(scope, &evaluation.decision);
        // X25
        if evaluation.decision.outcome != recorded {
            return Err(CoreError::Protocol("explain-mismatch"));
        }
        let explained = match (scope, viewer) {
            (Scope::Requester, _) | (_, None) => None,
            (Scope::Viewer | Scope::Audit, Some(viewer)) => Some(Box::new(self.explained(
                &past,
                req,
                (&viewer, scope),
                log.last(),
                &evaluation.decision,
            )?)),
        };
        let exercise =
            meta::exercise_id(&req.domain, &req.nonce).map_err(|_| CoreError::Protocol("nonce"))?;
        let allowed = recorded == Outcome::Allow;
        let mut response = answer(
            evaluation.decision,
            allowed.then_some(req.exercise.unwrap_or(exercise)),
            Some(record),
            false,
        );
        response.explained = explained;
        // OP-152 m.7 (d) E11
        if req.intent.context.upstream_exercise.is_some() {
            response.causal = Some(self.causal_declared().await?);
        }
        Ok(response)
    }

    /// What `viewer` sees of the recorded decision `record` beyond the requester's view at
    /// `scope` (§9.6.1, §13.7.5), from the state `past` just before it.
    fn explained(
        &self,
        past: &Past,
        req: &Request,
        (viewer, scope): (&Id, Scope),
        record: Option<&Vec<u8>>,
        decision: &Decision,
    ) -> Result<audit::Explained, CoreError> {
        let bad = || CoreError::Protocol("explain-record");
        let record = RecordEnvelope::from_bytes(record.ok_or_else(bad)?).map_err(|_| bad())?;
        let is_audit = scope == Scope::Audit;
        Ok(audit::Explained {
            lineage: audit::viewed_lineage(
                &past.state,
                &req.basis,
                viewer,
                is_audit,
                self.pseudonyms.as_ref(),
            )?,
            audit: is_audit
                .then(|| audit::audit_detail(self.domain, &record, decision))
                .transpose()?,
        })
    }

    /// Whether `party` may audit the domain: the meta-anchor's root, or the holder of a live
    /// Grant covering `access:audit_export` (OP-141 m.38 (d), m.39 (b)).
    pub(crate) async fn audits(&self, party: &Id, now: u64) -> Result<bool, CoreError> {
        let meta_anchor = meta::meta_anchor(&self.domain);
        let root = self
            .settled(|snap| {
                crate::domain::read::<meta::AnchorState>(snap, kind::ANCHOR, &meta_anchor)
                    .is_some_and(|a| {
                        meta::root_requirements(
                            &a,
                            &Actor {
                                party: *party,
                                instance: Id([0; 16]),
                            },
                        )
                        .is_some()
                    })
            })
            .await?;
        if root {
            return Ok(true);
        }
        for g in self.reader.grants_for(party, None, 1_000).await? {
            let audit = self
                .settled(|snap| crate::domain::audit_grant(snap, &g, party, &self.domain, now))
                .await?;
            if audit {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn rebuild(
        &self,
        req: &Request,
        actor: Option<Actor>,
        digest: Digest,
        record: u64,
        at: u64,
        opened: bool,
    ) -> Result<Evaluation, CoreError> {
        let exercise =
            meta::exercise_id(&req.domain, &req.nonce).map_err(|_| CoreError::Protocol("nonce"))?;
        let mut resolved = self
            .resolve(req, actor.map(|a| a.party), at, record.saturating_sub(1))
            .await?;
        self.rebind(req, actor, &digest, &mut resolved, at).await?;
        let compromised = match self.compromised(actor, at).await? {
            Some(c) => Some(c),
            None => self.recovery_binding(req, actor, at).await?,
        };
        let frame = Frame {
            intent_digest: digest,
            exercise,
            pos: record,
            actor,
            now: at,
            catalog: &self.catalog,
            proofs: &resolved.proofs,
            held: resolved.held,
            policies: &self.policies,
            compromised,
        };
        let (mut evaluation, _) = self.passes(req, &frame).await?;
        let tier = crate::requirements::tier_of(
            &req.intent,
            req.payload.as_ref(),
            evaluation.expansion,
            evaluation.action.as_deref(),
        );
        self.tiered(req, &mut evaluation, opened, at).await?;
        self.recovery_rules(req, actor, &mut evaluation, tier, at)
            .await?;
        self.throttled(&mut evaluation, actor, opened, at).await?;
        Ok(evaluation)
    }

    /// The last committed position.
    #[must_use]
    pub const fn head(&self) -> u64 {
        self.leader.head().pos
    }

    /// Extends the leader's lease; [`Renewal::HandoffRequested`] means another process asked
    /// for the domain and this core should be released (OP-149 m.28 (a)).
    ///
    /// # Errors
    /// [`CoreError::Sequencer`]; the core must then be dropped.
    pub async fn renew(&self) -> Result<Renewal, CoreError> {
        Ok(self.leader.renew().await?)
    }

    /// Gives the lease up (OP-31).
    ///
    /// # Errors
    /// [`CoreError::Sequencer`].
    pub async fn release(self) -> Result<(), CoreError> {
        Ok(self.leader.release().await?)
    }

    async fn snapshot_get(
        &self,
        snapshot: &mut Snapshot,
        keys: &[Vec<u8>],
    ) -> Result<(), CoreError> {
        snapshot.fill(self.fetch(keys).await?);
        Ok(())
    }

    /// §17.1.1 step 3: the actor of the request, `None` when it is anonymous.
    pub(crate) async fn actor(
        &self,
        inc: &Incoming,
        digest: &Digest,
        now: u64,
    ) -> Result<Option<Actor>, CoreError> {
        let Some(sign1) = &inc.ais else {
            return Ok(None);
        };
        let req = &inc.request;
        let kid = kid_of(sign1)?;
        let bootstrap = req
            .payload
            .as_ref()
            .is_some_and(|p| BOOTSTRAP.contains(&p.action()));
        let recover = match &req.payload {
            Some(Payload::InstanceRecover { instance, key }) => Some((*instance, key.clone())),
            _ => None,
        };
        let (party, instance, key) = if let Some((predecessor, key)) = recover {
            // OP-153 m.3 (c), L0-META-7
            if access_kernel::verify::key_scope::thumbprint(&key) != kid {
                return Err(CoreError::Ais(AisError::Mismatch("key")));
            }
            let mut snap = Snapshot::default();
            let ikey = meta::key(kind::INSTANCE, &predecessor);
            self.snapshot_get(&mut snap, std::slice::from_ref(&ikey))
                .await?;
            let Some(old) = snap
                .values_of(&ikey)
                .and_then(|v| InstanceState::from_value(&v).ok())
            else {
                return Ok(None);
            };
            let exercise = meta::exercise_id(&req.domain, &req.nonce)
                .map_err(|_| CoreError::Protocol("nonce"))?;
            (
                old.party,
                meta::object_id(&exercise, kind::INSTANCE, 0),
                key,
            )
        } else if bootstrap {
            let (party, key) = match (self.binding.bound(&kid), &req.payload) {
                (Some(bound), _) => bound,
                // OP-154 m.3 (d)
                (None, Some(Payload::InstanceCreate { party, key, .. }))
                    if access_kernel::verify::key_scope::thumbprint(key) == kid
                        && self.workload_bound(party, &kid, now).await? =>
                {
                    (*party, key.clone())
                }
                (None, _) => return Ok(None),
            };
            let exercise = meta::exercise_id(&req.domain, &req.nonce)
                .map_err(|_| CoreError::Protocol("nonce"))?;
            let instance = match &req.payload {
                Some(Payload::InstanceCreate { .. }) => {
                    meta::object_id(&exercise, kind::INSTANCE, 0)
                }
                _ => Id([0; 16]),
            };
            (party, instance, key)
        } else {
            let mut snap = Snapshot::default();
            let index = meta::key_index(&kid);
            self.snapshot_get(&mut snap, std::slice::from_ref(&index))
                .await?;
            let Some(id) = snap.values_of(&index).and_then(|v| Id::from_value(&v).ok()) else {
                return Err(CoreError::Ais(AisError::Mismatch("key")));
            };
            let ikey = meta::key(kind::INSTANCE, &id);
            self.snapshot_get(&mut snap, std::slice::from_ref(&ikey))
                .await?;
            let Some(state) = snap
                .values_of(&ikey)
                .and_then(|v| InstanceState::from_value(&v).ok())
            else {
                return Err(CoreError::Ais(AisError::Mismatch("key")));
            };
            if state.ended.is_some() {
                return Err(CoreError::Ais(AisError::Mismatch("key")));
            }
            (state.party, id, state.key)
        };
        let exercise = req.exercise;
        let expected = Expected {
            domain: &req.domain,
            nonce: &req.nonce,
            intent: digest,
            mode: req.mode,
            pep: &inc.pep,
            capacity: req.capacity,
            basis: &req.basis,
            exercise: exercise.as_ref(),
        };
        ais::verify(sign1, &key, &expected, now).map_err(CoreError::Ais)?;
        Ok(Some(Actor { party, instance }))
    }

    /// L2-REC-5: a terminal outcome is returned again, never evaluated again.
    async fn replay(
        &self,
        nonce: &[u8],
        digest: &Digest,
        actor_ref: &[u8],
        exercise: Digest,
    ) -> Result<Replay, CoreError> {
        let Some(stored) = self.reader.nonce(nonce).await? else {
            return Ok(Replay::New);
        };
        if stored.intent_digest != digest.0 || stored.actor != actor_ref {
            return Err(CoreError::Nonce);
        }
        let outcome = match stored.outcome.as_str() {
            "allow" => Outcome::Allow,
            "deny" => Outcome::Deny,
            _ => return Ok(Replay::Open),
        };
        Ok(Replay::Done(Box::new(Response {
            decision: Decision {
                outcome,
                blockers: Vec::new(),
                unmet: Vec::new(),
                relied_on: Vec::new(),
            },
            exercise: (outcome == Outcome::Allow).then_some(exercise),
            record: Some(stored.decision_pos),
            replayed: true,
            basis_ref: None,
            consistency: None,
            receipt: None,
            signed_receipt: None,
            pap: None,
            signed_pap: None,
            ended: Vec::new(),
            explained: None,
            causal: None,
        })))
    }

    /// L1-ADP-13: a continuation names an allowed Exercise of the same intent and actor.
    async fn continued(
        &self,
        req: &Request,
        digest: &Digest,
        actor: Option<Actor>,
    ) -> Result<(), CoreError> {
        let Some(e) = req.exercise else {
            return Ok(());
        };
        let k = meta::exercise_key(kind::EXERCISE, &e);
        let mut snap = Snapshot::default();
        self.snapshot_get(&mut snap, std::slice::from_ref(&k))
            .await?;
        let same = snap
            .values_of(&k)
            .and_then(|v| ExerciseState::from_value(&v).ok())
            .is_some_and(|s| s.intent == *digest && actor.is_some_and(|a| a.instance == s.actor));
        if same {
            Ok(())
        } else {
            Err(CoreError::Protocol("exercise"))
        }
    }

    /// The payload rules of a request; a `probe` is an eligibility check, which may name a core
    /// meta-action without its payload and is then answered by coverage only (OP-152 m.5, OP-151
    /// m.20 (d)).
    fn check_payload(req: &Request, probe: bool) -> Result<(), CoreError> {
        let is_meta = meta::is_meta(&req.intent.action.namespace, &req.intent.action.name);
        match &req.payload {
            Some(p) => {
                let body = p.digest().map_err(|_| CoreError::Protocol("payload"))?;
                // OP-153 m.17 (h), OP-141 m.13
                if Payload::from_value(&p.to_value()).as_ref() != Ok(p) {
                    return Err(CoreError::Protocol("payload"));
                }
                if !is_meta
                    || p.action() != req.intent.action.name
                    || req.intent.opaque.get("payload") != Some(&body)
                {
                    return Err(CoreError::Protocol("payload"));
                }
                // OP-141 m.27 (e)
                if let Payload::PolicySet { content, .. } = p
                    && crate::restrict::compile(content).is_err()
                {
                    return Err(CoreError::Protocol("policy"));
                }
                // L0-META-30
                if let Payload::Contribute { class, .. } = p {
                    let target = ResourceRef {
                        namespace: String::from(CONTRIBUTION_NAMESPACE),
                        path: vec![class.clone()],
                        incarnation: 0,
                    };
                    if req.intent.resources != [target] {
                        return Err(CoreError::Protocol("payload"));
                    }
                }
            }
            // OP-151 m.20 (d)
            None if is_meta && probe && req.mode == Mode::Check => {}
            None if is_meta => return Err(CoreError::Protocol("payload")),
            // OP-141 m.39 (a), OP-151 m.19 (d)
            None if req.intent.action.namespace == meta::NAMESPACE
                && !matches!(
                    req.intent.action.name.as_str(),
                    READ_ACTION | crate::domain::export::EXPORT_ACTION
                ) =>
            {
                return Err(CoreError::Protocol("action"));
            }
            // OP-141 m.39 (a), §9.13.7
            None if req.intent.action.namespace == meta::NAMESPACE
                && req.intent.action.name == crate::domain::export::EXPORT_ACTION
                && !req.intent.params.iter().all(|(k, v)| {
                    matches!(
                        (k.as_str(), v),
                        ("from" | "to", ParamValue::Count(_)) | ("disclosure", ParamValue::Enum(_))
                    )
                }) =>
            {
                return Err(CoreError::Protocol("export-params"));
            }
            None => {}
        }
        match (req.mode, req.exercise) {
            (Mode::Continue, Some(_)) | (Mode::Commit | Mode::Check, None) => Ok(()),
            _ => Err(CoreError::Protocol("exercise")),
        }
    }

    /// The frame one evaluation runs in: the intent digest, the Exercise and the position the
    /// decision record will have, with the actor, the proofs and the overlays.
    fn frame<'a>(
        &'a self,
        (intent_digest, exercise, pos): (Digest, Digest, u64),
        actor: Option<Actor>,
        now: u64,
        resolved: &'a Proofs,
        compromised: Option<&'static str>,
    ) -> Frame<'a> {
        Frame {
            intent_digest,
            exercise,
            pos,
            actor,
            now,
            catalog: &self.catalog,
            proofs: &resolved.proofs,
            held: resolved.held,
            policies: &self.policies,
            compromised,
        }
    }

    /// Runs the evaluation over a snapshot, fetching state and counters as it asks for them
    /// (§17.1.1 steps 7–8).
    async fn passes(
        &self,
        req: &Request,
        frame: &Frame<'_>,
    ) -> Result<(Evaluation, Snapshot), CoreError> {
        let mut snapshot = Snapshot::default();
        let mut evaluation = None;
        for _ in 0..MAX_PASSES {
            match pass(req, frame, &snapshot) {
                Pass::Need(keys) => self.snapshot_get(&mut snapshot, &keys).await?,
                Pass::NeedCounters(keys) => {
                    let mut rows = Vec::with_capacity(keys.len());
                    for k in keys {
                        let used = self.counter(&k).await?;
                        rows.push((k, used));
                    }
                    snapshot.fill_counters(rows);
                }
                Pass::NeedScans(prefixes) => {
                    for p in prefixes {
                        let rows = self.scan(&p).await?;
                        snapshot.fill_scan(p, rows);
                    }
                }
                Pass::Done(e) => {
                    evaluation = Some(e);
                    break;
                }
                Pass::Rejected(r) => return Err(CoreError::Rejected(r)),
            }
        }
        let evaluation = evaluation.ok_or(CoreError::Passes)?;
        Ok((evaluation, snapshot))
    }

    /// The consequence tier's ceilings: the intent validity, and the time-lock of a CT3
    /// meta-action that widens authority, counted from the nonce's first decision
    /// (§13.7.3, SEC26, OP-141 m.34 (b), (c)).
    async fn tiered(
        &self,
        req: &Request,
        evaluation: &mut Evaluation,
        open: bool,
        now: u64,
    ) -> Result<(), CoreError> {
        let tier = crate::requirements::tier_of(
            &req.intent,
            req.payload.as_ref(),
            evaluation.expansion,
            evaluation.action.as_deref(),
        );
        let validity = &req.intent.validity;
        if validity.until.saturating_sub(validity.from)
            > access_kernel::tier::validity_ceiling(tier)
        {
            return Err(CoreError::Protocol("intent-validity"));
        }
        if tier != access_kernel::tier::Tier::Ct3
            || evaluation.decision.outcome != Outcome::Allow
            || req.payload.is_none()
        {
            return Ok(());
        }
        let key = meta::policy_default_key(meta::CT3_DELAY);
        let delay = self
            .fetch(std::slice::from_ref(&key))
            .await?
            .into_iter()
            .find_map(|(_, v, _)| match v {
                Some(Value::Unsigned(s)) => Some(s),
                _ => None,
            })
            .unwrap_or(meta::CT3_DELAY_DEFAULT_S);
        let opened = if open {
            match self.reader.nonce_opened(&req.nonce).await? {
                Some(pos) => self.reader.recorded_at(pos).await?.unwrap_or(now),
                None => now,
            }
        } else {
            now
        };
        let until = opened.saturating_add(delay.saturating_mul(1_000));
        if now < until {
            evaluation.decision = Decision {
                outcome: Outcome::RequireAction,
                blockers: vec![Blocker {
                    class: BlockerClass::Restricted,
                    subcode: Some(String::from("time-lock")),
                    position: Position::Anchor,
                    resolver: Resolver::Root,
                    remediation: Remediation::WaitUntil(until),
                }],
                unmet: Vec::new(),
                relied_on: Vec::new(),
            };
            evaluation.effects.clear();
            evaluation.draws.clear();
            evaluation.releases.clear();
        }
        Ok(())
    }

    /// The receipt of an ALLOW (§9.8, L2-RCP-1): its digest for the record and its payload.
    fn receipt_of(
        inc: &Incoming,
        domain: &Digest,
        actor: Option<Actor>,
        fixed: &Fixed,
    ) -> Result<(Digest, Vec<u8>), CoreError> {
        let r = access_kernel::receipt::Receipt {
            domain: *domain,
            exercise: fixed.exercise,
            record: fixed.pos,
            intent: fixed.intent,
            instance: actor.map(|a| a.instance),
            ais: inc
                .ais
                .as_ref()
                .map(|b| Digest(suiss_crypto::digest::context_digest("access/ais/v1", b).0)),
            capacity: inc.request.capacity,
            basis: inc.request.basis,
            audience: inc.pep.clone(),
            iat: fixed.now,
            drawn: fixed.drawn,
            agency: fixed.agency.clone(),
        };
        let digest =
            access_kernel::receipt::digest(&r).map_err(|_| CoreError::Protocol("receipt"))?;
        let bytes = r.to_bytes().map_err(|_| CoreError::Protocol("receipt"))?;
        Ok((digest, bytes))
    }

    /// Whether the nonce is open after `require_action`; a terminal nonce returns its recorded
    /// response (L2-REC-5). `check` never opens one.
    async fn opened(
        &self,
        req: &Request,
        digest: &Digest,
        actor_ref: &[u8],
        exercise: Digest,
    ) -> Result<Result<bool, Box<Response>>, CoreError> {
        if req.mode == Mode::Check {
            return Ok(Ok(false));
        }
        Ok(
            match self.replay(&req.nonce, digest, actor_ref, exercise).await? {
                Replay::Done(done) => Err(done),
                Replay::Open => Ok(true),
                Replay::New => Ok(false),
            },
        )
    }

    /// The PAP of an allowed `projection.issue` (L2-PAP-1, OP-143 m.11): its digest for the
    /// record and its payload.
    async fn pap_of(
        &self,
        inc: &Incoming,
        actor: Actor,
        fixed: &Fixed,
    ) -> Result<(Digest, Vec<u8>), CoreError> {
        use access_kernel::validity::{Revalidation, ValidityContract};
        let req = &inc.request;
        let Some(Payload::ProjectionIssue {
            bounds,
            audience,
            class,
            variant,
            max_staleness_ms,
            offline_slice,
        }) = &req.payload
        else {
            return Err(CoreError::Protocol("payload"));
        };
        let key = self
            .settled(|snap| {
                crate::domain::read::<InstanceState>(snap, kind::INSTANCE, &actor.instance)
                    .map(|i| i.key)
            })
            .await?
            .ok_or(CoreError::Protocol("instance"))?;
        let lineage = self
            .settled(|snap| crate::domain::lineage_commitment(snap, &req.basis))
            .await?
            .ok_or(CoreError::Protocol("basis"))?;
        // OP-143 m.12
        let slice = match (offline_slice, req.basis) {
            (Some(sl), meta::ExerciseBasis::Holding(h)) => self
                .settled(|snap| crate::domain::slice_entries(snap, &h.grant, sl))
                .await?
                .ok_or(CoreError::Protocol("basis"))?,
            _ => BTreeSet::new(),
        };
        // P52, OP-143 m.15 (d)
        let (bounds_set, local) = self.pseudonymous(&bounds.authority, &bounds.requirements)?;
        let capacity = match req.capacity {
            access_kernel::combinator::Capacity::For(p) => {
                access_kernel::combinator::Capacity::For(self.party_ref(&p)?)
            }
            own @ access_kernel::combinator::Capacity::Own => own,
        };
        let holder = access_kernel::pap::Holder {
            instance: actor.instance,
            key,
        };
        // §9.12.1, PI-12
        let (verifier_profile_ref, clock_source) =
            self.contract_profile(audience, fixed.now).await?;
        let validity = ValidityContract {
            issuing_exercise: fixed.exercise,
            basis_ref: dcbor::encode(
                &Value::Array(vec![
                    self.domain.to_value(),
                    Value::Unsigned(fixed.pos.saturating_sub(1)),
                ]),
                Limits::CEILING,
            )
            .map_err(|_| CoreError::Protocol("pap"))?,
            holder: access_kernel::pap::holder_digest(&holder)
                .map_err(|_| CoreError::Protocol("pap"))?,
            audience: audience.clone(),
            bounds: bounds_set.clone(),
            class: *class,
            variant: *variant,
            profile_version: 1,
            params: BTreeMap::new(),
            horizon: bounds.constraints.validity.until,
            max_staleness_ms: *max_staleness_ms,
            freshness_sources: BTreeSet::new(),
            revalidation: Revalidation::default(),
            offline_slice: slice,
            local_requirements: local.clone(),
            verifier_profile_ref,
            clock_source,
            clock_skew_ms: access_kernel::ais::SKEW_MS,
            must_understand: BTreeSet::new(),
            // OP-150 m.10 (a)
            status: inc.status.clone(),
        };
        let pap = access_kernel::pap::Pap {
            domain: self.domain,
            projection_exercise: fixed.exercise,
            holder,
            capacity,
            bounds: bounds_set,
            local_requirements: local,
            validity,
            lineage_commitment: lineage,
            iat: fixed.now,
        };
        let bytes = pap.to_bytes().map_err(|_| CoreError::Protocol("pap"))?;
        let digest = Digest(suiss_crypto::digest::context_digest("access/pap/v1", &bytes).0);
        Ok((digest, bytes))
    }

    /// The receipt of an ALLOW and the PAP of an allowed `projection.issue`, each with the digest
    /// the decision record carries (L2-RCP-2, L2-PAP-2).
    async fn artefacts(
        &self,
        inc: &Incoming,
        actor: Option<Actor>,
        fixed: &Fixed,
        allowed: bool,
    ) -> Result<(Option<(Digest, Vec<u8>)>, Option<(Digest, Vec<u8>)>), CoreError> {
        if !allowed {
            return Ok((None, None));
        }
        let receipt = Self::receipt_of(inc, &self.domain, actor, fixed)?;
        let pap = match (&inc.request.payload, actor) {
            (Some(Payload::ProjectionIssue { .. }), Some(a)) => {
                Some(self.pap_of(inc, a, fixed).await?)
            }
            _ => None,
        };
        Ok((Some(receipt), pap))
    }

    /// The rate limit of a request's class (§13.7.4, OP-141 m.23); an advisory `check` or
    /// explain also goes to the oracle-watch table, never to a metric label (§17.8.2, SEC31).
    fn admit(
        &mut self,
        inc: &Incoming,
        bucket: Who,
        actor: Option<Actor>,
        now: u64,
    ) -> Result<(), CoreError> {
        let class = Self::class_of(inc);
        let advisory = match class {
            Class::Check => Some(Advisory::Check),
            Class::Explain => Some(Advisory::Explain),
            Class::Commit | Class::Search => None,
        };
        if let Some(what) = advisory {
            match actor {
                Some(a) => ORACLE.record(&a.instance.0, what, now),
                None => ORACLE.record(b"anonymous", what, now),
            }
        }
        if self.limiter.admit(class, bucket, now) {
            Ok(())
        } else {
            Err(CoreError::Limited)
        }
    }

    /// The rate class of a request (§13.7.4, OP-141 m.23).
    const fn class_of(inc: &Incoming) -> Class {
        match (inc.request.mode, inc.explain) {
            (Mode::Check, true) => Class::Explain,
            (Mode::Check, false) => Class::Check,
            _ => Class::Commit,
        }
    }

    /// Requester throttling: a `REQUIRE_ACTION` that newly asks for a contribution
    /// counts against the actor Party's request rate; over it, the request is denied
    /// (§13.7.4, SEC28, OP-141 m.40).
    async fn throttled(
        &self,
        evaluation: &mut Evaluation,
        actor: Option<Actor>,
        open: bool,
        now: u64,
    ) -> Result<(), CoreError> {
        let asks = evaluation.decision.outcome == Outcome::RequireAction
            && evaluation
                .decision
                .unmet
                .iter()
                .any(|u| u.term.proof_kind == access_kernel::model::ProofKind::Contribution);
        let Some(actor) = actor.filter(|_| asks && !open) else {
            return Ok(());
        };
        let mut draws = Vec::new();
        for (len, limit) in crate::rate::REQUEST_RATE {
            let key = crate::rate::request_rate_key(&actor.party, len, now);
            if self.counter(&key).await? >= limit {
                // §13.7.4
                REQUESTER_THROTTLED.incr(["adp"]);
                tracing::warn!(
                    event = "api.throttled",
                    outcome = "deny",
                    surface = "adp",
                    "requester rate reached; the request is denied (§13.7.4)"
                );
                evaluation.decision = Decision {
                    outcome: Outcome::Deny,
                    blockers: vec![Blocker {
                        class: BlockerClass::Restricted,
                        subcode: Some(String::from("policy:request-rate")),
                        position: Position::ActorSide,
                        resolver: Resolver::Time,
                        remediation: Remediation::WaitUntil(
                            now.saturating_sub(now.checked_rem(len).unwrap_or(0))
                                .saturating_add(len),
                        ),
                    }],
                    unmet: Vec::new(),
                    relied_on: Vec::new(),
                };
                evaluation.draws.clear();
                return Ok(());
            }
            draws.push((key, limit, 1, None));
        }
        evaluation.draws.extend(draws);
        Ok(())
    }

    /// The bootstrap rate: an allowed Exercise of the Public bootstrap Grant draws on its PEP's
    /// and context's hourly counter; over [`crate::rate::BOOTSTRAP_RATE`] it is denied
    /// (§13.7.4, OP-152 m.5 (b)).
    async fn bootstrap_rate(
        &self,
        inc: &Incoming,
        evaluation: &mut Evaluation,
        now: u64,
    ) -> Result<(), CoreError> {
        let req = &inc.request;
        let bootstrap = matches!(req.basis, meta::ExerciseBasis::Public(g)
                if g == meta::object_id(&self.domain, kind::GRANT, crate::genesis::BOOTSTRAP_GRANT))
            && req
                .payload
                .as_ref()
                .is_some_and(|p| BOOTSTRAP.contains(&p.action()));
        if !bootstrap || evaluation.decision.outcome != Outcome::Allow {
            return Ok(());
        }
        let (len, limit) = crate::rate::BOOTSTRAP_RATE;
        let key = crate::rate::bootstrap_rate_key(&inc.pep, inc.context.as_ref(), len, now);
        if self.counter(&key).await? >= limit {
            REQUESTER_THROTTLED.incr(["bootstrap"]);
            tracing::warn!(
                event = "api.throttled",
                outcome = "deny",
                surface = "bootstrap",
                "bootstrap rate reached; the request is denied (§13.7.4)"
            );
            evaluation.decision = Decision {
                outcome: Outcome::Deny,
                blockers: vec![Blocker {
                    class: BlockerClass::Restricted,
                    subcode: Some(String::from("policy:bootstrap-rate")),
                    position: Position::ActorSide,
                    resolver: Resolver::Time,
                    remediation: Remediation::WaitUntil(
                        now.saturating_sub(now.checked_rem(len).unwrap_or(0))
                            .saturating_add(len),
                    ),
                }],
                unmet: Vec::new(),
                relied_on: Vec::new(),
            };
            evaluation.effects.clear();
            evaluation.draws.clear();
            evaluation.releases.clear();
            return Ok(());
        }
        evaluation.draws.push((key, limit, 1, None));
        Ok(())
    }

    /// Whether the domain declares causal-bound allowances (§7.9.7.4, OP-152 m.7 (d) E11).
    async fn causal_declared(&self) -> Result<bool, CoreError> {
        let key = meta::policy_default_key(meta::CAUSAL_BINDING);
        Ok(self
            .fetch(std::slice::from_ref(&key))
            .await?
            .into_iter()
            .any(|(_, v, _)| v == Some(Value::Bool(true))))
    }

    /// The count=1 causal-bound allowance of a request naming an upstream Exercise, in a domain
    /// that declares it: an allowed Exercise draws on the upstream `ExerciseID`'s counter, and a
    /// second downstream Exercise of the same upstream one is denied (§7.9.7.4, E17, EI-17,
    /// OP-152 m.7 (d) E11). Returns whether the link was enforced; `None` without an upstream.
    async fn causal_bound(
        &self,
        req: &Request,
        evaluation: &mut Evaluation,
    ) -> Result<Option<bool>, CoreError> {
        let Some(upstream) = req.intent.context.upstream_exercise else {
            return Ok(None);
        };
        if !self.causal_declared().await? {
            return Ok(Some(false));
        }
        if evaluation.decision.outcome != Outcome::Allow {
            return Ok(Some(true));
        }
        let key = crate::rate::causal_key(&upstream);
        if self.counter(&key).await? >= 1 {
            evaluation.decision = Decision {
                outcome: Outcome::Deny,
                blockers: vec![Blocker {
                    class: BlockerClass::Restricted,
                    subcode: Some(String::from("policy:causal-bound")),
                    position: Position::ActorSide,
                    resolver: Resolver::Actor,
                    remediation: Remediation::NewRequestRequired,
                }],
                unmet: Vec::new(),
                relied_on: Vec::new(),
            };
            evaluation.effects.clear();
            evaluation.draws.clear();
            evaluation.releases.clear();
            return Ok(Some(true));
        }
        evaluation.draws.push((key, 1, 1, None));
        Ok(Some(true))
    }

    /// A `check` of `inc` as if `subject` asked it, without an AIS: the single-subject
    /// eligibility check (OP-149 m.10, §9.5.2 rule 1). Nothing is recorded.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] for anything but an anonymous `check` without a payload; else as
    /// [`Authority::exercise`].
    pub async fn eligible(
        &mut self,
        inc: &Incoming,
        subject: Id,
        now: u64,
    ) -> Result<Response, CoreError> {
        if inc.request.mode != Mode::Check || inc.ais.is_some() || inc.request.payload.is_some() {
            return Err(CoreError::Protocol("eligibility"));
        }
        self.run(inc, now, Some(subject)).await
    }

    /// Runs one request through the commit path (§17.1.1).
    ///
    /// # Errors
    /// [`CoreError`] for a request that gets no decision.
    pub async fn exercise(&mut self, inc: &Incoming, now: u64) -> Result<Response, CoreError> {
        self.run(inc, now, None).await
    }

    /// The live Instance whose key signed the AIS of `inc`; `None` for an anonymous request or
    /// a key no Instance holds. The decision itself still establishes the actor; this only names
    /// the holder a projection family is opened for before the decision (OP-150 m.10 (a)).
    ///
    /// # Errors
    /// [`CoreError::Protocol`] for an AIS without a readable key id.
    pub async fn holder_of(&self, inc: &Incoming) -> Result<Option<Id>, CoreError> {
        let Some(sign1) = &inc.ais else {
            return Ok(None);
        };
        let kid = kid_of(sign1)?;
        let mut snap = Snapshot::default();
        Ok(self
            .instance_of(&mut snap, &kid)
            .await?
            .map(|(instance, _, _)| instance))
    }

    /// The actor and its rate-limit bucket: from the AIS, or for an eligibility check its
    /// `subject` with the PEP's bucket (OP-141 m.23, OP-149 m.10).
    async fn requester(
        &self,
        inc: &Incoming,
        digest: &Digest,
        now: u64,
        subject: Option<Id>,
    ) -> Result<(Option<Actor>, Who), CoreError> {
        Ok(match subject {
            None => {
                let actor = self.actor(inc, digest, now).await?;
                (actor, who(inc, actor))
            }
            Some(party) => (
                Some(Actor {
                    party,
                    instance: Id([0; 16]),
                }),
                pep_bucket(inc),
            ),
        })
    }

    /// The rules of the requester's side laid over the decision, in order: the requester
    /// throttle, the stale-holding softening and the projection issuance policy.
    async fn requester_rules(
        &self,
        req: &Request,
        evaluation: &mut Evaluation,
        actor: Option<Actor>,
        open: bool,
        now: u64,
    ) -> Result<(), CoreError> {
        self.throttled(evaluation, actor, open, now).await?;
        self.stale_holding(req, actor, evaluation, now).await?;
        self.projection_policy(req, evaluation, actor, now).await
    }

    /// The commit path; an eligibility check names its `subject`.
    #[expect(
        clippy::too_many_lines,
        reason = "the commit path in its order: resolve, evaluate, tier, approve, rules, record"
    )]
    async fn run(
        &mut self,
        inc: &Incoming,
        now: u64,
        subject: Option<Id>,
    ) -> Result<Response, CoreError> {
        let req = &inc.request;
        if req.domain != self.domain {
            return Err(CoreError::Protocol("domain"));
        }
        Self::check_payload(req, subject.is_some())?;
        let digest = intent_digest(&req.intent).map_err(|_| CoreError::Protocol("intent"))?;
        let (actor, bucket) = self.requester(inc, &digest, now, subject).await?;
        self.admit(inc, bucket, actor, now)?;
        self.continued(req, &digest, actor).await?;
        let exercise =
            meta::exercise_id(&req.domain, &req.nonce).map_err(|_| CoreError::Protocol("nonce"))?;
        let actor_ref = actor.map_or_else(|| b"anonymous".to_vec(), |a| a.instance.0.to_vec());
        let open = match self.opened(req, &digest, &actor_ref, exercise).await? {
            Ok(open) => open,
            Err(done) => return Ok(*done),
        };
        for _ in 0..MAX_RETRIES {
            let head = self.leader.head().pos;
            let mut resolved = self.resolve(req, actor.map(|a| a.party), now, head).await?;
            self.rebind(req, actor, &digest, &mut resolved, now).await?;
            let compromised = match self.compromised(actor, now).await? {
                Some(c) => Some(c),
                None => self.recovery_binding(req, actor, now).await?,
            };
            let records = u64::try_from(resolved.claims.len())
                .map_err(|_| CoreError::Protocol("proofs"))?
                .saturating_add(u64::from(!open))
                .saturating_add(1);
            let frame = self.frame(
                (digest, exercise, head.saturating_add(records)),
                actor,
                now,
                &resolved,
                compromised,
            );
            let (mut evaluation, snapshot) = self.passes(req, &frame).await?;
            let (tier, render, render_bytes) = rendered(req, &evaluation)?;
            self.tiered(req, &mut evaluation, open, now).await?;
            self.recovery_rules(req, actor, &mut evaluation, tier, now)
                .await?;
            self.approval(req, actor, &resolved, &mut evaluation, &exercise, now)
                .await?;
            self.requester_rules(req, &mut evaluation, actor, open, now)
                .await?;
            self.bootstrap_rate(inc, &mut evaluation, now).await?;
            let causal = self.causal_bound(req, &mut evaluation).await?;
            observe(&evaluation.decision);
            if req.mode == Mode::Check {
                let answered = answer(evaluation.decision, None, None, false);
                return Ok(Response { causal, ..answered });
            }
            let allowed = evaluation.decision.outcome == Outcome::Allow;
            let continued = req.exercise.unwrap_or(exercise);
            // §9.8, L2-RCP-1, L2-RCP-2
            let fixed = Fixed {
                exercise: continued,
                pos: frame.pos,
                intent: digest,
                now,
                drawn: !evaluation.draws.is_empty(),
                agency: evaluation.agency.clone(),
            };
            let (receipt, pap) = self.artefacts(inc, actor, &fixed, allowed).await?;
            let shape = Shape {
                digest: &digest,
                actor,
                actor_ref: &actor_ref,
                open,
                pos: frame.pos,
                exercise,
                artifacts: receipt.iter().chain(pap.iter()).map(|r| r.0).collect(),
                render,
                render_bytes,
                tier,
            };
            let derived = self.derived(req, &resolved, exercise, now).await?;
            let items = self.items(inc, &shape, &evaluation, &snapshot, &resolved, &derived)?;
            match self.leader.commit(now, &items).await {
                Ok(Committed::Appended(positions)) => {
                    let mut response = answer(
                        evaluation.decision,
                        allowed.then_some(continued),
                        positions.last().copied(),
                        false,
                    );
                    response.receipt = receipt.map(|r| r.1);
                    response.pap = pap.map(|p| p.1);
                    response.causal = causal;
                    // §9.9.3 k.6
                    response.ended = derived.ended_by_claims;
                    if allowed {
                        response.ended.extend(derived.ended);
                    }
                    return Ok(response);
                }
                Ok(Committed::Replayed(pos)) => {
                    return Ok(answer(
                        evaluation.decision,
                        Some(continued),
                        Some(pos),
                        true,
                    ));
                }
                Err(e) if e.is_retry() => retried(),
                Err(SequencerError::NonceConflict) => return Err(CoreError::Nonce),
                Err(e) => return Err(e.into()),
            }
        }
        Err(CoreError::Rejected(Rejection::Fuel))
    }

    /// The Claim records of a request (L2-CLM-4).
    fn claim_items(
        &mut self,
        resolved: &Proofs,
        derived: &events::Derived,
    ) -> Result<Vec<Item>, CoreError> {
        let mut out = Vec::with_capacity(resolved.claims.len());
        for c in &resolved.claims {
            let ckey = meta::key(kind::CLAIM, &c.id);
            let admit = c.disposition == Disposition::Admit;
            // L2-CLM-4, OP-141 m.20 (b)
            let effects: Vec<Effect> = if admit {
                meta::sorted(
                    vec![
                        (
                            ckey.clone(),
                            Some(
                                ClaimState {
                                    statement: c.statement.clone(),
                                    instance: c.instance,
                                    since: c.pos,
                                    ended: None,
                                }
                                .to_value(),
                            ),
                        ),
                        (
                            claim::member_key(&c.statement.class, &c.statement.subject, &c.id),
                            Some(c.id.to_value()),
                        ),
                    ]
                    .into_iter()
                    // OP-141 m.30 (b)
                    .chain(
                        c.statement
                            .supersedes
                            .map(|s| (claim::successor_key(&s, &c.id), Some(c.id.to_value()))),
                    )
                    .collect(),
                )
            } else {
                Vec::new()
            };
            let digest = claim::claim_digest(&c.bytes);
            let mut f = vec![
                ("claim", digest.to_value()),
                ("id", c.id.to_value()),
                ("issuer", c.statement.issuer.to_value()),
                ("subject", c.statement.subject.to_value()),
                ("class", Value::text(&c.statement.class)),
                ("disposition", Value::text(c.disposition.word())),
            ];
            if admit {
                f.push(("effects", effects_value(&effects)));
            }
            out.push(Item {
                draft: Draft {
                    kind: RecordKind::Claim,
                    fields: fields(&mut self.salts, f)?,
                },
                nonce: None,
                // OP-149 m.7
                events: derived.claims.get(&c.id).cloned().unwrap_or_default(),
                proofs: vec![(digest.0, c.bytes.clone())],
                reads: vec![(ckey.clone(), 0)],
                writes: effects.iter().map(|(k, _)| k.clone()).collect(),
                draws: c
                    .draw
                    .iter()
                    .map(|(key, limit)| Draw {
                        key: key.clone(),
                        limit: *limit,
                        draw: 1,
                    })
                    .collect(),
                single_use: Vec::new(),
            });
        }
        Ok(out)
    }

    /// The opening record of a new nonce (L2-REC-4).
    fn opening_item(&mut self, inc: &Incoming, shape: &Shape<'_>) -> Result<Item, CoreError> {
        let req = &inc.request;
        let digest = shape.digest;
        let actor_value = shape
            .actor
            .map_or_else(|| Value::text("anonymous"), |a| a.instance.to_value());
        let proof = inc.ais.as_ref().map(|b| {
            let d = suiss_crypto::digest::context_digest("access/ais/v1", b);
            (d, b.clone())
        });
        let mut opening = vec![
            ("nonce", Value::Bytes(req.nonce.clone())),
            ("actor", actor_value),
            ("basis", meta::basis_value(&req.basis)),
            ("capacity", meta::capacity_value(req.capacity)),
            ("intent", digest_value(digest)),
        ];
        if let Some((d, _)) = &proof {
            opening.push(("ais", d.to_value()));
        }
        if let Some(e) = &req.exercise {
            opening.push(("exercise", e.to_value()));
        }
        Ok(Item {
            draft: Draft {
                kind: RecordKind::Opening,
                fields: fields(&mut self.salts, opening)?,
            },
            nonce: None,
            events: Vec::new(),
            proofs: proof.map(|(d, b)| vec![(d.0, b)]).unwrap_or_default(),
            reads: Vec::new(),
            writes: Vec::new(),
            draws: Vec::new(),
            single_use: Vec::new(),
        })
    }

    fn items(
        &mut self,
        inc: &Incoming,
        shape: &Shape<'_>,
        evaluation: &Evaluation,
        snapshot: &Snapshot,
        resolved: &Proofs,
        derived: &events::Derived,
    ) -> Result<Vec<Item>, CoreError> {
        let req = &inc.request;
        let digest = shape.digest;
        let mut items = self.claim_items(resolved, derived)?;
        let allowed = evaluation.decision.outcome == Outcome::Allow;
        let outcome = match evaluation.decision.outcome {
            Outcome::Allow => "allow",
            Outcome::Deny => "deny",
            Outcome::RequireAction => "require_action",
        };
        if !shape.open {
            items.push(self.opening_item(inc, shape)?);
        }
        let mut effects = evaluation.effects.clone();
        let mut single_use = Vec::new();
        if allowed {
            allow_effects(shape, evaluation, resolved, &mut effects, &mut single_use);
            // EI-5, OP-156 m.3 (t)
            effects.extend(commitment::binding(
                &req.intent,
                req.payload.as_ref(),
                &shape.exercise,
            ));
        }
        let effects = meta::sorted(effects);
        let mut reads: Vec<(Vec<u8>, u64)> = snapshot.read_set();
        for r in &resolved.reads {
            if !reads.iter().any(|(k, _)| *k == r.0) {
                reads.push(r.clone());
            }
        }
        reads.sort();
        let mut decision = vec![
            ("outcome", decision_value(&evaluation.decision)),
            ("state_basis", state_basis_value(&reads)),
            (
                "versions",
                Value::Map(vec![
                    (Value::text("core"), Value::Unsigned(1)),
                    (Value::text("meta_schema"), Value::Unsigned(1)),
                ]),
            ),
            ("nonce", Value::Bytes(req.nonce.clone())),
            ("intent", digest_value(digest)),
        ];
        // TI-12, L2-RCP-2, L2-PAP-2
        decision.extend((!shape.artifacts.is_empty()).then(|| {
            (
                "artifacts",
                Value::Array(shape.artifacts.iter().map(Digest::to_value).collect()),
            )
        }));
        // OP-143 m.13 (g)
        let foreign = evaluation
            .foreign
            .as_ref()
            .map(|pap| (access_kernel::pap::pap_digest(pap), pap.clone()));
        if let Some((d, _)) = &foreign {
            decision.push(("proof_commit", Value::Array(vec![d.to_value()])));
        }
        if !effects.is_empty() {
            decision.push(("effects", effects_value(&effects)));
        }
        let draws = draws_of(evaluation);
        // OP-141 m.36 (a)
        if let Some(c) = consumption_value(&draws, &single_use) {
            decision.push(("consumption", c));
        }
        items.push(Item {
            draft: Draft {
                kind: RecordKind::Decision,
                fields: fields(&mut self.salts, decision)?,
            },
            nonce: Some(NonceUse {
                nonce: req.nonce.clone(),
                actor: shape.actor_ref.to_vec(),
                intent_digest: digest.0,
                outcome: String::from(outcome),
                render_digest: Some(shape.render.0),
                tier: Some(approval::tier_code(shape.tier)),
            }),
            // OP-130 m.9, OP-149 m.7
            events: if allowed {
                derived.decision.clone()
            } else {
                Vec::new()
            },
            // OP-143 m.13 (g); §9.14.5
            proofs: foreign
                .map(|(d, b)| (d.0, b))
                .into_iter()
                .chain(
                    (outcome == "require_action")
                        .then(|| (shape.render.0, shape.render_bytes.clone())),
                )
                .collect(),
            reads,
            writes: effects.iter().map(|(k, _)| k.clone()).collect(),
            draws,
            single_use,
        });
        Ok(items)
    }
}

/// The counter draws of a decision record: its budget draws and, for a release, the released
/// counters (OP-141 m.28 (g)).
fn draws_of(evaluation: &Evaluation) -> Vec<Draw> {
    evaluation
        .draws
        .iter()
        .map(|(key, limit, draw, _)| Draw {
            key: key.clone(),
            limit: *limit,
            draw: *draw,
        })
        .chain(evaluation.releases.iter().map(|(key, amount)| Draw {
            key: meta::released_key(key),
            limit: u64::MAX >> 1,
            draw: *amount,
        }))
        .collect()
}

/// The effects every ALLOW adds: the contributions it relied on are consumed (OP-141 m.19
/// (g)) and the Exercise is recorded for its continuations (L1-ADP-13).
fn allow_effects(
    shape: &Shape<'_>,
    evaluation: &Evaluation,
    resolved: &Proofs,
    effects: &mut Vec<Effect>,
    single_use: &mut Vec<Vec<u8>>,
) {
    for id in &evaluation.decision.relied_on {
        if let Some((k, c)) = resolved.contributions.get(id) {
            let mut c = c.clone();
            c.consumed = Some(shape.pos);
            effects.push((k.clone(), Some(c.to_value())));
            single_use.push(k.clone());
        }
    }
    if let Some(a) = shape.actor {
        effects.push((
            meta::exercise_key(kind::EXERCISE, &shape.exercise),
            Some(
                ExerciseState {
                    intent: *shape.digest,
                    actor: a.instance,
                    since: shape.pos,
                    draws: exercise_draws(evaluation),
                    grounds: BTreeSet::new(),
                }
                .to_value(),
            ),
        ));
    }
}

/// The `consumption` field of a decision record: its counter draws and single-use keys, each
/// sorted by key (OP-141 m.36 (a)); `None` when it consumes nothing.
fn consumption_value(draws: &[Draw], single_use: &[Vec<u8>]) -> Option<Value> {
    if draws.is_empty() && single_use.is_empty() {
        return None;
    }
    let mut d: Vec<(&[u8], u64)> = draws.iter().map(|d| (d.key.as_slice(), d.draw)).collect();
    d.sort_unstable();
    let mut u: Vec<&[u8]> = single_use.iter().map(Vec::as_slice).collect();
    u.sort_unstable();
    let mut fields = Vec::new();
    if !d.is_empty() {
        fields.push((
            Value::text("draws"),
            Value::Array(
                d.into_iter()
                    .map(|(k, n)| Value::Array(vec![Value::Bytes(k.to_vec()), Value::Unsigned(n)]))
                    .collect(),
            ),
        ));
    }
    if !u.is_empty() {
        fields.push((
            Value::text("single_use"),
            Value::Array(u.into_iter().map(|k| Value::Bytes(k.to_vec())).collect()),
        ));
    }
    Some(Value::Map(fields))
}

/// The draws an allowed Exercise records, sorted by key (OP-141 m.28 (a)).
fn exercise_draws(evaluation: &Evaluation) -> Vec<meta::ExerciseDraw> {
    let mut d: Vec<meta::ExerciseDraw> = evaluation
        .draws
        .iter()
        .map(|(key, _, draw, unit)| meta::ExerciseDraw {
            key: key.clone(),
            drawn: *draw,
            released: 0,
            unit: unit.clone(),
        })
        .collect();
    d.sort_by(|a, b| a.key.cmp(&b.key));
    d
}

/// The intent's consequence tier and its render digest from the accepted Action Schema
/// (§13.7.1, §9.13.3, XI-8): what the nonce keeps for the approval of a `REQUIRE_ACTION`.
fn rendered(
    req: &Request,
    evaluation: &Evaluation,
) -> Result<(access_kernel::tier::Tier, Digest, Vec<u8>), CoreError> {
    let tier = crate::requirements::tier_of(
        &req.intent,
        req.payload.as_ref(),
        evaluation.expansion,
        evaluation.action.as_deref(),
    );
    let render = access_kernel::render::of(
        evaluation.action.as_deref(),
        &req.intent,
        access_kernel::render::DEFAULT_LOCALE,
    )
    .map_err(|_| CoreError::Protocol("render"))?;
    let bytes =
        access_kernel::render::encode(&render).map_err(|_| CoreError::Protocol("render"))?;
    let digest =
        Digest(suiss_crypto::digest::context_digest(access_kernel::render::CONTEXT, &bytes).0);
    Ok((tier, digest, bytes))
}

/// Whom the rate limits count: the actor Instance, else the PEP (OP-141 m.23 (a)).
pub(crate) fn who(inc: &Incoming, actor: Option<Actor>) -> Who {
    actor.map_or_else(|| pep_bucket(inc), |a| Who::Instance(a.instance))
}

/// The PEP's bucket, or the bucket of the end user it names under it (OP-141 m.23 (a)).
fn pep_bucket(inc: &Incoming) -> Who {
    match &inc.requester {
        Some(r) => Who::Pep(format!("{}/{r}", inc.pep)),
        None => Who::Pep(inc.pep.clone()),
    }
}

/// Counts a re-validation after the head moved (§17.8.2, OP-32).
fn retried() {
    VALIDATION_RETRIES.incr(["exercise"]);
}

/// Counts a decision by outcome (§17.8.2, RR-8). Telemetry only: nothing reads it back
/// (TI-18).
fn observe(decision: &Decision) {
    DECISIONS.incr([match decision.outcome {
        Outcome::Allow => "allow",
        Outcome::Deny => "deny",
        Outcome::RequireAction => "require_action",
    }]);
}

const fn answer(
    decision: Decision,
    exercise: Option<Digest>,
    record: Option<u64>,
    replayed: bool,
) -> Response {
    Response {
        decision,
        exercise,
        record,
        replayed,
        basis_ref: None,
        consistency: None,
        receipt: None,
        signed_receipt: None,
        pap: None,
        signed_pap: None,
        ended: Vec::new(),
        explained: None,
        causal: None,
    }
}

/// Where a nonce stands (L2-REC-5).
enum Replay {
    /// Never seen.
    New,
    /// After `require_action`: evaluated again, only a decision is written.
    Open,
    /// Terminal: the recorded outcome.
    Done(Box<Response>),
}

/// What the records of one evaluation are built from.
/// What a receipt takes from the decision being committed.
struct Fixed {
    exercise: Digest,
    pos: u64,
    intent: Digest,
    now: u64,
    drawn: bool,
    agency: Vec<access_kernel::receipt::AgencyLink>,
}

struct Shape<'a> {
    digest: &'a Digest,
    actor: Option<Actor>,
    actor_ref: &'a [u8],
    open: bool,
    pos: u64,
    exercise: Digest,
    artifacts: Vec<Digest>,
    /// The intent's render digest and tier, kept with the nonce for its approval (§9.14.1,
    /// OP-150 L6), and the render itself for the surface to show (§9.14.5).
    render: Digest,
    render_bytes: Vec<u8>,
    tier: access_kernel::tier::Tier,
}

pub use access_kernel::contribution::NAMESPACE as CONTRIBUTION_NAMESPACE;

pub mod agent_status;
pub mod agents;
pub mod approval;
pub mod audit;
mod binding;
pub mod commitment;
pub mod consent;
mod events;
pub mod export;
pub mod faces;
pub mod hub;
pub mod impact;
mod ingest;
mod issuers;
pub mod lab;
pub mod management;
pub mod outcome;
pub mod projection;
mod proofs;
pub mod publishing;
pub mod recovery;
mod regime;
pub mod resources;
pub mod roles;
pub mod sources;
pub mod ssh;
pub mod vault;
mod workload;

pub use ingest::Ingested;
pub use proofs::{Compromise, MAX_PROOFS, NewClaim, Resolved};
pub use roles::ROLES_CLAIM;
