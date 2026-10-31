//! The commit path (§17.1.1, OP-141): actor from the AIS, nonce rule, evaluation over a
//! snapshot fetched as it is read, and the opening and decision records committed together.

use std::collections::BTreeMap;

use access_authority_sequencer::SequencerError;
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::domain::{Draft, Item, NonceUse, Outcome as Committed};
use access_authority_sequencer::ports::DomainLog;
use access_kernel::ais::{self, AisError, Expected};
use access_kernel::algebra::Catalog;
use access_kernel::claim::{self, ClaimState, Disposition};
use access_kernel::codec::Canonical;
use access_kernel::combinator::codec::decision_value;
use access_kernel::combinator::{Decision, Mode, Outcome, Rejection};
use access_kernel::digest::Digest;
use access_kernel::fold::Effect;
use access_kernel::intent::intent_digest;
use access_kernel::meta::{self, Actor, ExerciseState, InstanceState, Payload, kind};
use access_kernel::model::{Id, ResourceRef};
use access_kernel::record::{Opened, RecordKind};
use access_kernel::verify::cose;
use access_store::authority::Draw;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::domain::{Evaluation, Frame, Pass, Request, Snapshot, pass};
use crate::ports::{Binding, Reader, Salts};
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
}

const BOOTSTRAP: [&str; 2] = ["party_register", "instance_create"];

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
    reader: R,
    binding: B,
    salts: S,
    domain: Digest,
    catalog: Catalog,
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The core over a leader that holds the domain's lease.
    pub fn new(leader: Leader<L>, reader: R, binding: B, salts: S, domain: Digest) -> Self {
        Self {
            leader,
            reader,
            binding,
            salts,
            domain,
            catalog: Catalog::default(),
        }
    }

    /// Extends the leader's lease.
    ///
    /// # Errors
    /// [`CoreError::Sequencer`]; the core must then be dropped.
    pub async fn renew(&self) -> Result<(), CoreError> {
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
        snapshot.fill(self.reader.fetch(keys).await?);
        Ok(())
    }

    /// §17.1.1 step 3: the actor of the request, `None` when it is anonymous.
    async fn actor(
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
        let (party, instance, key) = if bootstrap {
            let Some((party, key)) = self.binding.bound(&kid) else {
                return Ok(None);
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
        Ok(Replay::Done(Response {
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
        }))
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

    fn check_payload(req: &Request) -> Result<(), CoreError> {
        let is_meta = meta::is_meta(&req.intent.action.namespace, &req.intent.action.name);
        match &req.payload {
            Some(p) => {
                let body = p.digest().map_err(|_| CoreError::Protocol("payload"))?;
                if !is_meta
                    || p.action() != req.intent.action.name
                    || req.intent.opaque.get("payload") != Some(&body)
                {
                    return Err(CoreError::Protocol("payload"));
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
            None if is_meta => return Err(CoreError::Protocol("payload")),
            None => {}
        }
        match (req.mode, req.exercise) {
            (Mode::Continue, Some(_)) | (Mode::Commit | Mode::Check, None) => Ok(()),
            _ => Err(CoreError::Protocol("exercise")),
        }
    }

    /// Runs one request through the commit path (§17.1.1).
    ///
    /// # Errors
    /// [`CoreError`] for a request that gets no decision.
    pub async fn exercise(&mut self, inc: &Incoming, now: u64) -> Result<Response, CoreError> {
        let req = &inc.request;
        if req.domain != self.domain {
            return Err(CoreError::Protocol("domain"));
        }
        Self::check_payload(req)?;
        let digest = intent_digest(&req.intent).map_err(|_| CoreError::Protocol("intent"))?;
        let actor = self.actor(inc, &digest, now).await?;
        self.continued(req, &digest, actor).await?;
        let exercise =
            meta::exercise_id(&req.domain, &req.nonce).map_err(|_| CoreError::Protocol("nonce"))?;
        let actor_ref = actor.map_or_else(|| b"anonymous".to_vec(), |a| a.instance.0.to_vec());
        let open = if req.mode == Mode::Check {
            false
        } else {
            match self
                .replay(&req.nonce, &digest, &actor_ref, exercise)
                .await?
            {
                Replay::Done(done) => return Ok(done),
                Replay::Open => true,
                Replay::New => false,
            }
        };
        for _ in 0..MAX_RETRIES {
            let head = self.leader.head().pos;
            let resolved = self.resolve(req, actor.map(|a| a.party), now, head).await?;
            let records = u64::try_from(resolved.claims.len())
                .map_err(|_| CoreError::Protocol("proofs"))?
                .saturating_add(u64::from(!open))
                .saturating_add(1);
            let frame = Frame {
                intent_digest: digest,
                exercise,
                pos: head.saturating_add(records),
                actor,
                now,
                catalog: &self.catalog,
                proofs: &resolved.proofs,
                held: resolved.held,
            };
            let mut snapshot = Snapshot::default();
            let mut evaluation = None;
            for _ in 0..MAX_PASSES {
                match pass(req, &frame, &snapshot) {
                    Pass::Need(keys) => self.snapshot_get(&mut snapshot, &keys).await?,
                    Pass::Done(e) => {
                        evaluation = Some(e);
                        break;
                    }
                    Pass::Rejected(r) => return Err(CoreError::Rejected(r)),
                }
            }
            let evaluation = evaluation.ok_or(CoreError::Passes)?;
            if req.mode == Mode::Check {
                return Ok(Response {
                    decision: evaluation.decision,
                    exercise: None,
                    record: None,
                    replayed: false,
                    basis_ref: None,
                });
            }
            let shape = Shape {
                digest: &digest,
                actor,
                actor_ref: &actor_ref,
                open,
                pos: frame.pos,
                exercise,
            };
            let items = self.items(inc, &shape, &evaluation, &snapshot, &resolved)?;
            let allowed = evaluation.decision.outcome == Outcome::Allow;
            let continued = req.exercise.unwrap_or(exercise);
            match self.leader.commit(now, &items).await {
                Ok(Committed::Appended(positions)) => {
                    return Ok(Response {
                        decision: evaluation.decision,
                        exercise: allowed.then_some(continued),
                        record: positions.last().copied(),
                        replayed: false,
                        basis_ref: None,
                    });
                }
                Ok(Committed::Replayed(pos)) => {
                    return Ok(Response {
                        decision: evaluation.decision,
                        exercise: Some(continued),
                        record: Some(pos),
                        replayed: true,
                        basis_ref: None,
                    });
                }
                Err(e) if e.is_retry() => {}
                Err(SequencerError::NonceConflict) => return Err(CoreError::Nonce),
                Err(e) => return Err(e.into()),
            }
        }
        Err(CoreError::Rejected(Rejection::Fuel))
    }

    /// The Claim records of a request (L2-CLM-4).
    fn claim_items(&mut self, resolved: &Proofs) -> Result<Vec<Item>, CoreError> {
        let mut out = Vec::with_capacity(resolved.claims.len());
        for c in &resolved.claims {
            let ckey = meta::key(kind::CLAIM, &c.id);
            let admit = c.disposition == Disposition::Admit;
            // L2-CLM-4, OP-141 m.20 (b)
            let effects: Vec<Effect> = if admit {
                vec![
                    (
                        ckey.clone(),
                        Some(
                            ClaimState {
                                statement: c.statement.clone(),
                                instance: Some(c.instance),
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
                events: Vec::new(),
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
    ) -> Result<Vec<Item>, CoreError> {
        let req = &inc.request;
        let digest = shape.digest;
        let mut items = self.claim_items(resolved)?;
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
            // OP-141 m.19 (g): the contributions relied on are consumed
            for id in &evaluation.decision.relied_on {
                if let Some((k, c)) = resolved.contributions.get(id) {
                    let mut c = c.clone();
                    c.consumed = Some(shape.pos);
                    effects.push((k.clone(), Some(c.to_value())));
                    single_use.push(k.clone());
                }
            }
            // L1-ADP-13
            if let Some(a) = shape.actor {
                effects.push((
                    meta::exercise_key(kind::EXERCISE, &shape.exercise),
                    Some(
                        ExerciseState {
                            intent: *digest,
                            actor: a.instance,
                            since: shape.pos,
                        }
                        .to_value(),
                    ),
                ));
            }
        }
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
        if !effects.is_empty() {
            decision.push(("effects", effects_value(&effects)));
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
            }),
            events: Vec::new(),
            proofs: Vec::new(),
            reads,
            writes: effects.iter().map(|(k, _)| k.clone()).collect(),
            draws: Vec::new(),
            single_use,
        });
        Ok(items)
    }
}

/// Where a nonce stands (L2-REC-5).
enum Replay {
    /// Never seen.
    New,
    /// After `require_action`: evaluated again, only a decision is written.
    Open,
    /// Terminal: the recorded outcome.
    Done(Response),
}

/// What the records of one evaluation are built from.
struct Shape<'a> {
    digest: &'a Digest,
    actor: Option<Actor>,
    actor_ref: &'a [u8],
    open: bool,
    pos: u64,
    exercise: Digest,
}

/// Namespace of a contribution's resource (L0-META-30).
pub const CONTRIBUTION_NAMESPACE: &str = "access.contribution";

mod proofs;

pub use proofs::{MAX_PROOFS, NewClaim, Resolved};
