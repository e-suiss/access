//! The pure part of the commit path (§17.1.1 steps 4–8, OP-63): a snapshot of the state that
//! records what it served, and the decision for one request over it.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use access_kernel::algebra::Catalog;
use access_kernel::codec::{Canonical, Stored};
use access_kernel::combinator::{
    Basis, Blocker, BlockerClass, Capacity, Decision, EvaluationInput, Fuel, Hop, HopStatus,
    Mandate, Mode, Outcome as KernelOutcome, Position, Rejection, Remediation, Resolver, evaluate,
};
use access_kernel::digest::Digest;
use access_kernel::fold::Effect;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::{
    self, Actor, AnchorState, ExerciseBasis, GrantBasis, GrantState, MandateState, MetaError,
    Payload, View, kind,
};
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, ResourceSelector,
    Structural, Window,
};
use suiss_crypto::dcbor::Value;

/// Fuel for one evaluation (OP-111 m.7, PD).
pub const FUEL: u64 = 100_000;

/// The state at one position as far as it was fetched; every key it serves enters the read
/// set with the version it had (TI-4). A key not fetched yet is noted as missing.
#[derive(Debug, Default)]
pub struct Snapshot {
    values: BTreeMap<Vec<u8>, (Option<Value>, u64)>,
    reads: RefCell<BTreeSet<Vec<u8>>>,
    missing: RefCell<BTreeSet<Vec<u8>>>,
}

impl Snapshot {
    /// Adds fetched keys: `None` for a key that is absent, at version 0.
    pub fn fill(&mut self, rows: impl IntoIterator<Item = (Vec<u8>, Option<Value>, u64)>) {
        for (k, v, version) in rows {
            self.missing.borrow_mut().remove(&k);
            self.values.insert(k, (v, version));
        }
    }

    /// The value of a fetched key, without recording a read.
    #[must_use]
    pub fn values_of(&self, key: &[u8]) -> Option<Value> {
        self.values.get(key).and_then(|(v, _)| v.clone())
    }

    /// Whether `key` was fetched.
    #[must_use]
    pub fn has(&self, key: &[u8]) -> bool {
        self.values.contains_key(key)
    }

    /// Every fetched key with its version.
    #[must_use]
    pub fn fetched(&self) -> Vec<(Vec<u8>, u64)> {
        self.values
            .iter()
            .map(|(k, (_, v))| (k.clone(), *v))
            .collect()
    }

    /// The version of a fetched key, 0 when absent or not fetched.
    #[must_use]
    pub fn version_of(&self, key: &[u8]) -> u64 {
        self.values.get(key).map_or(0, |(_, v)| *v)
    }

    /// Keys asked for and not fetched yet.
    #[must_use]
    pub fn missing(&self) -> Vec<Vec<u8>> {
        self.missing.borrow().iter().cloned().collect()
    }

    /// Clears the read set and the missing keys before an evaluation is run again.
    pub fn restart(&self) {
        self.reads.borrow_mut().clear();
        self.missing.borrow_mut().clear();
    }

    /// The keys served, with the version each had.
    #[must_use]
    pub fn read_set(&self) -> Vec<(Vec<u8>, u64)> {
        self.reads
            .borrow()
            .iter()
            .filter_map(|k| self.values.get(k).map(|(_, v)| (k.clone(), *v)))
            .collect()
    }
}

impl View for Snapshot {
    fn get(&self, key: &[u8]) -> Option<Value> {
        self.reads.borrow_mut().insert(key.to_vec());
        if let Some((v, _)) = self.values.get(key) {
            return v.clone();
        }
        self.missing.borrow_mut().insert(key.to_vec());
        None
    }
}

/// The request as the commit path sees it after the transport layer.
#[derive(Clone, Debug)]
pub struct Request {
    /// The domain addressed.
    pub domain: Digest,
    /// The mode.
    pub mode: Mode,
    /// The nonce.
    pub nonce: Vec<u8>,
    /// The intent.
    pub intent: IntentEnvelope,
    /// The meta-action body, for an intent in the `access` namespace.
    pub payload: Option<Payload>,
    /// Declared basis.
    pub basis: ExerciseBasis,
    /// Declared capacity.
    pub capacity: Capacity,
    /// Proofs sent with the request (L1-ADP-12).
    pub proofs: Vec<ProofRef>,
    /// The Exercise continued, for `continue` (L1-ADP-13).
    pub exercise: Option<Digest>,
    /// The position the reader has seen, as an opaque token (OP-141 m.22 (f)).
    pub consistency: Option<String>,
}

/// A proof as the request carries it (L1-ADP-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofRef {
    /// A Claim's `COSE_Sign1`.
    Claim(Vec<u8>),
    /// A recorded Claim.
    ClaimRef(access_kernel::model::Id),
    /// The `ExerciseID` of an allowed `contribute`.
    Contribution(Digest),
}

/// What an evaluation produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// The Kernel decision.
    pub decision: Decision,
    /// State changes of an allowed meta-action.
    pub effects: Vec<Effect>,
}

/// The step after one pass over the snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pass {
    /// Fetch these keys and run again.
    Need(Vec<Vec<u8>>),
    /// The evaluation is complete over the snapshot.
    Done(Evaluation),
    /// A protocol rejection: no decision, no record (L0-EVAL-61).
    Rejected(Rejection),
}

fn deny(class: BlockerClass, subcode: &str, resolver: Resolver) -> Decision {
    Decision {
        outcome: KernelOutcome::Deny,
        blockers: vec![Blocker {
            class,
            subcode: Some(subcode.to_owned()),
            position: Position::Anchor,
            resolver,
            remediation: Remediation::NotSatisfiableByActor,
        }],
        unmet: Vec::new(),
        relied_on: Vec::new(),
    }
}

/// The blocker a refused meta-action produces.
fn meta_denial(e: MetaError) -> Decision {
    let class = match e {
        MetaError::Ended => BlockerClass::Ended,
        _ => BlockerClass::NoCoveringAuthority,
    };
    deny(class, e.code(), Resolver::Root)
}

fn everything() -> Window {
    Window {
        from: 0,
        until: u64::MAX,
    }
}

/// A hop that covers exactly the intent, with `requirements`: how an implicit power enters the
/// evaluator, so its requirements are resolved like any other.
fn exact_hop(
    intent: &IntentEnvelope,
    scope: Option<ResourceSelector>,
    requirements: BTreeSet<access_kernel::model::RequirementTerm>,
) -> Hop {
    let resource = scope.unwrap_or_else(|| {
        ResourceSelector::Structural(Structural {
            namespace: intent
                .resources
                .first()
                .map_or_else(String::new, |r| r.namespace.clone()),
            prefix: Vec::new(),
            kind: None,
            attrs: BTreeMap::new(),
        })
    });
    Hop {
        authority: CanonicalAuthority {
            authority: AuthoritySet {
                actions: ActionSet {
                    exact: BTreeSet::from([intent.action.clone()]),
                    prefix: BTreeSet::new(),
                },
                resource,
                params: BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            constraints: ConstraintSet {
                validity: everything(),
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth: 0,
                downstream_holder_class: None,
            },
            requirements,
        },
        status: HopStatus::Active,
        conditions_hold: true,
        budgets: Vec::new(),
    }
}

pub(crate) fn read<T: Canonical>(
    view: &dyn View,
    kind: &str,
    id: &access_kernel::model::Id,
) -> Option<T> {
    view.get(&meta::key(kind, id))
        .and_then(|v| T::from_value(&v).ok())
}

/// The lineage of a basis as Kernel hops, from the Anchor down to the basis Grant; an ended
/// Grant anywhere above makes the hops below it `Revoked` (INV-5).
pub(crate) fn lineage_hops(
    view: &dyn View,
    grant: &access_kernel::model::Id,
) -> Option<(Vec<Hop>, BTreeSet<Capacity>)> {
    let mut chain = Vec::new();
    let mut at = *grant;
    loop {
        if chain.len() >= meta::MAX_LINEAGE {
            return None;
        }
        let g: GrantState = read(view, kind::GRANT, &at)?;
        let next = g.content.basis;
        chain.push(g);
        match next {
            GrantBasis::Anchor(a) => {
                let anchor: AnchorState = read(view, kind::ANCHOR, &a)?;
                chain.reverse();
                let mut ended = anchor.ended.is_some();
                let capacities = chain.last()?.content.agency.clone();
                let hops = chain
                    .into_iter()
                    .map(|g| {
                        ended |= g.ended.is_some();
                        Hop {
                            authority: g.content.authority,
                            status: if ended {
                                HopStatus::Revoked
                            } else {
                                HopStatus::Active
                            },
                            conditions_hold: true,
                            budgets: Vec::new(),
                        }
                    })
                    .collect();
                return Some((hops, capacities));
            }
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
}

/// The Instance's Mandate, if it has a live one; the first by id (C14).
fn mandate(view: &dyn View, actor: Option<&Actor>) -> Option<Mandate> {
    let actor = actor?;
    let list = view.get(&meta::key(kind::MANDATES, &actor.instance))?;
    let Value::Array(ids) = list else {
        return None;
    };
    ids.iter().find_map(|id| {
        let id = access_kernel::model::Id::from_value(id).ok()?;
        let m: MandateState = read(view, kind::MANDATE, &id)?;
        m.ended.is_none().then_some(Mandate {
            authority: m.envelope.authority,
            requirements: m.envelope.requirements,
        })
    })
}

/// What one evaluation is made against besides the request and the state.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// The intent digest Access computed (TI-11).
    pub intent_digest: Digest,
    /// The `ExerciseID` (L0-META-3).
    pub exercise: Digest,
    /// Position the decision record will have.
    pub pos: u64,
    /// The actor, `None` for an anonymous request.
    pub actor: Option<Actor>,
    /// Trusted time.
    pub now: u64,
    /// The pinned catalog.
    pub catalog: &'a Catalog,
    /// The usable proofs (OP-141 m.19 (f)).
    pub proofs: &'a [access_kernel::requirement::Proof],
    /// For a holding basis on a Grant held by a predicate, the actor's episode start.
    pub held: Option<u64>,
}

/// One pass of the evaluation over `snapshot` (§17.1.1 steps 7–8). Implicit powers of a
/// meta-action are decided by the Kernel's meta module; their requirements, and every domain
/// action, go through the Kernel evaluator.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the two branches, meta-action and domain action, read best together"
)]
pub fn pass(req: &Request, frame: &Frame<'_>, snapshot: &Snapshot) -> Pass {
    let Frame {
        intent_digest,
        exercise,
        pos,
        actor,
        now,
        catalog,
        proofs,
        held,
    } = *frame;
    snapshot.restart();
    let mut effects = Vec::new();
    // L0-META-30: a contribution is authorized like a domain action and records itself
    let contribute = matches!(req.payload, Some(Payload::Contribute { .. }));
    if let Some(payload) = req.payload.as_ref().filter(|_| contribute) {
        let Some(actor) = actor else {
            return Pass::Done(Evaluation {
                decision: deny(
                    BlockerClass::NoCoveringAuthority,
                    "anonymous-meta",
                    Resolver::Actor,
                ),
                effects,
            });
        };
        let ctx = meta::Context {
            domain: req.domain,
            exercise,
            pos,
            actor,
            basis: req.basis,
            capacity: req.capacity,
            catalog,
        };
        match meta::apply(&ctx, payload, snapshot) {
            Ok(out) => effects = out.effects,
            Err(e) => {
                return Pass::Done(Evaluation {
                    decision: meta_denial(e),
                    effects: Vec::new(),
                });
            }
        }
    }
    let (bases, mandate) = if let Some(payload) = req.payload.as_ref().filter(|_| !contribute) {
        let Some(actor) = actor else {
            return Pass::Done(Evaluation {
                decision: deny(
                    BlockerClass::NoCoveringAuthority,
                    "anonymous-meta",
                    Resolver::Actor,
                ),
                effects,
            });
        };
        let ctx = meta::Context {
            domain: req.domain,
            exercise,
            pos,
            actor,
            basis: req.basis,
            capacity: req.capacity,
            catalog,
        };
        let out = meta::apply(&ctx, payload, snapshot);
        let missing = snapshot.missing();
        if !missing.is_empty() {
            return Pass::Need(missing);
        }
        match out {
            Err(e) => {
                return Pass::Done(Evaluation {
                    decision: meta_denial(e),
                    effects,
                });
            }
            Ok(out) => {
                effects = out.effects;
                // L0-META-13: a self-acting meta-action names a live Grant held by Public that
                // covers it, like any other basis
                let basis = if let ExerciseBasis::Public(g) = req.basis {
                    let public = read::<GrantState>(snapshot, kind::GRANT, &g)
                        .filter(|s| {
                            s.content.holder == access_kernel::model::SubjectSelector::Public
                        })
                        .and_then(|_| lineage_hops(snapshot, &g));
                    let missing = snapshot.missing();
                    if !missing.is_empty() {
                        return Pass::Need(missing);
                    }
                    public.map(|(hops, capacities)| Basis {
                        hops: hops.into_iter().map(Stored::Known).collect(),
                        capacities,
                    })
                } else {
                    Some(Basis {
                        hops: vec![Stored::Known(exact_hop(
                            &req.intent,
                            None,
                            out.requirements,
                        ))],
                        capacities: BTreeSet::from([req.capacity]),
                    })
                };
                // L0-EVAL-16: a Mandate bounds meta-actions like any other action
                let mandate = mandate(snapshot, Some(&actor));
                let missing = snapshot.missing();
                if !missing.is_empty() {
                    return Pass::Need(missing);
                }
                (basis.into_iter().collect::<Vec<_>>(), mandate)
            }
        }
    } else {
        let hops = match req.basis {
            ExerciseBasis::Anchor(a) => read::<AnchorState>(snapshot, kind::ANCHOR, &a)
                .filter(|s| s.ended.is_none())
                .and_then(|s| {
                    let terms = meta::root_requirements(&s, actor.as_ref()?)?;
                    let scope = match s.scope {
                        meta::AnchorScope::Resource(r) => Some(r),
                        _ => None,
                    };
                    Some((
                        vec![exact_hop(&req.intent, scope, terms)],
                        BTreeSet::from([Capacity::Own]),
                    ))
                }),
            ExerciseBasis::Holding(h) => read::<GrantState>(snapshot, kind::GRANT, &h.grant)
                .filter(|g| {
                    // OP-141 m.20 (c), (d): a predicate holder holds from its episode start
                    let holds = match &g.content.holder {
                        access_kernel::model::SubjectSelector::Party(p) => {
                            *p == h.holder && g.since == h.since
                        }
                        access_kernel::model::SubjectSelector::Pred(_) => held == Some(h.since),
                        _ => false,
                    };
                    actor.is_some_and(|a| a.party == h.holder) && holds
                })
                .and_then(|_| lineage_hops(snapshot, &h.grant)),
            ExerciseBasis::Public(g) => read::<GrantState>(snapshot, kind::GRANT, &g)
                .filter(|s| s.content.holder == access_kernel::model::SubjectSelector::Public)
                .and_then(|_| lineage_hops(snapshot, &g)),
        };
        let mandate = mandate(snapshot, actor.as_ref());
        let missing = snapshot.missing();
        if !missing.is_empty() {
            return Pass::Need(missing);
        }
        let bases = hops
            .map(|(hops, capacities)| Basis {
                hops: hops.into_iter().map(Stored::Known).collect(),
                capacities,
            })
            .into_iter()
            .collect::<Vec<_>>();
        (bases, mandate)
    };
    let input = EvaluationInput {
        mode: req.mode,
        intent: &req.intent,
        intent_digest,
        now,
        actor_instance: actor.map(|a| a.instance),
        actor_is_agent: false,
        mandate: mandate.as_ref(),
        capacity: req.capacity,
        bases: &bases,
        restrictions: &[],
        proofs,
        catalog,
    };
    match evaluate(&input, &mut Fuel(FUEL)) {
        Ok(decision) => {
            if decision.outcome != KernelOutcome::Allow {
                effects.clear();
            }
            Pass::Done(Evaluation { decision, effects })
        }
        Err(r) => Pass::Rejected(r),
    }
}
