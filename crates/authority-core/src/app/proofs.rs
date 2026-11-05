//! The proofs a request carries, resolved against the state (OP-141 m.19 (b)–(f)): Claims are
//! verified and given a disposition, recorded Claims and contributions are looked up.

use std::collections::BTreeMap;

use access_authority_sequencer::ports::DomainLog;
use access_internal_api::events::compromise_from;
use access_kernel::claim::{self, ClaimState, Disposition, Gate, Statement};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use std::collections::BTreeSet;

use access_kernel::meta::{
    self, ContentState, ContributionState, ExerciseBasis, GrantState, InstanceState, kind,
};
use access_kernel::model::{Conjunct, Id, ProofKind, SubjectSelector};
use access_kernel::requirement::{Proof, ProofBinding};
use access_kernel::verify::cose::PublicKey;
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::Authority;
use crate::app::events::occurred;
use crate::domain::{ProofRef, Request, Snapshot};
use crate::ports::{Binding, Reader, Salts};

/// Most proofs one request carries (§13.7.4, OP-141 m.23 (e)).
pub const MAX_PROOFS: usize = 64;

/// A Claim the request records (L2-CLM-4).
#[derive(Clone, Debug)]
pub struct NewClaim {
    /// The `COSE_Sign1` bytes.
    pub bytes: Vec<u8>,
    /// Its `ClaimID`.
    pub id: Id,
    /// What it says.
    pub statement: Statement,
    /// The Instance that signed it; `None` for a Claim that came unsigned or by an external
    /// carrier.
    pub instance: Option<Id>,
    /// Its disposition.
    pub disposition: Disposition,
    /// Position of its record.
    pub pos: u64,
    /// The quota draw of an admitted Claim: counter key and limit (OP-141 m.21 (a)).
    pub draw: Option<(Vec<u8>, u64)>,
}

/// The proofs of one request.
#[derive(Clone, Debug, Default)]
pub struct Resolved {
    /// What the Kernel is given.
    pub proofs: Vec<Proof>,
    /// Claims to record before the decision.
    pub claims: Vec<NewClaim>,
    /// Keys read to resolve them, with their versions.
    pub reads: Vec<(Vec<u8>, u64)>,
    /// Contributions offered, by proof id: their key and state.
    pub contributions: BTreeMap<Id, (Vec<u8>, ContributionState)>,
    /// For a holding of a Grant held by a predicate: when the actor's episode began
    /// (OP-141 m.20 (d)).
    pub held: Option<u64>,
}

fn first16(d: &Digest) -> Id {
    let mut out = [0; 16];
    out.copy_from_slice(&d.0[..16]);
    Id(out)
}

fn claim_proof(id: Id, s: &Statement, instance: Option<Id>, position: u64) -> Proof {
    Proof {
        id,
        kind: ProofKind::Claim,
        class: s.class.clone(),
        position,
        time: s.issued_at,
        party: s.subject,
        instance: instance.unwrap_or(Id([0; 16])),
        issuer: s.issuer,
        binding: ProofBinding {
            actor_instance: s.bound_instance,
            intent_digest: s.bound_intent,
            resource: s.bound_resource.clone(),
        },
        assurance: s.assurance.clone(),
        consumed: false,
    }
}

/// One accepted `party_compromise` Claim (SEC12, OP-149 m.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compromise {
    /// occurredAt: from when the Party is taken as compromised, in trusted milliseconds.
    pub from: u64,
    /// The Claim.
    pub claim: Id,
    /// Position of the Claim's record.
    pub declared: u64,
    /// Trusted time of that record.
    pub declared_at: u64,
}

const fn current(s: &Statement, now: u64) -> bool {
    s.validity.from <= now && now <= s.validity.until
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The recorded successors of Claim `id` in the issuer line of `of`, other than `except`.
    async fn successors(
        &self,
        snap: &mut Snapshot,
        id: &Id,
        of: &Statement,
        except: &Id,
    ) -> Result<usize, CoreError> {
        let mut n: usize = 0;
        for (_, value, _) in self.scan(&claim::successor_prefix(id)).await? {
            let Some(c) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            if c == *except {
                continue;
            }
            let same = self
                .get(snap, &meta::key(kind::CLAIM, &c))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .is_some_and(|s| claim::same_line(of, &s.statement));
            if same {
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    /// Whether Claim `id` asserts in its issuer line: it has no recorded successor and is not
    /// one side of a fork (TI-RT7, OP-141 m.30 (c), (d)).
    pub(crate) async fn in_line(
        &self,
        snap: &mut Snapshot,
        id: &Id,
        s: &Statement,
    ) -> Result<bool, CoreError> {
        if self.successors(snap, id, s, id).await? > 0 {
            return Ok(false);
        }
        let Some(prev) = s.supersedes else {
            return Ok(true);
        };
        let prior = self
            .get(snap, &meta::key(kind::CLAIM, &prev))
            .await?
            .and_then(|v| ClaimState::from_value(&v).ok())
            .filter(|p| claim::same_line(&p.statement, s));
        match prior {
            Some(p) => Ok(self.successors(snap, &prev, &p.statement, id).await? == 0),
            None => Ok(true),
        }
    }

    pub(crate) async fn get(
        &self,
        snap: &mut Snapshot,
        key: &[u8],
    ) -> Result<Option<Value>, CoreError> {
        if !snap.has(key) {
            snap.fill(self.fetch(&[key.to_vec()]).await?);
        }
        Ok(snap.values_of(key))
    }

    /// The live Instance whose current key has thumbprint `kid`: its id, Party and key.
    pub(crate) async fn instance_of(
        &self,
        snap: &mut Snapshot,
        kid: &[u8; 32],
    ) -> Result<Option<(Id, Id, PublicKey)>, CoreError> {
        let Some(id) = self
            .get(snap, &meta::key_index(kid))
            .await?
            .and_then(|v| Id::from_value(&v).ok())
        else {
            return Ok(None);
        };
        let state = self
            .get(snap, &meta::key(kind::INSTANCE, &id))
            .await?
            .and_then(|v| InstanceState::from_value(&v).ok())
            .filter(|s| s.ended.is_none());
        Ok(state.map(|s| (id, s.party, s.key)))
    }

    /// The live Acceptances of `issuer` (L0-META-5).
    pub(crate) async fn gates(
        &self,
        snap: &mut Snapshot,
        issuer: &Id,
    ) -> Result<Vec<Gate>, CoreError> {
        Ok(self
            .widened_gates(snap, issuer)
            .await?
            .into_iter()
            .map(|(g, _)| g)
            .collect())
    }

    /// The live Acceptances of `issuer`, each with the position of its last widening
    /// (OP-141 m.42 (a)).
    async fn widened_gates(
        &self,
        snap: &mut Snapshot,
        issuer: &Id,
    ) -> Result<Vec<(Gate, u64)>, CoreError> {
        let Some(index) = self
            .get(snap, &meta::key(kind::ACCEPTANCES, issuer))
            .await?
        else {
            return Ok(Vec::new());
        };
        let Value::Array(ids) = index else {
            return Err(CoreError::Store(access_store::StoreError::Corrupt));
        };
        let mut gates = Vec::new();
        for v in ids {
            let id = Id::from_value(&v)
                .map_err(|_| CoreError::Store(access_store::StoreError::Corrupt))?;
            let Some(a) = self
                .get(snap, &meta::key(kind::ACCEPTANCE, &id))
                .await?
                .and_then(|v| ContentState::from_value(&v).ok())
            else {
                continue;
            };
            if a.ended.is_none()
                && let Ok(g) = Gate::of(&a.content)
            {
                gates.push((g, a.widened.unwrap_or(0)));
            }
        }
        Ok(gates)
    }

    /// Resolves the request's proofs at trusted time `now`; new Claim records take the
    /// positions after `head` (L2-CLM-2 to L2-CLM-4, L0-META-30).
    ///
    /// # Errors
    /// [`CoreError::Protocol`] for a Claim that does not verify or a reference to nothing.
    pub(crate) async fn resolve(
        &self,
        req: &Request,
        party: Option<Id>,
        now: u64,
        head: u64,
    ) -> Result<Resolved, CoreError> {
        let proofs = &req.proofs;
        if proofs.len() > MAX_PROOFS {
            return Err(CoreError::Protocol("proofs"));
        }
        let mut snap = Snapshot::default();
        let mut out = Resolved {
            held: None,
            ..Resolved::default()
        };
        let mut next = head;
        for p in proofs {
            match p {
                ProofRef::Claim(bytes) => {
                    let id = claim::claim_id(bytes);
                    let ckey = meta::key(kind::CLAIM, &id);
                    if out.claims.iter().any(|c| c.id == id) {
                        continue;
                    }
                    if self.get(&mut snap, &ckey).await?.is_some() {
                        self.recorded(&mut snap, &mut out, &id, now).await?;
                        continue;
                    }
                    next = next.checked_add(1).ok_or(CoreError::Protocol("position"))?;
                    self.inline(&mut snap, &mut out, bytes, next, now).await?;
                }
                ProofRef::ClaimRef(id) => {
                    let ckey = meta::key(kind::CLAIM, id);
                    if self.get(&mut snap, &ckey).await?.is_none() {
                        return Err(CoreError::Protocol("proof"));
                    }
                    self.recorded(&mut snap, &mut out, id, now).await?;
                }
                ProofRef::Contribution(e) => {
                    let k = meta::exercise_key(kind::CONTRIBUTION, e);
                    let c = self
                        .get(&mut snap, &k)
                        .await?
                        .and_then(|v| ContributionState::from_value(&v).ok())
                        .ok_or(CoreError::Protocol("proof"))?;
                    // OP-141 m.19 (g): a consumed contribution is no proof; SEC11: neither is
                    // one whose Instance has ended since
                    let live = self
                        .get(&mut snap, &meta::key(kind::INSTANCE, &c.instance))
                        .await?
                        .and_then(|v| InstanceState::from_value(&v).ok())
                        .is_some_and(|i| i.ended.is_none());
                    if c.consumed.is_some() || !live {
                        continue;
                    }
                    let id = first16(e);
                    out.proofs.push(Proof {
                        id,
                        kind: ProofKind::Contribution,
                        class: c.class.clone(),
                        position: c.since,
                        time: 0,
                        party: c.party,
                        instance: c.instance,
                        issuer: c.party,
                        binding: ProofBinding {
                            actor_instance: None,
                            intent_digest: Some(c.target),
                            resource: None,
                        },
                        assurance: BTreeMap::new(),
                        consumed: false,
                    });
                    out.contributions.insert(id, (k, c));
                }
                // OP-143 m.13 (d)
                ProofRef::ForeignPap { .. } => {}
            }
        }
        out.held = self.held(&mut snap, &req.basis, party, now).await?;
        // TI-4: every key read, except those the new Claim records write
        let new: Vec<Vec<u8>> = out
            .claims
            .iter()
            .map(|c| meta::key(kind::CLAIM, &c.id))
            .collect();
        out.reads = snap
            .fetched()
            .into_iter()
            .filter(|(k, _)| !new.contains(k))
            .collect();
        Ok(out)
    }

    /// When `party`'s episode of holding a Grant held by `conjuncts` began, if it holds it now:
    /// the latest of, per conjunct, the earliest record of a Claim that meets it under a
    /// `subject-selection` Acceptance, not before that Acceptance last widened (OP-141 m.20 (c),
    /// (d), m.42 (b)).
    pub(crate) async fn episode(
        &self,
        snap: &mut Snapshot,
        conjuncts: &BTreeSet<Conjunct>,
        party: &Id,
        now: u64,
    ) -> Result<Option<u64>, CoreError> {
        let mut since = None;
        for c in conjuncts {
            let mut first: Option<u64> = None;
            for (_, value, _) in self
                .scan(&claim::member_prefix(&c.claim_class, party))
                .await?
            {
                let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                    continue;
                };
                let Some(state) = self
                    .get(snap, &meta::key(kind::CLAIM, &id))
                    .await?
                    .and_then(|v| ClaimState::from_value(&v).ok())
                    .filter(|s| s.statement.subject == *party && claim::satisfies(c, s, now))
                else {
                    continue;
                };
                if !self.in_line(snap, &id, &state.statement).await? {
                    continue;
                }
                // OP-141 m.42 (b)
                let gates = self.widened_gates(snap, &state.statement.issuer).await?;
                let start = gates
                    .iter()
                    .filter(|(g, _)| g.admits_for(claim::SUBJECT_SELECTION, &state.statement, now))
                    .map(|(_, widened)| state.since.max(*widened))
                    .min();
                if let Some(start) = start {
                    first = Some(first.map_or(start, |f| f.min(start)));
                }
            }
            let Some(first) = first else {
                return Ok(None);
            };
            since = Some(since.map_or(first, |s: u64| s.max(first)));
        }
        Ok(since)
    }

    /// Whether a `party_compromise` overlay covers the actor Instance: an accepted, current
    /// Claim about its Party whose occurredAt is not after the Instance's establishment
    /// (SEC12, OP-141 m.31).
    pub(crate) async fn compromised(
        &self,
        actor: Option<meta::Actor>,
        now: u64,
    ) -> Result<bool, CoreError> {
        let Some(actor) = actor else {
            return Ok(false);
        };
        let Some(cutoff) = self
            .compromises(&actor.party, now)
            .await?
            .iter()
            .map(|c| c.from)
            .min()
        else {
            return Ok(false);
        };
        let mut snap = Snapshot::default();
        let since = self
            .get(&mut snap, &meta::key(kind::INSTANCE, &actor.instance))
            .await?
            .and_then(|v| InstanceState::from_value(&v).ok())
            .map(|i| i.since);
        let Some(since) = since else {
            return Ok(false);
        };
        Ok(self
            .reader
            .recorded_at(since)
            .await?
            .is_none_or(|at| at >= cutoff))
    }

    /// The accepted, current `party_compromise` Claims about `party` that assert in their
    /// issuer line, each with its occurredAt (SEC12, OP-141 m.31, OP-149 m.5).
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn compromises(&self, party: &Id, now: u64) -> Result<Vec<Compromise>, CoreError> {
        let mut snap = Snapshot::default();
        let mut found = Vec::new();
        for (_, value, _) in self
            .scan(&claim::member_prefix(claim::PARTY_COMPROMISE, party))
            .await?
        {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(&mut snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|s| {
                    s.ended.is_none()
                        && s.statement.subject == *party
                        && s.statement.class == claim::PARTY_COMPROMISE
                        && current(&s.statement, now)
                })
            else {
                continue;
            };
            let gates = self.gates(&mut snap, &state.statement.issuer).await?;
            if !gates
                .iter()
                .any(|g| g.admits_for(claim::PREDICATE_INPUT, &state.statement, now))
                || !self.in_line(&mut snap, &id, &state.statement).await?
            {
                continue;
            }
            // OP-149 m.17 (d)
            let from = compromise_from(
                occurred(state.statement.value.as_ref()),
                state.statement.issued_at,
            );
            found.push(Compromise {
                from,
                claim: id,
                declared: state.since,
                declared_at: self.reader.recorded_at(state.since).await?.unwrap_or(0),
            });
        }
        Ok(found)
    }

    /// The episode behind a holding basis whose Grant is held by a predicate.
    pub(crate) async fn held(
        &self,
        snap: &mut Snapshot,
        basis: &ExerciseBasis,
        party: Option<Id>,
        now: u64,
    ) -> Result<Option<u64>, CoreError> {
        let (ExerciseBasis::Holding(h), Some(party)) = (basis, party) else {
            return Ok(None);
        };
        let Some(SubjectSelector::Pred(conjuncts)) = self
            .get(snap, &meta::key(kind::GRANT, &h.grant))
            .await?
            .and_then(|v| GrantState::from_value(&v).ok())
            .map(|g| g.content.holder)
        else {
            return Ok(None);
        };
        self.episode(snap, &conjuncts, &party, now).await
    }

    /// A Claim the request carries: verified, given its disposition, and a proof when a
    /// `predicate-input` Acceptance admits it; its record takes position `pos` (L2-CLM-2 to
    /// L2-CLM-4).
    async fn inline(
        &self,
        snap: &mut Snapshot,
        out: &mut Resolved,
        bytes: &[u8],
        pos: u64,
        now: u64,
    ) -> Result<(), CoreError> {
        let id = claim::claim_id(bytes);
        let kid = claim::kid(bytes).map_err(|e| CoreError::Protocol(e.code()))?;
        let (instance, party, key) = self
            .instance_of(snap, &kid)
            .await?
            .ok_or(CoreError::Protocol("claim-signature"))?;
        let statement = claim::verify(bytes, &key, &party, &self.domain)
            .map_err(|e| CoreError::Protocol(e.code()))?;
        let gates = self.gates(snap, &statement.issuer).await?;
        let mut disposition = claim::disposition(&statement, &gates, now);
        let mut draw = None;
        if disposition == Disposition::Admit
            && let Some((limit, window)) = claim::quota_of(&statement, &gates, now)
        {
            let key = claim::quota_key(&statement.issuer, window, now);
            let pending = out
                .claims
                .iter()
                .filter(|c| c.draw.as_ref().is_some_and(|(k, _)| *k == key))
                .count();
            let used = self
                .counter(&key)
                .await?
                .saturating_add(u64::try_from(pending).unwrap_or(u64::MAX));
            if used >= limit {
                disposition = Disposition::Quota;
            } else {
                draw = Some((key, limit));
            }
        }
        let proof = gates
            .iter()
            .any(|g| g.admits_for(claim::PREDICATE_INPUT, &statement, now));
        if disposition == Disposition::Admit
            && proof
            && current(&statement, now)
            && self.in_line(snap, &id, &statement).await?
        {
            out.proofs
                .push(claim_proof(id, &statement, Some(instance), pos));
        }
        out.claims.push(NewClaim {
            bytes: bytes.to_vec(),
            id,
            statement,
            instance: Some(instance),
            disposition,
            pos,
            draw,
        });
        Ok(())
    }

    /// A recorded Claim as a proof, while an Acceptance still covers it (L2-CLM-3).
    async fn recorded(
        &self,
        snap: &mut Snapshot,
        out: &mut Resolved,
        id: &Id,
        now: u64,
    ) -> Result<(), CoreError> {
        let Some(state) = snap
            .values_of(&meta::key(kind::CLAIM, id))
            .and_then(|v| ClaimState::from_value(&v).ok())
            .filter(|s| s.ended.is_none())
        else {
            return Ok(());
        };
        let gates = self.gates(snap, &state.statement.issuer).await?;
        if current(&state.statement, now)
            && gates.iter().any(|g| g.admits(&state.statement, now))
            && self.in_line(snap, id, &state.statement).await?
        {
            out.proofs.push(claim_proof(
                *id,
                &state.statement,
                state.instance,
                state.since,
            ));
        }
        Ok(())
    }
}
