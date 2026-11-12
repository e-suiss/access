//! Forced recovery on the authority side (§16.6 FR-0…FR-6, §13.6, SEC20–SEC22, OP-158 m.3 (m)).
//!
//! - FR-2: the recovering provider fetches each declared witness's latest cosigned checkpoint
//!   itself and records it, ahead of the `domain_recover` decision, as a `checkpoint` Claim of
//!   that witness with its `witness_head` entry. The witness's cosignature over the note is the
//!   Claim's proof; the requester's checkpoints are hints only.
//! - FR-3: a `domain_recover` passes only on `threshold` `recover` contributions whose Instance
//!   keys are keys of the Genesis recovery entry (SEC20, OP-158 m.7 (c)); the Kernel checks the
//!   rest (entry, R*, the two arms and the fork rule).
//! - PR-1: the post-recovery quarantine is the root's own narrowing `policy.set`
//!   ([`crate::restrict::patterns::post_recovery_quarantine`]).

use std::collections::BTreeSet;

use access_authority_sequencer::checkpoint::{CLAIM_CONTEXT, origin};
use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::{self, Disposition, Statement};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{BlockerClass, Outcome, Resolver};
use access_kernel::digest::Digest;
use access_kernel::meta::{InstanceState, Payload, kind};
use access_kernel::model::{EqValue, Id, Window};
use access_kernel::recovery::{CheckpointRef, RECOVER, RecoveryEntry};
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::note::{Checkpoint, Verifier, verify_note};
use suiss_crypto::sig::PureBackend;

use crate::CoreError;
use crate::app::Authority;
use crate::app::proofs::{NewClaim, Resolved};
use crate::domain::{Evaluation, Request};
use crate::ports::{Binding, Reader, Salts};

/// The context of a witness's Party id: `SHA-256(context ‖ 0x00 ‖ vkey)`, first 16 bytes.
pub const WITNESS_PARTY_CONTEXT: &str = "access/witness-party/v1";

/// How long a recorded witness head holds: the guard's freshness ceiling (SEC22, PD).
pub const HEAD_VALIDITY_MS: u64 = access_kernel::fold::WITNESS_FRESHNESS_MS;

/// The subcode of a `domain_recover` whose `recover` contributions do not come from enough
/// keys of the Genesis recovery entry (SEC20, OP-158 m.7 (c)).
pub const RECOVERY_KEY: &str = "recovery-key";

/// Why a witness answer is not a head the recovery can record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessHeadError {
    /// The cosignature does not verify under the witness's key, or carries no time.
    #[error("cosignature")]
    Cosignature,
    /// The note is not a checkpoint of this domain's log.
    #[error("checkpoint")]
    Checkpoint,
}

/// The Party id the domain records a witness under.
#[must_use]
pub fn witness_party(vkey: &str) -> Id {
    let d = suiss_crypto::digest::context_digest(WITNESS_PARTY_CONTEXT, vkey.as_bytes());
    let mut out = [0; 16];
    out.copy_from_slice(&d.0[..16]);
    Id(out)
}

/// One witness's latest cosigned checkpoint, checked (FR-2). Only [`WitnessHead::verified`]
/// makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessHead {
    party: Id,
    head: CheckpointRef,
    at: u64,
    body: Vec<u8>,
}

impl WitnessHead {
    /// The head `cosigned` states for `domain`, when `witness` (its `vkey`) cosigned it.
    ///
    /// # Errors
    /// [`WitnessHeadError`].
    pub fn verified(
        domain: &Digest,
        cosigned: &str,
        witness: &str,
    ) -> Result<Self, WitnessHeadError> {
        let verifier = Verifier::parse(witness).map_err(|_| WitnessHeadError::Cosignature)?;
        let (note, accepted) = verify_note(&PureBackend, cosigned, std::slice::from_ref(&verifier))
            .map_err(|_| WitnessHeadError::Cosignature)?;
        let seconds = accepted
            .iter()
            .find_map(|a| a.timestamp)
            .ok_or(WitnessHeadError::Cosignature)?;
        let cp = Checkpoint::parse(&note.body).map_err(|_| WitnessHeadError::Checkpoint)?;
        if cp.origin != origin(domain) {
            return Err(WitnessHeadError::Checkpoint);
        }
        let body = dcbor::encode(
            &Value::Map(vec![
                (Value::text("note"), Value::text(cosigned)),
                (Value::text("excerpt"), Value::Bytes(Vec::new())),
                (Value::text("trigger"), Value::text("out-of-cycle")),
            ]),
            Limits::CEILING,
        )
        .map_err(|_| WitnessHeadError::Checkpoint)?;
        Ok(Self {
            party: witness_party(witness),
            head: CheckpointRef::new(cp.size, Digest(cp.root)),
            at: seconds.saturating_mul(1_000),
            body,
        })
    }

    /// The witness's Party id.
    #[must_use]
    pub const fn party(&self) -> Id {
        self.party
    }

    /// The head.
    #[must_use]
    pub const fn head(&self) -> CheckpointRef {
        self.head
    }

    /// When the witness cosigned it, Unix ms.
    #[must_use]
    pub const fn at(&self) -> u64 {
        self.at
    }

    /// The Claim id the head is recorded under.
    #[must_use]
    pub fn claim(&self) -> Id {
        claim::claim_id(&self.body)
    }

    fn statement(&self, domain: Digest) -> Statement {
        Statement {
            domain,
            issuer: self.party,
            subject: self.party,
            class: claim::CHECKPOINT.to_owned(),
            value: Some(EqValue::Bytes(
                suiss_crypto::digest::context_digest(CLAIM_CONTEXT, &self.body)
                    .0
                    .to_vec(),
            )),
            issued_at: self.at,
            validity: Window {
                from: self.at,
                until: self.at.saturating_add(HEAD_VALIDITY_MS),
            },
            assurance: std::collections::BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        }
    }
}

/// The arm a recovery takes (§13.6, SEC22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arm {
    /// Arm (i): the replica reproduces the witnesses' highest checkpoint and N is it.
    Replica,
    /// Arm (ii): no replica, one behind the witnesses or a witness without a fresh head; the
    /// meta-anchor root's general threshold is needed and `(N, highest]` is the lost suffix.
    Lossy,
}

/// What a recovery cites (FR-3): N and its checkpoint, the replica's head, the lost suffix, the
/// fork's conflicting heads, and the arm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// N.
    pub n: u64,
    /// The checkpoint N cites.
    pub cited: CheckpointRef,
    /// R*, the replica's head, when a replica answered.
    pub replica_head: Option<CheckpointRef>,
    /// `(N, highest]`.
    pub lost_suffix: Option<access_kernel::recovery::LostSuffix>,
    /// The conflicting heads of a fork.
    pub fork: BTreeSet<CheckpointRef>,
    /// The arm.
    pub arm: Arm,
}

/// Why no recovery can be planned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// No fresh witness head: the witness quorum is missing.
    #[error("no-witness-head")]
    NoWitness,
    /// The recovery-side records reproduce no witnessed root.
    #[error("not-reproducible")]
    NotReproducible,
    /// The rollback guard refuses the plan.
    #[error("guard: {0}")]
    Guard(access_kernel::fold::GuardError),
}

/// SEC21, SEC22, FR-1…FR-3: plans the recovery from the declared witnesses' heads (`None` for
/// one that gave none, which leaves the quorum incomplete) and the roots the
/// recovery-side records reproduce, `roots[s]` being the root of the first `s` records (index 0
/// is the empty tree). `replica` says the records came from a provider-external replica, so N
/// is also R*, the highest witnessed checkpoint the replica reproduces. N is the highest size the records reproduce, not above the highest
/// witnessed one, whose root agrees with every head at that size; at a fork it stays on the
/// branch the records reproduce, or without a replica below the first forked size.
///
/// # Errors
/// [`PlanError`].
pub fn plan(
    heads: &[Option<WitnessHead>],
    roots: &[[u8; 32]],
    replica: bool,
    now: u64,
) -> Result<Plan, PlanError> {
    use access_kernel::fold::{Guard, rollback_guard};
    let fresh: Vec<&WitnessHead> = heads
        .iter()
        .flatten()
        .filter(|h| h.at <= now && now.saturating_sub(h.at) <= HEAD_VALIDITY_MS)
        .collect();
    let highest = fresh
        .iter()
        .map(|h| h.head.size)
        .max()
        .ok_or(PlanError::NoWitness)?;
    let mut by_size: std::collections::BTreeMap<u64, BTreeSet<[u8; 32]>> =
        std::collections::BTreeMap::new();
    for h in &fresh {
        by_size
            .entry(h.head.size)
            .or_default()
            .insert(h.head.root.0);
    }
    let fork_at = by_size
        .iter()
        .find_map(|(s, r)| (r.len() > 1).then_some(*s));
    let available = u64::try_from(roots.len().saturating_sub(1)).unwrap_or(u64::MAX);
    let root_at = |s: u64| usize::try_from(s).ok().and_then(|i| roots.get(i)).copied();
    let mut n = available.min(highest);
    if let (Some(f), false) = (fork_at, replica) {
        n = n.min(f.saturating_sub(1));
    }
    let agrees =
        |s: u64| root_at(s).is_some_and(|r| by_size.get(&s).is_none_or(|w| w.contains(&r)));
    while n > 0 && !agrees(n) {
        n = n.saturating_sub(1);
    }
    let root = root_at(n)
        .filter(|_| n > 0)
        .ok_or(PlanError::NotReproducible)?;
    let replica_head = replica.then(|| CheckpointRef::new(n, Digest(root)));
    let fork: BTreeSet<CheckpointRef> = match fork_at {
        Some(f) => fresh
            .iter()
            .filter(|h| h.head.size == f)
            .map(|h| h.head)
            .collect(),
        None => BTreeSet::new(),
    };
    let kernel: Vec<Option<access_kernel::fold::WitnessHead>> = heads
        .iter()
        .map(|h| {
            h.as_ref()
                .map(|h| access_kernel::fold::WitnessHead::new(h.head.size, h.head.root.0, h.at))
        })
        .collect();
    let guard = rollback_guard(
        &kernel,
        replica_head.map(|r| r.size),
        (n, root),
        !fork.is_empty(),
        now,
    )
    .map_err(PlanError::Guard)?;
    let (arm, lost_suffix) = match guard {
        Guard::Pass => (Arm::Replica, None),
        Guard::Lossy { from, until } => (
            Arm::Lossy,
            (from < until).then(|| access_kernel::recovery::LostSuffix::new(from, until)),
        ),
        _ => return Err(PlanError::NotReproducible),
    };
    Ok(Plan {
        n,
        cited: CheckpointRef::new(n, Digest(root)),
        replica_head,
        lost_suffix,
        fork,
        arm,
    })
}

/// FR-2: the recovering provider's own reading of each declared witness's latest cosigned
/// head of `domain`; a witness that does not answer or whose answer does not verify gives
/// none, which leaves the quorum incomplete (`REQUIRE_ACTION`, never a guess).
pub async fn fetch_witness_heads(
    targets: &[access_authority_sequencer::witness::Target],
    domain: &Digest,
) -> Vec<Option<WitnessHead>> {
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let head = match access_authority_sequencer::witness::latest(t, domain).await {
            Ok((_, note)) => WitnessHead::verified(domain, &note, &t.vkey).ok(),
            Err(_) => None,
        };
        out.push(head);
    }
    out
}

/// The roots of every prefix of a log whose leaves are `leaves`: index `s` is the root of the
/// first `s` records.
///
/// # Errors
/// [`PlanError::NotReproducible`] when the frontier overflows.
pub fn prefix_roots(leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, PlanError> {
    let mut f = suiss_ledger::merkle::Frontier::default();
    let mut out = Vec::with_capacity(leaves.len().saturating_add(1));
    out.push(f.root());
    for l in leaves {
        f.push(*l).map_err(|_| PlanError::NotReproducible)?;
        out.push(f.root());
    }
    Ok(out)
}

/// FR-1, FR-4: what the recovering provider adopts from the records `0..N − 1` an export or
/// the replica carried, once `note` is `C_N` over exactly those records with a cosignature of a
/// `witnesses` key. The outgoing binding keys are superseded at `C_N`, citing it (PR-0); the
/// recovery batch then starts at N. The adoption for the store, as run `run`, recorded as the
/// adopted run whose first and last kept position is N − 1.
///
/// # Errors
/// [`crate::app::handover::HandoverError::Batch`].
pub fn take_over(
    received: &crate::app::handover::Received,
    (note, witnesses): (&str, &[Verifier]),
    outgoing: &[access_kernel::verify::key_scope::BindingKey],
    run: [u8; 16],
) -> Result<crate::app::handover::TakeOver, crate::app::handover::HandoverError> {
    use crate::app::handover::{HandoverError, TakeOver, adopted_nonces, consumed, kind_word};
    let bad = HandoverError::Batch;
    let mut frontier = suiss_ledger::merkle::Frontier::default();
    let mut rows = Vec::with_capacity(received.records.len());
    for r in &received.records {
        let leaf = r.leaf_hash().map_err(|_| bad("leaf"))?;
        frontier.push(leaf).map_err(|_| bad("leaf"))?;
        rows.push(access_store::authority::LogRecord {
            pos: r.header.pos,
            kind: kind_word(r.header.kind),
            recorded_at: r.header.recorded_at,
            leaf_hash: leaf,
            envelope: r.to_bytes().map_err(|_| bad("encode"))?,
        });
    }
    let (_, accepted) = verify_note(&PureBackend, note, witnesses).map_err(|_| bad("witness"))?;
    let cp = Checkpoint::parse(
        &suiss_crypto::note::parse_note(note)
            .map_err(|_| bad("checkpoint"))?
            .body,
    )
    .map_err(|_| bad("checkpoint"))?;
    let n = received.cited.0;
    let last = received.records.last().ok_or(bad("records"))?;
    if accepted.iter().all(|a| a.timestamp.is_none())
        || cp.size != n
        || cp.root != frontier.root()
        || last.header.pos.checked_add(1) != Some(n)
    {
        return Err(bad("checkpoint"));
    }
    let superseded = outgoing
        .iter()
        .map(|b| {
            let mut b = b.clone();
            b.superseded = Some(access_kernel::verify::key_scope::Superseded {
                at: Digest(cp.root),
                cited: Digest(cp.root),
                cause: None,
            });
            b
        })
        .collect();
    let (counters, single_use) = consumed(&received.records);
    let nonces = adopted_nonces(&received.records)?;
    let state = received
        .state
        .iter()
        .map(|(key, e)| {
            let value = e
                .value
                .as_ref()
                .map(|v| dcbor::encode(v, Limits::CEILING))
                .transpose()
                .map_err(|_| bad("state"))?;
            Ok((key.clone(), value, e.version))
        })
        .collect::<Result<Vec<_>, HandoverError>>()?;
    let h = last.header.pos;
    Ok(TakeOver {
        domain: received.domain,
        cited: received.cited,
        h,
        at: cp.root,
        adoption: access_store::handover::Adoption {
            run,
            k: h,
            cited_root: cp.root,
            records: rows.clone(),
            head: access_store::authority::HeadRow {
                pos: h,
                epoch: 0,
                leaf_hash: rows.last().map(|r| r.leaf_hash).unwrap_or_default(),
                recorded_at: last.header.recorded_at,
                frontier: frontier.nodes().to_vec(),
            },
            state,
            nonces,
            counters,
            single_use,
        },
        superseded,
    })
}

/// How many distinct Instances gave a live `recover` contribution to `target` with a key of
/// `entry` (SEC20).
#[must_use]
pub fn entry_contributors(
    entry: &RecoveryEntry,
    target: &Digest,
    contributions: &[(Id, InstanceState, String, Digest)],
) -> u64 {
    let distinct: BTreeSet<Id> = contributions
        .iter()
        .filter(|(_, i, class, t)| {
            class == RECOVER
                && t == target
                && i.ended.is_none()
                && entry.keys.contains(&thumbprint(&i.key))
        })
        .map(|(id, ..)| *id)
        .collect();
    u64::try_from(distinct.len()).unwrap_or(u64::MAX)
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// FR-2: records the witness heads the recovering provider fetched itself, each as an
    /// admitted `checkpoint` Claim with its `witness_head` entry, in one commit ahead of the
    /// `domain_recover` decision; the Claim ids, in order.
    ///
    /// # Errors
    /// [`CoreError`] when the commit gets no answer.
    pub async fn record_witness_heads(
        &mut self,
        heads: &[WitnessHead],
        now: u64,
    ) -> Result<Vec<Id>, CoreError> {
        let mut resolved = Resolved::default();
        let first = self
            .leader
            .head()
            .pos
            .checked_add(1)
            .ok_or(CoreError::Protocol("position"))?;
        for (i, h) in heads.iter().enumerate() {
            let id = h.claim();
            resolved.claims.push(NewClaim {
                bytes: h.body.clone(),
                id,
                statement: h.statement(self.domain),
                instance: None,
                disposition: Disposition::Admit,
                pos: first.saturating_add(u64::try_from(i).unwrap_or(u64::MAX)),
                draw: None,
                beside: vec![(
                    access_kernel::recovery::witness_head_key(&id),
                    h.head.to_value(),
                )],
            });
        }
        let ids = resolved.claims.iter().map(|c| c.id).collect();
        let items = self.claim_items(&resolved, &crate::app::events::Derived::default())?;
        self.leader
            .commit(now, &items)
            .await
            .map_err(|_| CoreError::Unavailable("commit"))?;
        Ok(ids)
    }

    /// SEC20, OP-158 m.7 (c): an allowed `domain_recover` needs `threshold` `recover`
    /// contributions from distinct Instances whose keys are keys of the Genesis recovery entry;
    /// a contribution from any other key counts for nothing.
    pub(crate) async fn recovery_keys(
        &self,
        req: &Request,
        digest: &Digest,
        contributions: &[access_kernel::meta::ContributionState],
        evaluation: &mut Evaluation,
    ) -> Result<(), CoreError> {
        if !matches!(req.payload, Some(Payload::DomainRecover(_)))
            || evaluation.decision.outcome != Outcome::Allow
        {
            return Ok(());
        }
        let entry = self
            .fetch(&[access_kernel::recovery::entry_key()])
            .await?
            .into_iter()
            .find_map(|(_, v, _)| v)
            .and_then(|v| RecoveryEntry::from_value(&v).ok());
        let mut given = Vec::with_capacity(contributions.len());
        for c in contributions {
            let instance = self
                .fetch(&[access_kernel::meta::key(kind::INSTANCE, &c.instance)])
                .await?
                .into_iter()
                .find_map(|(_, v, _)| v)
                .and_then(|v| InstanceState::from_value(&v).ok());
            if let Some(i) = instance {
                given.push((c.instance, i, c.class.clone(), c.target));
            }
        }
        let enough = entry.is_some_and(|e| entry_contributors(&e, digest, &given) >= e.threshold);
        if !enough {
            evaluation.decision = crate::domain::deny(
                BlockerClass::NoCoveringAuthority,
                RECOVERY_KEY,
                Resolver::Root,
            );
            evaluation.effects.clear();
            evaluation.draws.clear();
            evaluation.releases.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
