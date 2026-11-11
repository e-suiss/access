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
