//! The approval behind a `contribute` Exercise (§9.14.1 A, AP-6, SI-5, §13.7.3, OP-150 L6):
//! the request carries the Approval Act Statement the approver's single act signed, and an
//! `authentication` Claim bound to H(AAS) from a present human of the tier's authenticator
//! class, fresh within the tier's ceiling. The statement is checked against what the decision
//! point recorded when it asked for the approval: the target intent, the render it computed
//! from the accepted Action Schema, the tier. A statement over another render is "The request
//! changed after you approved…" and approves nothing (§9.14.2).

use std::collections::BTreeMap;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::aas::{self, Act, ApprovalAct, Expected};
use access_kernel::assurance;
use access_kernel::claim::body::Class;
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Decision, Outcome, Position, Unmet};
use access_kernel::digest::Digest;
use access_kernel::meta::{self, Actor, ContributionState, InstanceState, Payload, kind};
use access_kernel::model::ProofKind;
use access_kernel::tier::Tier;
use suiss_crypto::dcbor::{self, Limits};

use crate::CoreError;
use crate::app::Authority;
use crate::app::proofs::Resolved;
use crate::domain::{Evaluation, ProofRef, Request, Snapshot};
use crate::ports::{Binding, Opening, Reader, Salts};

/// The tier as the nonce row stores it.
#[must_use]
pub const fn tier_code(tier: Tier) -> u8 {
    match tier {
        Tier::Ct0 => 0,
        Tier::Ct1 => 1,
        Tier::Ct2 => 2,
        Tier::Ct3 => 3,
    }
}

/// The tier a nonce row stores.
#[must_use]
pub const fn tier_of(code: u8) -> Option<Tier> {
    match code {
        0 => Some(Tier::Ct0),
        1 => Some(Tier::Ct1),
        2 => Some(Tier::Ct2),
        3 => Some(Tier::Ct3),
        _ => None,
    }
}

/// What the approver's act established, written to the contribution's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approved {
    /// H(AAS).
    pub statement: Digest,
    /// Assurance of the Claim bound to it.
    pub assurance: BTreeMap<String, u64>,
    /// Its `auth_time`.
    pub auth_time: u64,
}

fn protocol(e: aas::AasError) -> CoreError {
    CoreError::Protocol(e.code())
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    async fn instance_key(
        &self,
        instance: &access_kernel::model::Id,
    ) -> Result<access_kernel::verify::cose::PublicKey, CoreError> {
        let mut snap = Snapshot::default();
        self.get(&mut snap, &meta::key(kind::INSTANCE, instance))
            .await?
            .and_then(|v| InstanceState::from_value(&v).ok())
            .map(|s| s.key)
            .ok_or(CoreError::Protocol("aas-approver"))
    }

    /// The statement the request carries, verified against `expected`: a tagged `COSE_Sign1`
    /// under the approver Instance's key (L2-AAS-2), or the bare statement whose integrity the
    /// H(AAS)-bound Claim carries.
    async fn statement(
        &self,
        bytes: &[u8],
        actor: Actor,
        expected: &Expected<'_>,
    ) -> Result<(ApprovalAct, Digest), CoreError> {
        if bytes.first() == Some(&0xd2) {
            let key = self.instance_key(&actor.instance).await?;
            return aas::verify(bytes, &key, expected).map_err(protocol);
        }
        let value = dcbor::decode(bytes, Limits::CEILING)
            .map_err(|_| CoreError::Protocol("aas-malformed"))?;
        let act =
            ApprovalAct::from_value(&value).map_err(|_| CoreError::Protocol("aas-malformed"))?;
        aas::check(&act, expected).map_err(protocol)?;
        let h = aas::digest(&act).map_err(|_| CoreError::Protocol("aas-malformed"))?;
        Ok((act, h))
    }

    /// Checks the approval of an allowed `contribute` (§9.14.1 A step 4, §13.7.3) and writes
    /// what it established to the contribution's state. An ALLOW whose bound Claim is below the
    /// tier's authenticator class, lacks a present human or is stale becomes `REQUIRE_ACTION`
    /// with the authentication term unmet (a decision, not an error); a statement that does
    /// not fit the request, the recorded render or the actor is a protocol rejection.
    pub(crate) async fn approval(
        &self,
        req: &Request,
        actor: Option<Actor>,
        resolved: &Resolved,
        evaluation: &mut Evaluation,
        exercise: &Digest,
        now: u64,
    ) -> Result<(), CoreError> {
        let Some(Payload::Contribute { target, class }) = &req.payload else {
            return Ok(());
        };
        if evaluation.decision.outcome != Outcome::Allow {
            return Ok(());
        }
        let Some(actor) = actor else {
            return Err(CoreError::Protocol("aas-approver"));
        };
        let statements: Vec<&Vec<u8>> = req
            .proofs
            .iter()
            .filter_map(|p| match p {
                ProofRef::Aas(b) => Some(b),
                _ => None,
            })
            .collect();
        let [bytes] = statements.as_slice() else {
            return Err(CoreError::Protocol("aas"));
        };
        // §9.14.1 step 1: the approval answers a REQUIRE_ACTION of the target intent
        let Opening { render, tier } = self
            .reader
            .opening(target)
            .await?
            .ok_or(CoreError::Protocol("aas-target"))?;
        let expected = Expected {
            domain: &self.domain,
            target,
            instance: &actor.instance,
            render_digest: &render,
            now,
        };
        let (act, h) = self.statement(bytes, actor, &expected).await?;
        if act.act != Act::Contribution(class.clone()) {
            return Err(CoreError::Protocol("aas-act"));
        }
        if act.party != actor.party {
            return Err(CoreError::Protocol("aas-approver"));
        }
        if act.nonce != req.nonce {
            return Err(CoreError::Protocol("aas-nonce"));
        }
        // §13.7.3 "AAS expires_at"
        if !assurance::aas_within_ceiling(tier, act.issued_at, act.expires_at) {
            return Err(CoreError::Protocol("aas-expiry"));
        }
        // SI-5: the `authentication` Claim bound to H(AAS)
        let class_name = Class::Authentication.name();
        let bound = resolved
            .proofs
            .iter()
            .find(|p| {
                p.kind == ProofKind::Claim
                    && p.class == class_name
                    && p.binding.intent_digest == Some(h)
            })
            .ok_or(CoreError::Protocol("aas-binding"))?;
        let term = assurance::authentication_term(tier, true);
        if !assurance::meets(&term.assurance, &bound.assurance)
            || !assurance::fresh(tier, bound.time, now)
        {
            evaluation.decision = Decision {
                outcome: Outcome::RequireAction,
                blockers: Vec::new(),
                unmet: vec![Unmet {
                    term,
                    missing: 1,
                    position: Position::ActorSide,
                    satisfiable_by_actor: true,
                }],
                relied_on: Vec::new(),
            };
            evaluation.effects.clear();
            evaluation.draws.clear();
            evaluation.releases.clear();
            return Ok(());
        }
        let approved = Approved {
            statement: h,
            assurance: bound.assurance.clone(),
            auth_time: bound.time,
        };
        let key = meta::exercise_key(kind::CONTRIBUTION, exercise);
        for (k, v) in &mut evaluation.effects {
            if *k == key
                && let Some(value) = v
                && let Ok(mut c) = ContributionState::from_value(value)
            {
                c.statement = Some(approved.statement);
                c.assurance = approved.assurance.clone();
                c.auth_time = Some(approved.auth_time);
                *value = c.to_value();
            }
        }
        if !evaluation.decision.relied_on.contains(&bound.id) {
            evaluation.decision.relied_on.push(bound.id);
            evaluation.decision.relied_on.sort();
        }
        Ok(())
    }
}
