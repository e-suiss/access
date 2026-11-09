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
use access_kernel::requirement::Proof;
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

/// One part of the binding a `contribute` commit's `authentication` Claim must have (SI-5,
/// OP-150 m.14 (c)): what an `aas-binding` refusal names (OP-149 m.30 (b)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingFacet {
    /// A Claim of class `authentication` among the request's proofs.
    AuthenticationClaim,
    /// About the approver's Party.
    ApproverParty,
    /// Not bound to another Instance than the one that signed the statement.
    ApproverInstance,
    /// `bound_intent` is H(AAS).
    BoundIntent,
}

impl BindingFacet {
    /// Every facet, in the order the binding is narrowed.
    pub const ALL: [Self; 4] = [
        Self::AuthenticationClaim,
        Self::ApproverParty,
        Self::ApproverInstance,
        Self::BoundIntent,
    ];

    /// Stable code for problem details (RFC 9457 `errors[].code`).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationClaim => "authentication-claim",
            Self::ApproverParty => "approver-party",
            Self::ApproverInstance => "approver-instance",
            Self::BoundIntent => "bound-intent",
        }
    }
}

/// The facets no proof of the request meets, narrowed in [`BindingFacet::ALL`] order: once no
/// proof is left, the facets the plane cannot tell about any more are named too, so the list
/// says what was expected and, as far as the proofs show, what did not match.
fn unbound(proofs: &[Proof], actor: Actor, statement: Digest) -> Vec<BindingFacet> {
    let class_name = Class::Authentication.name();
    let mut left: Vec<&Proof> = proofs
        .iter()
        .filter(|p| p.kind == ProofKind::Claim)
        .collect();
    let mut facets = Vec::new();
    for facet in BindingFacet::ALL {
        left.retain(|p| match facet {
            BindingFacet::AuthenticationClaim => p.class == class_name,
            BindingFacet::ApproverParty => p.party == actor.party,
            BindingFacet::ApproverInstance => {
                p.binding.actor_instance.is_none_or(|i| i == actor.instance)
            }
            BindingFacet::BoundIntent => p.binding.intent_digest == Some(statement),
        });
        if left.is_empty() {
            facets.push(facet);
        }
    }
    facets
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

/// The statement is the actor's, for this request's nonce and capacity, within the tier's
/// ceiling (§9.14, §13.7.3, INV-4).
fn fits(act: &ApprovalAct, actor: Actor, req: &Request, tier: Tier) -> Result<(), CoreError> {
    if act.party != actor.party {
        return Err(CoreError::Protocol("aas-approver"));
    }
    if act.capacity != req.capacity {
        return Err(CoreError::Protocol("aas-capacity"));
    }
    if act.nonce != req.nonce {
        return Err(CoreError::Protocol("aas-nonce"));
    }
    if !assurance::aas_within_ceiling(tier, act.issued_at, act.expires_at) {
        return Err(CoreError::Protocol("aas-expiry"));
    }
    Ok(())
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

    /// The actor's own authority act (§9.14.1 B, §9.14.3, AP-6, P29, OP-152 m.7 (d) E19): a
    /// meta-Exercise other than `contribute` that carries an Approval Act Statement with
    /// `act = authority-act` over its own intent, nonce and the render the decision point recorded
    /// when it asked (`REQUIRE_ACTION`). The `authentication` Claim bound to H(AAS) then stands
    /// for the actor's intent-bound authentication: its binding is read as this intent's digest.
    /// Without a statement nothing changes; a statement that does not fit is a protocol
    /// rejection, and one no Claim is bound to is `aas-binding`.
    pub(crate) async fn rebind(
        &self,
        req: &Request,
        actor: Option<Actor>,
        digest: &Digest,
        resolved: &mut Resolved,
        now: u64,
    ) -> Result<(), CoreError> {
        if matches!(req.payload, None | Some(Payload::Contribute { .. })) {
            return Ok(());
        }
        let statements: Vec<&Vec<u8>> = req
            .proofs
            .iter()
            .filter_map(|p| match p {
                ProofRef::Aas(b) => Some(b),
                _ => None,
            })
            .collect();
        let bytes = match statements.as_slice() {
            [] => return Ok(()),
            [bytes] => *bytes,
            _ => return Err(CoreError::Protocol("aas")),
        };
        let actor = actor.ok_or(CoreError::Protocol("aas-approver"))?;
        // §9.14.1 step 1
        let Opening { render, tier } = self
            .reader
            .opening(digest)
            .await?
            .ok_or(CoreError::Protocol("aas-target"))?;
        let expected = Expected {
            domain: &self.domain,
            target: digest,
            instance: &actor.instance,
            render_digest: &render,
            now,
        };
        let (act, h) = self.statement(bytes, actor, &expected).await?;
        if act.act != Act::AuthorityAct {
            return Err(CoreError::Protocol("aas-act"));
        }
        fits(&act, actor, req, tier)?;
        let class_name = Class::Authentication.name();
        let mut bound = false;
        for p in &mut resolved.proofs {
            if p.kind == ProofKind::Claim
                && p.class == class_name
                && p.party == actor.party
                && p.binding.actor_instance.is_none_or(|i| i == actor.instance)
                && p.binding.intent_digest == Some(h)
            {
                p.binding.intent_digest = Some(*digest);
                bound = true;
            }
        }
        if bound {
            Ok(())
        } else {
            Err(CoreError::AasBinding(unbound(&resolved.proofs, actor, h)))
        }
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
        // §9.14.1 step 1
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
        fits(&act, actor, req, tier)?;
        // SI-5
        let class_name = Class::Authentication.name();
        let bound = resolved
            .proofs
            .iter()
            .find(|p| {
                p.kind == ProofKind::Claim
                    && p.class == class_name
                    && p.binding.intent_digest == Some(h)
            })
            .ok_or_else(|| CoreError::AasBinding(unbound(&resolved.proofs, actor, h)))?;
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
        // E49 (1), (3)
        let approved = Approved {
            statement: h,
            assurance: crate::requirements::contribution_assurance(&bound.assurance, &act),
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
