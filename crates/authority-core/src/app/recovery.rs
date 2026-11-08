//! Account recovery on the authority side (§12.3.2, INV-13, INV-40, SEC18, OP-153 m.3 (c)): the
//! realm issuer's `recovery_result` Claim is the actor-binding of a self-signed
//! `instance_recover`; the successor it names binds no Mandate and receives no CT3 Grant while
//! the recovery path that proved it is weaker than the authority, and it meets no CT2+ term for
//! the first 24 hours.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::assurance::{HARDWARE_BOUND, NON_CUSTODIAL, PHISHING_RESISTANT, UV};
use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::claim::{self, ClaimState};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{
    Blocker, BlockerClass, Decision, Outcome, Position, Remediation, Resolver,
};
use access_kernel::meta::{self, Actor, InstanceState, MandateState, Payload, kind};
use access_kernel::model::{EqValue, Id, RequirementTerm, SubjectSelector};
use access_kernel::tier::Tier;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::{Evaluation, Request, Snapshot};
use crate::ports::{Binding, Reader, Salts};

/// The registry class of a finished recovery (OP-153 m.2 N0, `identity-claims.cddl`).
pub const RECOVERY_RESULT: &str = "recovery_result";

/// The subcode of a self-signed `instance_recover` no live `recovery_result` names (OP-153
/// m.3 (c)).
pub const ACTOR_BINDING: &str = access_internal_api::instances::RECOVERY_UNBOUND;

/// The subcode of a bind or a CT3 Grant the Party's recovery path is weaker than (INV-40).
pub const RECOVERY_TOO_WEAK: &str = "recovery-too-weak";

/// The subcode of a CT2+ Exercise by a successor younger than 24 hours (SEC18).
pub const COOLING: &str = "cooling";

/// The highest AAL any recovery path reaches (§12.3.2: never AAL3).
const RECOVERY_CEILING: u8 = 2;

/// One accepted, current `recovery_result` about a Party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovered {
    /// `x5t#S256` of the successor key.
    pub successor: [u8; 32],
    /// The AAL the recovery path reached.
    pub achieved_aal: u8,
    /// When the Claim stops holding.
    pub until: u64,
}

/// The fields of a `recovery_result` body naming `party`; `None` for a body that does not.
fn body_of(bytes: &[u8], party: &Id) -> Option<([u8; 32], u8)> {
    let v = dcbor::decode(bytes, Limits::CEILING).ok()?;
    let named = Id::from_value(v.get("party")?).ok()?;
    if named != *party {
        return None;
    }
    let successor = match v.get("successor")? {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).ok()?,
        _ => return None,
    };
    let aal = match v.get("achieved_aal")? {
        Value::Unsigned(n) => u8::try_from(*n).ok().filter(|n| (1..=3).contains(n))?,
        _ => return None,
    };
    Some((successor, aal))
}

/// The digest a `recovery_result` Claim carries in `value` for `body` (L2-CLB-1).
fn digest_of(body: &[u8]) -> Option<[u8; 32]> {
    let v = dcbor::decode(body, Limits::CEILING).ok()?;
    let bytes = dcbor::encode(
        &Value::Array(vec![Value::text(RECOVERY_RESULT), v]),
        Limits::CEILING,
    )
    .ok()?;
    Some(context_digest(BODY_CONTEXT, &bytes).0)
}

/// The AAL a requirement term asks of its actor (INV-40, §13.7.3): its `aal` floor when it
/// names one; AAL3 for a hardware-bound or non-custodial floor; AAL2 for a phishing-resistant
/// or user-verified one; AAL1 otherwise.
fn term_aal(t: &RequirementTerm) -> u8 {
    if let Some(aal) = t.assurance.get("aal") {
        return u8::try_from(*aal).unwrap_or(u8::MAX);
    }
    let has = |k: &str| t.assurance.get(k).is_some_and(|v| *v > 0);
    if has(HARDWARE_BOUND) || has(NON_CUSTODIAL) {
        3
    } else if has(PHISHING_RESISTANT) || has(UV) {
        2
    } else {
        1
    }
}

/// The recovery AAL an authority needs (INV-40): its strictest term, capped at what a recovery
/// path can reach at all, so an AAL3 term asks for the strongest recovery and is never a
/// standing DENY (OP-153 m.13 (e)).
#[must_use]
pub fn needed<'a>(terms: impl IntoIterator<Item = &'a RequirementTerm>) -> u8 {
    terms
        .into_iter()
        .map(term_aal)
        .max()
        .unwrap_or(1)
        .clamp(1, RECOVERY_CEILING)
}

/// Whether a Grant's terms make it a CT3 Grant: its authenticator class is the CT3 one
/// (§13.7.3: hardware-bound and non-custodial).
fn ct3_terms<'a>(terms: impl IntoIterator<Item = &'a RequirementTerm>) -> bool {
    terms.into_iter().any(|t| term_aal(t) >= 3)
}

fn require(decision: &mut Evaluation, subcode: &str, resolver: Resolver, until: u64) {
    decision.decision = Decision {
        outcome: Outcome::RequireAction,
        blockers: vec![Blocker {
            class: BlockerClass::Restricted,
            subcode: Some(String::from(subcode)),
            position: Position::ActorSide,
            resolver,
            remediation: Remediation::WaitUntil(until),
        }],
        unmet: Vec::new(),
        relied_on: Vec::new(),
    };
    decision.effects.clear();
    decision.draws.clear();
    decision.releases.clear();
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The accepted, current, unsuperseded `recovery_result` Claims about `party` whose
    /// disclosed body matches their value (OP-153 m.3 (c), L2-CLB-1): accepted means a gate of
    /// the issuer admits them for `actor-binding` (INV-40: the result is bound to the
    /// successor's actor-binding).
    pub(crate) async fn recoveries(
        &self,
        party: &Id,
        now: u64,
    ) -> Result<Vec<Recovered>, CoreError> {
        let mut snap = Snapshot::default();
        let mut out = Vec::new();
        for (_, value, _) in self
            .scan(&claim::member_prefix(RECOVERY_RESULT, party))
            .await?
        {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(&mut snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|c| {
                    let s = &c.statement;
                    c.ended.is_none()
                        && s.subject == *party
                        && s.class == RECOVERY_RESULT
                        && s.validity.from <= now
                        && now <= s.validity.until
                })
            else {
                continue;
            };
            let Some(EqValue::Bytes(d)) = &state.statement.value else {
                continue;
            };
            let Ok(d) = <[u8; 32]>::try_from(d.as_slice()) else {
                continue;
            };
            let Some(bytes) = self.reader.proof(&d).await? else {
                continue;
            };
            if digest_of(&bytes) != Some(d) {
                continue;
            }
            let Some((successor, achieved_aal)) = body_of(&bytes, party) else {
                continue;
            };
            let gates = self.gates(&mut snap, &state.statement.issuer).await?;
            let accepted = gates
                .iter()
                .any(|g| g.admits_for(claim::ACTOR_BINDING, &state.statement, now));
            if accepted && self.unsuperseded(&mut snap, &id, &state.statement).await? {
                out.push(Recovered {
                    successor,
                    achieved_aal,
                    until: state.statement.validity.until,
                });
            }
        }
        Ok(out)
    }

    /// OP-153 m.3 (c): a self-signed `instance_recover` stands only while a live, accepted
    /// `recovery_result` of the realm issuer names its key; otherwise the recorded DENY
    /// `actor-binding`.
    pub(crate) async fn recovery_binding(
        &self,
        req: &Request,
        actor: Option<Actor>,
        now: u64,
    ) -> Result<Option<&'static str>, CoreError> {
        let (Some(Payload::InstanceRecover { key, .. }), Some(actor)) = (&req.payload, actor)
        else {
            return Ok(None);
        };
        let kid = thumbprint(key);
        let named = self
            .recoveries(&actor.party, now)
            .await?
            .iter()
            .any(|r| r.successor == kid);
        Ok((!named).then_some(ACTOR_BINDING))
    }

    /// The live Instance `instance`.
    async fn live_instance(&self, instance: &Id) -> Result<Option<InstanceState>, CoreError> {
        let mut snap = Snapshot::default();
        Ok(self
            .get(&mut snap, &meta::key(kind::INSTANCE, instance))
            .await?
            .and_then(|v| InstanceState::from_value(&v).ok())
            .filter(|i| i.ended.is_none()))
    }

    /// The rules a recovery lays over an allowed decision:
    /// - INV-40 (ii): a `mandate_bind` or `mandate_rebind` by a Party with a live
    ///   `recovery_result`, and a new CT3 Grant to such a Party, need the recovery path's AAL to
    ///   reach the authority's strictest term; otherwise `REQUIRE_ACTION` ("strengthen
    ///   recovery") until the result lapses.
    /// - SEC18: a CT2+ Exercise by the successor a `recovery_result` named meets no term for 24
    ///   hours after its Instance was established; `REQUIRE_ACTION` until then.
    pub(crate) async fn recovery_rules(
        &self,
        req: &Request,
        actor: Option<Actor>,
        evaluation: &mut Evaluation,
        tier: Tier,
        now: u64,
    ) -> Result<(), CoreError> {
        if evaluation.decision.outcome != Outcome::Allow {
            return Ok(());
        }
        // INV-40
        let target = match &req.payload {
            Some(Payload::MandateBind { envelope, .. }) => actor.map(|a| {
                (
                    a.party,
                    needed(&envelope.requirements),
                    Resolver::ActorParty,
                )
            }),
            Some(Payload::MandateRebind { envelope, mandate }) => {
                let mut snap = Snapshot::default();
                let owner = self
                    .get(&mut snap, &meta::key(kind::MANDATE, mandate))
                    .await?
                    .and_then(|v| MandateState::from_value(&v).ok())
                    .map(|m| m.instance);
                let party = match owner {
                    Some(i) => self.live_instance(&i).await?.map(|i| i.party),
                    None => None,
                };
                party.map(|p| (p, needed(&envelope.requirements), Resolver::ActorParty))
            }
            Some(Payload::GrantIssue(content)) => match &content.holder {
                SubjectSelector::Party(p) if ct3_terms(&content.authority.requirements) => Some((
                    *p,
                    needed(&content.authority.requirements),
                    Resolver::Issuer,
                )),
                _ => None,
            },
            _ => None,
        };
        if let Some((party, need, resolver)) = target {
            let weak = self
                .recoveries(&party, now)
                .await?
                .into_iter()
                .filter(|r| r.achieved_aal < need)
                .map(|r| r.until)
                .max();
            if let Some(until) = weak {
                require(evaluation, RECOVERY_TOO_WEAK, resolver, until);
                return Ok(());
            }
        }
        // SEC18
        let Some(actor) = actor else {
            return Ok(());
        };
        if !matches!(tier, Tier::Ct2 | Tier::Ct3) {
            return Ok(());
        }
        let Some(state) = self.live_instance(&actor.instance).await? else {
            return Ok(());
        };
        let kid = thumbprint(&state.key);
        if !self
            .recoveries(&actor.party, now)
            .await?
            .iter()
            .any(|r| r.successor == kid)
        {
            return Ok(());
        }
        let born = self.reader.recorded_at(state.since).await?.unwrap_or(now);
        if let Err(available) = access_kernel::assurance::cooled(tier, born, now) {
            require(evaluation, COOLING, Resolver::Actor, available);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use access_kernel::model::{Binding as ProofBinding, Consumption, Independence, ProofKind};

    fn term(assurance: &[(&str, u64)]) -> RequirementTerm {
        RequirementTerm {
            proof_kind: ProofKind::Claim,
            class: String::from("authentication"),
            count: 1,
            binding: ProofBinding::None,
            freshness_ms: None,
            independence: Independence::None,
            consumption: Consumption::Reusable,
            source: None,
            assurance: assurance
                .iter()
                .map(|(k, v)| (String::from(*k), *v))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    // INV-40, TN-53, OP-153 m.13 (e)
    #[test]
    fn the_needed_recovery_follows_the_strictest_term_up_to_aal2() {
        assert_eq!(needed(&[]), 1);
        assert_eq!(needed(&[term(&[])]), 1);
        assert_eq!(needed(&[term(&[(PHISHING_RESISTANT, 1)])]), 2);
        assert_eq!(needed(&[term(&[]), term(&[(UV, 1)])]), 2);
        assert_eq!(needed(&[term(&[(HARDWARE_BOUND, 1)])]), 2);
        assert_eq!(needed(&[term(&[("aal", 1)])]), 1);
        assert!(ct3_terms(&[term(&[(HARDWARE_BOUND, 1)])]));
        assert!(!ct3_terms(&[term(&[(UV, 1)])]));
    }

    // OP-153 m.3 (c), L2-CLB-1
    #[test]
    fn a_recovery_body_names_its_party_and_successor() {
        let body = Value::Map(vec![
            (Value::text("party"), Id([2; 16]).to_value()),
            (Value::text("successor"), Value::Bytes(vec![9; 32])),
            (Value::text("attempt"), Id([5; 16]).to_value()),
            (Value::text("path"), Value::text("registered_code")),
            (Value::text("achieved_aal"), Value::Unsigned(2)),
        ]);
        let bytes = dcbor::encode(&body, Limits::CEILING).unwrap();
        assert_eq!(body_of(&bytes, &Id([2; 16])), Some(([9; 32], 2)));
        assert_eq!(body_of(&bytes, &Id([3; 16])), None);
        assert!(digest_of(&bytes).is_some());
    }
}
