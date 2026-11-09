//! Who may meet which requirement, on the decision path (§7.8 E49, §8.17.5.4, §8.18.3,
//! §13.7.3, AGI-4, AGI-8, OP-154 m.3 (x)).
//!
//! - The approval ceiling: a contribution term takes the floors of
//!   [`access_kernel::requirement::approval_ceiling`] for the intent's tier and reversibility, so
//!   an approval from a surface below them is no contribution and the request stays
//!   `REQUIRE_ACTION`. The ceiling only tightens.
//! - A contribution's assurance is the bound `authentication` Claim's, with the surface class
//!   its Approval Act Statement declares and no more evidence than the statement declares.
//! - An agent actor's proofs: a contribution from the agent's own Party, its own Instance or
//!   any other agent counts for nothing (AGI-8); no Claim about the agent stands for a present
//!   human (AGI-4); from CT2 a proof bound to the agent's Instance counts only with an
//!   `attestation_runtime` Claim bound to that Instance and a hardware-bound key (Ek B 4121).

use std::collections::BTreeMap;

use access_kernel::aas::ApprovalAct;
use access_kernel::claim::body::Class;
use access_kernel::meta::{self, Actor, View};
use access_kernel::model::{ProofKind, RequirementTerm};
use access_kernel::requirement::{self, HUMAN_PRESENCE, Proof, SURFACE};
use access_kernel::schema::{ActionSchema, Reversibility};
use access_kernel::tier::Tier;

/// The ceiling's floors for an intent of `tier` on `schema`, with or without a Mandate the
/// actor acts within (E49 (2)): a domain action without a declared reversibility, and every
/// meta-action, is irreversible.
#[must_use]
pub fn ceiling(
    tier: Tier,
    schema: Option<&ActionSchema>,
    within_mandate: bool,
) -> BTreeMap<String, u64> {
    let ct = match tier {
        Tier::Ct0 => 0,
        Tier::Ct1 => 1,
        Tier::Ct2 => 2,
        Tier::Ct3 => 3,
    };
    let reversibility = schema.map_or(Reversibility::Irreversible, ActionSchema::reversibility);
    requirement::approval_ceiling(ct, reversibility, within_mandate)
}

/// `term` with the ceiling's floors when it asks for a contribution; any other term unchanged.
#[must_use]
pub fn with_ceiling(mut term: RequirementTerm, floors: &BTreeMap<String, u64>) -> RequirementTerm {
    if term.proof_kind == ProofKind::Contribution {
        for (dim, floor) in floors {
            let level = term.assurance.entry(dim.clone()).or_insert(*floor);
            *level = (*level).max(*floor);
        }
    }
    term
}

/// The assurance a contribution keeps (E49 (1), (3)): the bound Claim's levels, lowered to
/// what the statement's declared evidence reaches, with the statement's surface class. An
/// undeclared surface claims none.
#[must_use]
pub fn contribution_assurance(
    claim: &BTreeMap<String, u64>,
    act: &ApprovalAct,
) -> BTreeMap<String, u64> {
    let declared = access_kernel::aas::assurance_of(act.surface_class, act.evidence);
    let mut out = claim.clone();
    out.remove(SURFACE);
    for (dim, level) in &declared {
        if dim == SURFACE {
            out.insert(dim.clone(), *level);
        } else if let Some(have) = out.get_mut(dim) {
            *have = (*have).min(*level);
        }
    }
    out
}

fn tier_rank(t: Tier) -> u8 {
    match t {
        Tier::Ct0 => 0,
        Tier::Ct1 => 1,
        Tier::Ct2 => 2,
        Tier::Ct3 => 3,
    }
}

/// The proofs that may count for `actor` at `tier` (AGI-4, AGI-8, Ek B 4121); every proof
/// counts for a person.
#[must_use]
pub fn admissible(
    proofs: &[Proof],
    actor: Option<&Actor>,
    actor_is_agent: bool,
    tier: Tier,
    view: &dyn View,
) -> Vec<Proof> {
    let Some(actor) = actor.filter(|_| actor_is_agent) else {
        return proofs.to_vec();
    };
    let runtime = Class::AttestationRuntime.name();
    let attested = proofs.iter().any(|p| {
        p.kind == ProofKind::Claim
            && p.class == runtime
            && p.binding.actor_instance == Some(actor.instance)
    });
    proofs
        .iter()
        .filter(|p| match p.kind {
            // AGI-8
            ProofKind::Contribution => {
                p.party != actor.party
                    && p.instance != actor.instance
                    && !meta::actor_is_agent(view, &p.party)
            }
            ProofKind::Claim | ProofKind::Authentication => {
                // AGI-4
                let human = p.party == actor.party
                    && p.assurance.get(HUMAN_PRESENCE).is_some_and(|v| *v > 0);
                // Ek B 4121
                let actor_side =
                    p.binding.actor_instance == Some(actor.instance) && p.class != runtime;
                let hardware = p.assurance.get("hardware_bound").is_some_and(|v| *v > 0);
                !human && (!actor_side || tier_rank(tier) < 2 || (attested && hardware))
            }
            ProofKind::ForeignAuthority => true,
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use access_kernel::aas::{Act, EvidenceLevel, SurfaceClass};
    use access_kernel::combinator::Capacity;
    use access_kernel::digest::Digest;
    use access_kernel::model::Id;
    use access_kernel::requirement::ProofBinding;

    use super::*;
    use crate::domain::Snapshot;

    fn schema(reversibility: Option<Reversibility>) -> ActionSchema {
        ActionSchema {
            reversibility,
            name: "pay".to_owned(),
            major: 1,
            effect: access_kernel::schema::EffectClass::Reversible,
            reserved: false,
            consumption_bearing: false,
            params: BTreeMap::new(),
            resource_types: BTreeSet::new(),
            render: None,
        }
    }

    fn screen() -> BTreeMap<String, u64> {
        BTreeMap::from([
            (SURFACE.to_owned(), 2),
            ("phishing_resistant".to_owned(), 1),
        ])
    }

    // E49 (2), OP-154 m.3 (x), Ek B 4370
    #[test]
    fn only_a_low_reversible_action_inside_its_mandate_takes_a_small_surface() {
        let reversible = schema(Some(Reversibility::Reversible));
        let compensable = schema(Some(Reversibility::Compensable));
        assert!(ceiling(Tier::Ct1, Some(&reversible), true).is_empty());
        assert!(ceiling(Tier::Ct0, Some(&compensable), true).is_empty());
        assert_eq!(ceiling(Tier::Ct1, Some(&reversible), false), screen());
        assert_eq!(ceiling(Tier::Ct2, Some(&reversible), true), screen());
        assert_eq!(
            ceiling(
                Tier::Ct1,
                Some(&schema(Some(Reversibility::Irreversible))),
                true
            ),
            screen()
        );
        assert_eq!(ceiling(Tier::Ct1, Some(&schema(None)), true), screen());
        assert_eq!(ceiling(Tier::Ct0, None, true), screen());
        let approve = RequirementTerm {
            proof_kind: ProofKind::Contribution,
            class: "approve".to_owned(),
            count: 1,
            binding: access_kernel::model::Binding::IntentDigest,
            freshness_ms: None,
            independence: access_kernel::model::Independence::None,
            consumption: access_kernel::model::Consumption::SingleUse,
            source: None,
            assurance: BTreeMap::from([("aal".to_owned(), 3), (SURFACE.to_owned(), 0)]),
        };
        let tight = with_ceiling(approve.clone(), &screen());
        assert_eq!(tight.assurance.get(SURFACE), Some(&2));
        assert_eq!(tight.assurance.get("phishing_resistant"), Some(&1));
        assert_eq!(tight.assurance.get("aal"), Some(&3));
        let mut claim = approve;
        claim.proof_kind = ProofKind::Claim;
        assert_eq!(with_ceiling(claim.clone(), &screen()), claim);
    }

    fn act(surface: Option<SurfaceClass>, evidence: Option<EvidenceLevel>) -> ApprovalAct {
        ApprovalAct {
            act: Act::Contribution("approve".to_owned()),
            instance: Id([1; 16]),
            party: Id([2; 16]),
            capacity: Capacity::Own,
            target: Digest([3; 32]),
            domain: Digest([4; 32]),
            nonce: vec![5; 16],
            work_gate: None,
            surface_profile: "p".to_owned(),
            surface_version: 1,
            surface_class: surface,
            evidence,
            render_digest: Digest([6; 32]),
            material_fields: BTreeSet::new(),
            issued_at: 0,
            expires_at: 1,
        }
    }

    // E49 (1), (3), Ek B 4371
    #[test]
    fn a_contribution_keeps_the_surface_and_no_more_than_the_declared_evidence() {
        let passkey = BTreeMap::from([
            ("phishing_resistant".to_owned(), 1),
            ("uv".to_owned(), 1),
            (HUMAN_PRESENCE.to_owned(), 1),
            ("aal".to_owned(), 2),
            (SURFACE.to_owned(), 2),
        ]);
        let voice = contribution_assurance(
            &passkey,
            &act(Some(SurfaceClass::Voice), Some(EvidenceLevel::Presence)),
        );
        assert_eq!(voice.get(SURFACE), Some(&0));
        assert_eq!(voice.get("phishing_resistant"), Some(&0));
        assert_eq!(voice.get("uv"), Some(&0));
        assert_eq!(voice.get("aal"), Some(&2));
        let phone = contribution_assurance(
            &passkey,
            &act(
                Some(SurfaceClass::Phone),
                Some(EvidenceLevel::PhishingResistant),
            ),
        );
        assert_eq!(phone.get(SURFACE), Some(&2));
        assert_eq!(phone.get("phishing_resistant"), Some(&1));
        let undeclared = contribution_assurance(&passkey, &act(None, None));
        assert_eq!(undeclared.get(SURFACE), None);
        assert_eq!(undeclared.get("phishing_resistant"), Some(&1));
    }

    fn proof(kind: ProofKind, class: &str, party: u8, instance: u8) -> Proof {
        Proof {
            id: Id([party ^ instance ^ 0x40; 16]),
            kind,
            class: class.to_owned(),
            position: 1,
            time: 0,
            party: Id([party; 16]),
            instance: Id([instance; 16]),
            issuer: Id([9; 16]),
            binding: ProofBinding::default(),
            assurance: BTreeMap::new(),
            consumed: false,
        }
    }

    const AGENT: Actor = Actor {
        instance: Id([0xa1; 16]),
        party: Id([0xa0; 16]),
    };

    // AGI-8, AGI-4, A-5, EI-18, Ek B 4121, 4550
    #[test]
    fn an_agent_meets_no_human_term_and_approves_nothing_of_its_own() {
        let view = Snapshot::default();
        let own_party = proof(ProofKind::Contribution, "approve", 0xa0, 0x77);
        let own_instance = proof(ProofKind::Contribution, "approve", 0x55, 0xa1);
        let user = proof(ProofKind::Contribution, "approve", 0x10, 0x11);
        let mut presence = proof(ProofKind::Authentication, "presence", 0xa0, 0xa1);
        presence.assurance.insert(HUMAN_PRESENCE.to_owned(), 1);
        presence.id = Id([0x98; 16]);
        let mut session = proof(ProofKind::Claim, "authentication", 0xa0, 0xa2);
        session.binding.actor_instance = Some(AGENT.instance);
        let mut hardware = session.clone();
        hardware.id = Id([0x99; 16]);
        hardware.assurance.insert("hardware_bound".to_owned(), 1);
        let mut runtime = proof(ProofKind::Claim, "attestation_runtime", 0xa0, 0xa3);
        runtime.binding.actor_instance = Some(AGENT.instance);
        let all = vec![
            own_party,
            own_instance,
            user.clone(),
            presence,
            session.clone(),
            hardware.clone(),
        ];
        let ids = |ps: Vec<Proof>| ps.into_iter().map(|p| p.id).collect::<Vec<_>>();
        assert_eq!(
            ids(admissible(&all, Some(&AGENT), false, Tier::Ct2, &view)),
            ids(all.clone())
        );
        assert_eq!(
            ids(admissible(&all, Some(&AGENT), true, Tier::Ct1, &view)),
            ids(vec![user.clone(), session, hardware.clone()])
        );
        assert_eq!(
            ids(admissible(&all, Some(&AGENT), true, Tier::Ct2, &view)),
            ids(vec![user.clone()])
        );
        let mut attested = all;
        attested.push(runtime.clone());
        assert_eq!(
            ids(admissible(&attested, Some(&AGENT), true, Tier::Ct3, &view)),
            ids(vec![user, hardware, runtime])
        );
    }
}
