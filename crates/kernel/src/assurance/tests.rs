use alloc::collections::BTreeMap;
use alloc::string::String;

use super::*;
use crate::digest::Digest;
use crate::model::Id;
use crate::requirement::{Context, Proof, ProofBinding, matches};

fn levels(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(k, v)| (String::from(*k), *v)).collect()
}

fn password() -> BTreeMap<String, u64> {
    levels(&[("aal", 1), ("phishing_resistant", 0), ("human_presence", 0)])
}

fn totp() -> BTreeMap<String, u64> {
    levels(&[("aal", 2), ("phishing_resistant", 0), ("uv", 0)])
}

fn push() -> BTreeMap<String, u64> {
    levels(&[
        ("aal", 2),
        ("app_controlled_factor", 1),
        ("human_presence", 1),
    ])
}

fn passkey(uv: bool, device_bound: bool) -> BTreeMap<String, u64> {
    levels(&[
        ("aal", if uv && device_bound { 3 } else { 2 }),
        ("phishing_resistant", 1),
        ("uv", u64::from(uv)),
        ("hardware_bound", u64::from(device_bound)),
        ("non_custodial", u64::from(device_bound)),
        ("synced", u64::from(!device_bound)),
        ("human_presence", 1),
    ])
}

// §13.7.3, N-45, IDP-8
#[test]
fn password_otp_and_push_alone_satisfy_no_tier() {
    for weak in [password(), totp(), push()] {
        assert_eq!(ceiling(&weak), None);
        for tier in [Tier::Ct0, Tier::Ct1, Tier::Ct2, Tier::Ct3] {
            assert!(!meets(&floors(tier), &weak));
        }
    }
}

// §13.7.3
// MD-11
#[test]
fn passkeys_climb_the_tiers_by_uv_and_binding() {
    assert_eq!(ceiling(&passkey(false, false)), Some(Tier::Ct1));
    assert_eq!(ceiling(&passkey(false, true)), Some(Tier::Ct1));
    assert_eq!(ceiling(&passkey(true, false)), Some(Tier::Ct2));
    assert_eq!(ceiling(&passkey(true, true)), Some(Tier::Ct3));
    assert!(meets(&floors(Tier::Ct0), &passkey(false, false)));
    assert_eq!(floors(Tier::Ct0), floors(Tier::Ct1));
}

// §13.7.3, SI-5
#[test]
fn approval_adds_human_presence_to_every_tier() {
    for tier in [Tier::Ct0, Tier::Ct1, Tier::Ct2, Tier::Ct3] {
        let f = approval_floors(tier);
        assert_eq!(f.get(HUMAN_PRESENCE), Some(&1));
        let mut absent = passkey(true, true);
        absent.insert(String::from(HUMAN_PRESENCE), 0);
        assert!(!meets(&f, &absent));
        assert!(meets(&floors(tier), &absent));
    }
}

// §13.7.3
#[test]
fn freshness_and_aas_ceilings_follow_the_table() {
    assert_eq!(freshness_ceiling(Tier::Ct0), 15 * 60 * 1_000);
    assert_eq!(freshness_ceiling(Tier::Ct1), 15 * 60 * 1_000);
    assert_eq!(freshness_ceiling(Tier::Ct2), 5 * 60 * 1_000);
    assert_eq!(freshness_ceiling(Tier::Ct3), 5 * 60 * 1_000);
    for tier in [Tier::Ct0, Tier::Ct1, Tier::Ct2, Tier::Ct3] {
        assert_eq!(aas_expiry_ceiling(tier), freshness_ceiling(tier));
    }
    let now = 1_000_000_000;
    assert!(fresh(Tier::Ct1, now - 15 * 60 * 1_000, now));
    assert!(!fresh(Tier::Ct1, now - 15 * 60 * 1_000 - 1, now));
    assert!(fresh(Tier::Ct2, now - 5 * 60 * 1_000, now));
    assert!(!fresh(Tier::Ct2, now - 5 * 60 * 1_000 - 1, now));
    assert!(!fresh(Tier::Ct1, now + 1, now));
    assert!(aas_within_ceiling(Tier::Ct1, now, now + 15 * 60 * 1_000));
    assert!(!aas_within_ceiling(Tier::Ct2, now, now + 15 * 60 * 1_000));
    assert!(aas_within_ceiling(Tier::Ct3, now, now + 5 * 60 * 1_000));
    assert!(!aas_within_ceiling(Tier::Ct3, now + 1, now));
}

// §13.7.3
// §8.5, §8.17.5.4, TN-O3, X29
#[test]
fn the_authentication_term_binds_by_tier() {
    let t1 = authentication_term(Tier::Ct1, false);
    assert_eq!(t1.proof_kind, ProofKind::Claim);
    assert_eq!(t1.class, "authentication");
    assert_eq!(t1.binding, Binding::ActorInstance);
    assert_eq!(t1.freshness_ms, Some(CT1_FRESHNESS_MS));
    assert_eq!(t1.assurance, floors(Tier::Ct1));
    assert_eq!(t1.count, 1);
    assert_eq!(t1.consumption, Consumption::Reusable);
    assert_eq!(
        authentication_term(Tier::Ct0, false).binding,
        Binding::ActorInstance
    );
    for tier in [Tier::Ct2, Tier::Ct3] {
        let t = authentication_term(tier, true);
        assert_eq!(t.binding, Binding::IntentDigest);
        assert_eq!(t.freshness_ms, Some(CT2_FRESHNESS_MS));
        assert_eq!(t.assurance, approval_floors(tier));
    }
}

// §13.7.3, OP-111 m.4
#[test]
fn the_term_is_met_by_a_fresh_bound_claim_of_the_class() {
    let now = 1_700_000_000_000;
    let statement = Digest([7; 32]);
    let proof = |time: u64, assurance: BTreeMap<String, u64>| Proof {
        id: Id([1; 16]),
        kind: ProofKind::Claim,
        class: String::from("authentication"),
        position: 1,
        time,
        party: Id([2; 16]),
        instance: Id([3; 16]),
        issuer: Id([4; 16]),
        binding: ProofBinding {
            actor_instance: None,
            intent_digest: Some(statement),
            resource: None,
        },
        assurance,
        consumed: false,
    };
    let ctx = Context {
        now,
        actor_instance: Some(Id([3; 16])),
        actor_party: None,
        intent_digest: &statement,
        resources: &[],
    };
    let term = authentication_term(Tier::Ct2, true);
    assert!(matches(
        &term,
        &proof(now - 60_000, passkey(true, false)),
        &ctx
    ));
    assert!(!matches(
        &term,
        &proof(now - CT2_FRESHNESS_MS - 1, passkey(true, false)),
        &ctx
    ));
    assert!(!matches(
        &term,
        &proof(now - 60_000, passkey(false, false)),
        &ctx
    ));
    assert!(!matches(&term, &proof(now - 60_000, totp()), &ctx));
    let other = Digest([8; 32]);
    let elsewhere = Context {
        intent_digest: &other,
        ..ctx
    };
    assert!(!matches(
        &term,
        &proof(now - 60_000, passkey(true, false)),
        &elsewhere
    ));
}

// SEC18, §13.7.7, §8.13
#[test]
fn a_new_binding_cools_for_a_day_before_ct2() {
    let bound = 1_700_000_000_000;
    assert_eq!(
        cooled(Tier::Ct2, bound, bound + COOLING_MS - 1),
        Err(bound + COOLING_MS)
    );
    assert_eq!(cooled(Tier::Ct3, bound, bound), Err(bound + COOLING_MS));
    assert_eq!(cooled(Tier::Ct2, bound, bound + COOLING_MS), Ok(()));
    assert_eq!(cooled(Tier::Ct1, bound, bound), Ok(()));
    assert_eq!(cooled(Tier::Ct0, bound, bound), Ok(()));
    assert_eq!(COOLING_MS, 24 * 3_600 * 1_000);
}
