use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec;

use super::*;
use crate::model::{ActionRef, ActionSet, ResourceSelector, Structural};

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn contract(variant: ProfileVariant) -> ValidityContract {
    ValidityContract {
        issuing_exercise: d(1),
        basis_ref: vec![9, 9],
        holder: d(2),
        audience: ["pep:shop".to_string()].into_iter().collect(),
        bounds: AuthoritySet {
            actions: ActionSet {
                exact: [ActionRef {
                    namespace: "pay".to_string(),
                    name: "refund".to_string(),
                    major: 1,
                    schema: d(3),
                }]
                .into_iter()
                .collect(),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: "shop".to_string(),
                prefix: vec![],
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        class: variant.class(),
        variant,
        params: BTreeMap::new(),
        horizon: 10_000,
        max_staleness_ms: (variant == ProfileVariant::BoundedStaleness).then_some(1_000),
        freshness_sources: BTreeSet::new(),
        revalidation: Revalidation::default(),
        offline_slice: BTreeSet::new(),
        local_requirements: BTreeSet::new(),
        verifier_profile_ref: d(4),
        clock_source: "ntp".to_string(),
        clock_skew_ms: 60_000,
        must_understand: BTreeSet::new(),
    }
}

fn ctx(
    now: u64,
    understood: &BTreeSet<String>,
    online: bool,
    last_refresh: Option<u64>,
) -> VerifierContext<'_> {
    VerifierContext {
        now,
        audience: "pep:shop",
        understood,
        last_refresh,
        online,
        skew_ms: 60_000,
    }
}

// OP-117 m.12, m.13: the horizon is closed and the verifier's class skew caps the artefact's
#[test]
fn horizon_is_closed_and_skew_is_the_smaller_one() {
    let vc = contract(ProfileVariant::OnlineStrict);
    let none = BTreeSet::new();
    let edge = vc.horizon + vc.clock_skew_ms;
    assert_eq!(check(&vc, &ctx(edge, &none, true, None)), Ok(()));
    assert_eq!(
        check(&vc, &ctx(edge + 1, &none, true, None)),
        Err(ValidityError::Expired)
    );
    let mut tight = ctx(vc.horizon + 1_000, &none, true, None);
    tight.skew_ms = 999;
    assert_eq!(check(&vc, &tight), Err(ValidityError::Expired));
    tight.skew_ms = 1_000;
    assert_eq!(check(&vc, &tight), Ok(()));
}

#[test]
fn round_trips_and_class_must_match_variant() {
    let mut vc = contract(ProfileVariant::BoundedStaleness);
    vc.revalidation.every_uses = Some(5);
    vc.offline_slice.insert(OfflineSlice {
        budget_term: d(5),
        amount: 3,
        unit: "count".to_string(),
    });
    vc.must_understand.insert("geo".to_string());
    let bytes = vc.to_bytes().unwrap();
    assert_eq!(ValidityContract::from_bytes(&bytes), Ok(vc.clone()));
    vc.class = ProfileClass::Offline;
    assert_eq!(
        ValidityContract::from_bytes(&vc.to_bytes().unwrap()),
        Err(ModelError::Range)
    );
}

// §9.12, OP-108 m.2, PI-12
#[test]
fn use_rules() {
    let none = BTreeSet::new();
    let vc = contract(ProfileVariant::CheckpointedOffline);
    assert_eq!(
        check(&vc, &ctx(10_000 + 60_000, &none, false, None)),
        Ok(())
    );
    assert_eq!(
        check(&vc, &ctx(10_000 + 60_001, &none, false, None)),
        Err(ValidityError::Expired)
    );
    let mut other = ctx(0, &none, false, None);
    other.audience = "pep:bank";
    assert_eq!(check(&vc, &other), Err(ValidityError::Audience));

    let mut mu = vc.clone();
    mu.must_understand.insert("geo".to_string());
    assert_eq!(
        check(&mu, &ctx(0, &none, false, None)),
        Err(ValidityError::MustUnderstand)
    );
    let geo: BTreeSet<String> = ["geo".to_string()].into_iter().collect();
    assert_eq!(check(&mu, &ctx(0, &geo, false, None)), Ok(()));

    let mut overflow = vc.clone();
    overflow.horizon = u64::MAX;
    assert_eq!(
        check(&overflow, &ctx(0, &none, false, None)),
        Err(ValidityError::Overflow)
    );

    let strict = contract(ProfileVariant::OnlineStrict);
    assert_eq!(
        check(&strict, &ctx(0, &none, false, None)),
        Err(ValidityError::OnlineRequired)
    );
    assert_eq!(check(&strict, &ctx(0, &none, true, None)), Ok(()));

    let stale = contract(ProfileVariant::BoundedStaleness);
    assert_eq!(
        check(&stale, &ctx(5_000, &none, false, Some(4_000))),
        Ok(())
    );
    assert_eq!(
        check(&stale, &ctx(5_001, &none, false, Some(4_000))),
        Err(ValidityError::Stale)
    );
    assert_eq!(
        check(&stale, &ctx(5_000, &none, false, None)),
        Err(ValidityError::Stale)
    );
}

#[test]
fn horizon_is_the_earliest_bound() {
    assert_eq!(horizon(100, &[500, 300], 1_000), Ok(300));
    assert_eq!(horizon(100, &[], 1_000), Ok(1_100));
    assert_eq!(horizon(100, &[5_000], 1_000), Ok(1_100));
    assert_eq!(horizon(u64::MAX, &[1], 1), Err(ValidityError::Overflow));
}
