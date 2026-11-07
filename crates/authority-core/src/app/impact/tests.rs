#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;

use super::*;
use access_kernel::model::{Bound, ResourceSelector, Structural};

fn act(name: &str) -> ActionRef {
    ActionRef {
        namespace: "commerce".to_owned(),
        name: name.to_owned(),
        major: 1,
        schema: Digest([1; 32]),
    }
}

fn set(actions: &[&str], max: Option<i64>) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: actions.iter().map(|a| act(a)).collect(),
            prefix: BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: "commerce".to_owned(),
            prefix: Vec::new(),
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: max
            .map(|m| {
                BTreeMap::from([(
                    "amount".to_owned(),
                    Bound::Range {
                        min: None,
                        max: Some(m),
                        unit: "try".to_owned(),
                    },
                )])
            })
            .unwrap_or_default(),
        recipient: None,
        purpose: None,
    }
}

// X20, §8.17.9.2: a new action and a raised limit are gains for every holder; a dropped action
// is a loss
#[test]
fn abilities_name_what_each_holder_gains_and_loses() {
    let old = set(&["read", "refund"], Some(5_000));
    let new = set(&["refund", "void"], Some(10_000));
    let lines = abilities(&old, &new, &Catalog::default(), 41);
    let gained: Vec<&str> = lines
        .iter()
        .filter(|l| l.holders_gaining == 41)
        .map(|l| l.ability.action.name.as_str())
        .collect();
    let lost: Vec<&str> = lines
        .iter()
        .filter(|l| l.holders_losing == 41)
        .map(|l| l.ability.action.name.as_str())
        .collect();
    assert_eq!(gained, ["refund", "void"]);
    assert_eq!(lost, ["read"]);
    let refund = lines
        .iter()
        .find(|l| l.ability.action.name == "refund")
        .unwrap();
    assert_eq!(
        refund.ability.bounds.params.get("amount"),
        Some(&Bound::Range {
            min: None,
            max: Some(10_000),
            unit: "try".to_owned()
        })
    );
    assert_eq!(abilities(&old, &old, &Catalog::default(), 41), []);
}

// C28, §5.8: the closed algebra decides the relation of two versions exactly
#[test]
fn role_versions_relate_by_the_closed_algebra() {
    let cat = Catalog::default();
    let base = set(&["refund"], Some(5_000));
    assert_eq!(relation(&base, &base, &cat), SetRelation::Equivalent);
    assert_eq!(
        relation(&base, &set(&["refund"], Some(1_000)), &cat),
        SetRelation::Narrowing
    );
    assert_eq!(
        relation(&base, &set(&["refund", "void"], Some(5_000)), &cat),
        SetRelation::Widening
    );
    assert_eq!(
        relation(&base, &set(&["void"], Some(5_000)), &cat),
        SetRelation::Incomparable
    );
    assert!(SetRelation::Incomparable.widens() && !SetRelation::Narrowing.widens());
}

// §5.4: the member index prefix of a class is a prefix of every member key of it
#[test]
fn the_member_prefix_covers_every_member_of_its_class() {
    let p = member_class_prefix("finance");
    for (s, c) in [([3; 16], [4; 16]), ([0xff; 16], [0; 16])] {
        assert!(claim::member_key("finance", &Id(s), &Id(c)).starts_with(&p));
    }
    assert!(!claim::member_key("finance2", &Id([3; 16]), &Id([4; 16])).starts_with(&p));
}
