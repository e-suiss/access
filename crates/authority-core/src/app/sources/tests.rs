#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::combinator::Capacity;
use access_kernel::meta::{GrantBasis, GrantContent, key};
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, Conjunct, ConstraintSet, DelegationTerms,
    Structural,
};

use super::*;

const PARTNER: Digest = Digest([7; 32]);

fn action(namespace: &str) -> ActionRef {
    ActionRef {
        namespace: namespace.to_owned(),
        name: "read".to_owned(),
        major: 1,
        schema: Digest([3; 32]),
    }
}

fn grant(holder: SubjectSelector, namespace: &str) -> Value {
    GrantState {
        content: GrantContent {
            basis: GrantBasis::Anchor(Id([0xa0; 16])),
            holder,
            authority: CanonicalAuthority {
                authority: AuthoritySet {
                    actions: ActionSet {
                        exact: BTreeSet::from([action(namespace)]),
                        prefix: BTreeSet::new(),
                    },
                    resource: ResourceSelector::Structural(Structural {
                        namespace: namespace.to_owned(),
                        prefix: Vec::new(),
                        kind: None,
                        attrs: BTreeMap::new(),
                    }),
                    params: BTreeMap::new(),
                    recipient: None,
                    purpose: None,
                },
                constraints: ConstraintSet {
                    validity: Window {
                        from: 0,
                        until: 100,
                    },
                    conditions: BTreeSet::new(),
                    budget: BTreeSet::new(),
                },
                delegation: DelegationTerms::default(),
                requirements: BTreeSet::new(),
            },
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        },
        since: 1,
        revision: 0,
        ended: None,
    }
    .to_value()
}

fn acceptance(issuer: Value, use_: &str, classes: &[&str]) -> Value {
    let content = Value::Map(
        [
            ("issuer", issuer),
            ("use", Value::text(use_)),
            (
                "classes",
                Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
            ),
            (
                "validity",
                Window {
                    from: 0,
                    until: 100,
                }
                .to_value(),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (Value::text(k), v))
        .collect(),
    );
    ContentState {
        content,
        since: 2,
        widened: None,
        ended: None,
    }
    .to_value()
}

fn foreign() -> Value {
    use access_kernel::verify::cose::{Algorithm, PublicKey};
    use access_kernel::verify::key_scope::{BindingKey, BindingScope, thumbprint};
    let key = PublicKey::Ed25519([
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ]);
    let kid = thumbprint(&key);
    let binding = BindingKey {
        kid,
        alg: Algorithm::Ed25519,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    };
    Value::Map(
        [(
            Value::text("foreign"),
            ForeignIssuer {
                domain: PARTNER,
                binding: BTreeMap::from([(kid, binding)]),
            }
            .to_value(),
        )]
        .into_iter()
        .collect(),
    )
}

fn snapshot(acceptances: Vec<(Id, Value)>, grants: Vec<(Id, Value)>) -> Snapshot {
    let mut snap = Snapshot::default();
    let rows = |kind: &str, list: Vec<(Id, Value)>| {
        list.into_iter()
            .map(|(id, v)| (key(kind, &id), Some(v), 1))
            .collect::<Vec<_>>()
    };
    snap.fill_scan(
        prefix(kind::ACCEPTANCE),
        rows(kind::ACCEPTANCE, acceptances),
    );
    snap.fill_scan(prefix(kind::GRANT), rows(kind::GRANT, grants));
    snap
}

// §8.17.9.3, INV-15, §5.13
#[test]
fn partners_carry_their_ceilings_and_sources_their_blast_radius() {
    let hr = Id([0x11; 16]);
    let snap = snapshot(
        vec![
            (Id([1; 16]), acceptance(foreign(), "foreign-authority", &[])),
            (
                Id([2; 16]),
                acceptance(hr.to_value(), "subject-selection", &["employee"]),
            ),
            (
                Id([3; 16]),
                acceptance(hr.to_value(), "predicate-input", &["department"]),
            ),
        ],
        vec![
            (
                Id([0xb1; 16]),
                grant(
                    SubjectSelector::Foreign {
                        domain: PARTNER,
                        class: "buyer".to_owned(),
                    },
                    "shop",
                ),
            ),
            (
                Id([0xb2; 16]),
                grant(
                    SubjectSelector::Pred(BTreeSet::from([Conjunct {
                        claim_class: "employee".to_owned(),
                        value: None,
                    }])),
                    "hr",
                ),
            ),
            (Id([0xb3; 16]), grant(SubjectSelector::Party(hr), "hr")),
        ],
    );
    let out = report(&snap, 10);
    assert_eq!(out.sources.len(), 3);
    let by_use = |u: &str| out.sources.iter().find(|s| s.use_ == u).unwrap();
    assert_eq!(by_use("foreign-authority").issuer, Issuer::Foreign(PARTNER));
    assert_eq!(by_use("foreign-authority").dependents, 1);
    assert!(by_use("foreign-authority").protected);
    assert_eq!(by_use("subject-selection").dependents, 1);
    assert!(by_use("subject-selection").protected);
    assert_eq!(by_use("predicate-input").dependents, 0);
    assert!(!by_use("predicate-input").protected);
    assert_eq!(out.partners.len(), 1);
    let p = &out.partners[0];
    assert_eq!(p.domain, PARTNER);
    assert_eq!(p.acceptances, vec![Id([1; 16])]);
    assert_eq!(p.ceilings.len(), 1);
    assert_eq!(p.ceilings[0].class, "buyer");
    assert_eq!(p.ceilings[0].actions, vec![action("shop")]);
    assert_eq!(p.ceilings[0].until, 100);
}

// §8.17.9.3
#[test]
fn ended_and_expired_acceptances_are_not_listed() {
    let snap = snapshot(
        vec![(
            Id([1; 16]),
            acceptance(Id([9; 16]).to_value(), "predicate-input", &["x"]),
        )],
        Vec::new(),
    );
    assert_eq!(report(&snap, 10).sources.len(), 1);
    assert_eq!(report(&snap, 100).sources, Vec::new());
}
