extern crate std;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};

use super::*;
use crate::model::*;

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn s(x: &str) -> String {
    x.to_string()
}

fn action(ns: &str, name: &str) -> ActionRef {
    ActionRef {
        namespace: s(ns),
        name: s(name),
        major: 1,
        schema: d(9),
    }
}

fn rref(ns: &str, path: &[&str]) -> ResourceRef {
    ResourceRef {
        namespace: s(ns),
        path: path.iter().map(|p| s(p)).collect(),
        incarnation: 0,
    }
}

fn structural(
    ns: &str,
    prefix: &[&str],
    kind: Option<&str>,
    attrs: &[(&str, i64)],
) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: s(ns),
        prefix: prefix.iter().map(|p| s(p)).collect(),
        kind: kind.map(s),
        attrs: attrs
            .iter()
            .map(|(k, v)| (s(k), EqValue::Int(*v)))
            .collect(),
    })
}

fn range(min: Option<i64>, max: Option<i64>, unit: &str) -> Bound {
    Bound::Range {
        min,
        max,
        unit: s(unit),
    }
}

fn set(actions: &[ActionRef]) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: actions.iter().cloned().collect(),
            prefix: BTreeSet::new(),
        },
        resource: structural("shop", &[], None, &[]),
        params: BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

fn catalog() -> Catalog {
    let mut c = Catalog::default();
    c.catalogs.insert(
        d(1),
        [
            action("pay", "refund"),
            action("pay", "charge"),
            action("pay.admin", "close"),
            action("payroll", "run"),
        ]
        .into_iter()
        .collect(),
    );
    c.reserved.insert(action("pay.admin", "close"));
    let code = |x: &str| PurposeRef::Code(s(x));
    c.purposes.insert(
        code("support"),
        [code("complaint"), code("refund-check")]
            .into_iter()
            .collect(),
    );
    c.purposes.insert(
        code("complaint"),
        [code("complaint-escalation")].into_iter().collect(),
    );
    c
}

// OP-109 m.9: range
#[test]
fn range_rules() {
    let cat = Catalog::default();
    assert!(bound_le(
        &range(Some(0), Some(100), "try"),
        &range(None, Some(500), "try"),
        &cat
    ));
    assert!(!bound_le(
        &range(Some(0), Some(600), "try"),
        &range(None, Some(500), "try"),
        &cat
    ));
    assert!(!bound_le(
        &range(None, Some(100), "try"),
        &range(Some(0), Some(500), "try"),
        &cat
    ));
    assert!(!bound_le(
        &range(Some(0), Some(100), "eur"),
        &range(None, Some(500), "try"),
        &cat
    ));
    assert_eq!(
        bound_meet(
            &range(None, Some(100), "try"),
            &range(Some(200), None, "try"),
            &cat
        ),
        None
    );
    assert_eq!(
        bound_meet(
            &range(None, Some(100), "try"),
            &range(Some(50), None, "try"),
            &cat
        ),
        Some(range(Some(50), Some(100), "try"))
    );
    assert_eq!(
        bound_meet(
            &range(None, Some(1), "try"),
            &range(None, Some(1), "eur"),
            &cat
        ),
        None
    );
    assert_eq!(
        bound_normalize(&range(Some(2), Some(1), "try"), &cat),
        Ok(None)
    );
}

// OP-109 m.9: enum, eq, flag, count, interval; different types never compare
#[test]
fn simple_type_rules() {
    let cat = Catalog::default();
    let e = |xs: &[&str]| Bound::Enum(xs.iter().map(|x| s(x)).collect());
    assert!(bound_le(&e(&["late"]), &e(&["late", "damaged"]), &cat));
    assert!(!bound_le(&e(&["lost"]), &e(&["late", "damaged"]), &cat));
    assert_eq!(bound_meet(&e(&["a"]), &e(&["b"]), &cat), None);
    assert_eq!(
        bound_normalize(&Bound::Enum(BTreeSet::new()), &cat),
        Err(InputError::Empty)
    );
    assert!(bound_le(&Bound::CountMax(2), &Bound::CountMax(3), &cat));
    assert_eq!(
        bound_meet(&Bound::CountMax(2), &Bound::CountMax(3), &cat),
        Some(Bound::CountMax(2))
    );
    assert_eq!(
        bound_meet(&Bound::Flag(true), &Bound::Flag(false), &cat),
        None
    );
    let w = |a, b| Bound::Interval(Window { from: a, until: b });
    assert!(bound_le(&w(5, 6), &w(1, 10), &cat));
    assert!(!bound_le(&w(0, 6), &w(1, 10), &cat));
    assert_eq!(bound_meet(&w(1, 5), &w(6, 9), &cat), None);
    assert_eq!(bound_meet(&w(1, 5), &w(5, 9), &cat), Some(w(5, 5)));
    assert_eq!(bound_normalize(&w(2, 1), &cat), Err(InputError::Window));
    assert!(!bound_le(
        &Bound::CountMax(1),
        &range(None, Some(1), "count"),
        &cat
    ));
    assert_eq!(
        bound_meet(&Bound::Flag(true), &Bound::Eq(EqValue::Bool(true)), &cat),
        None
    );
}

// OP-109 m.9: resource selectors
#[test]
fn resource_rules() {
    let order = ResourceSelector::Exact(rref("shop", &["orders", "o1"]));
    assert!(resource_le(
        &order,
        &structural("shop", &["orders"], None, &[])
    ));
    assert!(!resource_le(
        &order,
        &structural("shop", &["orders"], Some("order"), &[])
    ));
    assert!(!resource_le(
        &order,
        &structural("shop", &["order"], None, &[])
    ));
    assert!(!resource_le(
        &ResourceSelector::Exact(rref("shop", &["ordersx"])),
        &structural("shop", &["orders"], None, &[])
    ));
    assert!(!resource_le(
        &structural("shop", &["orders"], None, &[]),
        &order
    ));
    assert!(resource_le(
        &structural("shop", &["orders", "eu"], Some("order"), &[("tier", 1)]),
        &structural("shop", &["orders"], None, &[("tier", 1)])
    ));
    assert_eq!(
        resource_meet(
            &structural("shop", &["orders"], None, &[("a", 1)]),
            &structural("shop", &["orders", "eu"], Some("order"), &[])
        ),
        Some(structural(
            "shop",
            &["orders", "eu"],
            Some("order"),
            &[("a", 1)]
        ))
    );
    assert_eq!(
        resource_meet(
            &structural("shop", &["orders"], None, &[("a", 1)]),
            &structural("shop", &[], None, &[("a", 2)])
        ),
        None
    );
    assert_eq!(
        resource_meet(
            &structural("shop", &["a"], None, &[]),
            &structural("shop", &["b"], None, &[])
        ),
        None
    );
    assert_eq!(
        resource_meet(&order, &structural("shop", &[], None, &[])),
        Some(order.clone())
    );
}

// OP-109 m.9: subject selectors
#[test]
fn subject_rules() {
    let alice = SubjectSelector::Party(Id([1; 16]));
    let bob = SubjectSelector::Party(Id([2; 16]));
    let pred = |xs: &[&str]| {
        SubjectSelector::Pred(
            xs.iter()
                .map(|x| Conjunct {
                    claim_class: s(x),
                    value: None,
                })
                .collect(),
        )
    };
    assert!(subject_le(&alice, &SubjectSelector::Public));
    assert!(!subject_le(&alice, &bob));
    assert!(subject_le(&pred(&["employee", "eu"]), &pred(&["employee"])));
    assert!(!subject_le(
        &pred(&["employee"]),
        &pred(&["employee", "eu"])
    ));
    assert!(!subject_le(&alice, &pred(&["employee"])));
    assert_eq!(subject_meet(&alice, &bob), None);
    assert_eq!(
        subject_meet(&pred(&["a"]), &pred(&["b"])),
        Some(pred(&["a", "b"]))
    );
    assert_eq!(
        subject_meet(&alice, &SubjectSelector::Public),
        Some(alice.clone())
    );
}

// OP-107 m.15, OP-109 m.9: purposes
#[test]
fn purpose_rules() {
    let cat = catalog();
    let code = |x: &str| PurposeRef::Code(s(x));
    let p = |xs: &[&str]| xs.iter().map(|x| code(x)).collect::<BTreeSet<_>>();
    assert!(purpose_le(
        &p(&["complaint-escalation"]),
        &p(&["support"]),
        &cat
    ));
    assert!(!purpose_le(&p(&["support"]), &p(&["complaint"]), &cat));
    assert_eq!(
        purpose_normalize(&p(&["support", "complaint"]), &cat),
        p(&["support"])
    );
    assert_eq!(
        purpose_meet(&p(&["support"]), &p(&["complaint"]), &cat),
        Some(p(&["complaint"]))
    );
    assert_eq!(
        purpose_meet(&p(&["complaint"]), &p(&["refund-check"]), &cat),
        None
    );
    assert_eq!(cat.check(), Ok(()));
    let mut cyclic = cat.clone();
    cyclic
        .purposes
        .insert(code("complaint-escalation"), p(&["support"]));
    assert_eq!(cyclic.check(), Err(InputError::PurposeCycle));
}

// OP-107 m.2, m.3: prefixes resolve in the pinned catalog and never cover reserved actions
#[test]
fn action_prefix_rules() {
    let cat = catalog();
    let mut parent = set(&[]);
    parent.actions.prefix.insert((s("pay"), d(1)));
    assert!(subsumes(&set(&[action("pay", "refund")]), &parent, &cat));
    assert!(!subsumes(
        &set(&[action("pay.admin", "close")]),
        &parent,
        &cat
    ));
    assert!(!subsumes(&set(&[action("payroll", "run")]), &parent, &cat));
    assert!(!subsumes(&set(&[action("pay", "new")]), &parent, &cat));
    let mut unknown = set(&[]);
    unknown.actions.prefix.insert((s("pay"), d(2)));
    assert!(!subsumes(&set(&[action("pay", "refund")]), &unknown, &cat));
    assert_eq!(normalize(&set(&[]), &cat), Ok(None));
}

// OP-109 m.10: parameters, recipient, purpose
#[test]
fn authority_set_rules() {
    let cat = catalog();
    let mut p = set(&[action("pay", "refund")]);
    p.params.insert(s("amount"), range(None, Some(500), "try"));
    let mut c = p.clone();
    assert!(subsumes(&c, &p, &cat));
    c.params.insert(s("amount"), range(None, Some(100), "try"));
    c.params
        .insert(s("reason"), Bound::Enum([s("late")].into_iter().collect()));
    assert!(subsumes(&c, &p, &cat));
    c.params.remove("amount");
    assert!(!subsumes(&c, &p, &cat));
    let mut r = set(&[action("pay", "refund")]);
    r.recipient = Some(SubjectSelector::Party(Id([1; 16])));
    assert!(!subsumes(&set(&[action("pay", "refund")]), &r, &cat));
    assert!(subsumes(&r, &set(&[action("pay", "refund")]), &cat));
}

fn grant(depth: u64, class: Option<SubjectSelector>) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: set(&[action("pay", "refund")]),
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: 100,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms {
            depth,
            downstream_holder_class: class,
        },
        requirements: BTreeSet::new(),
    }
}

// OP-107 m.16–m.18, m.20, OP-109 m.11
#[test]
fn child_within_parent_rules() {
    let cat = catalog();
    let staff = SubjectSelector::Pred(
        [Conjunct {
            claim_class: s("staff"),
            value: None,
        }]
        .into_iter()
        .collect(),
    );
    let alice = SubjectSelector::Party(Id([1; 16]));
    let parent = grant(2, Some(staff.clone()));
    let staff_alice = SubjectSelector::Pred(
        [
            Conjunct {
                claim_class: s("staff"),
                value: None,
            },
            Conjunct {
                claim_class: s("eu"),
                value: None,
            },
        ]
        .into_iter()
        .collect(),
    );
    assert!(child_within_parent(
        &grant(1, Some(staff.clone())),
        &parent,
        &staff_alice,
        &cat
    ));
    assert!(!child_within_parent(
        &grant(2, Some(staff.clone())),
        &parent,
        &staff_alice,
        &cat
    ));
    assert!(!child_within_parent(
        &grant(0, None),
        &grant(0, None),
        &alice,
        &cat
    ));
    assert!(!child_within_parent(&grant(0, None), &parent, &alice, &cat));
    assert!(!child_within_parent(
        &grant(1, None),
        &parent,
        &staff_alice,
        &cat
    ));
    assert!(!child_within_parent(
        &grant(1, Some(SubjectSelector::Public)),
        &grant(2, None),
        &alice,
        &cat
    ));
    assert!(!child_within_parent(
        &grant(1, None),
        &grant(2, None),
        &SubjectSelector::Public,
        &cat
    ));
    assert!(child_within_parent(
        &grant(0, None),
        &grant(2, None),
        &SubjectSelector::Public,
        &cat
    ));
    assert!(!child_within_parent(
        &grant(0, None),
        &grant(2, Some(SubjectSelector::Public)),
        &alice,
        &cat
    ));
}

// OP-109 m.11: validity and requirements
#[test]
fn child_within_parent_validity_and_requirements() {
    let cat = catalog();
    let alice = SubjectSelector::Party(Id([1; 16]));
    let mut longer = grant(0, None);
    longer.constraints.validity.until = 101;
    assert!(!child_within_parent(&longer, &grant(1, None), &alice, &cat));

    let term = RequirementTerm {
        proof_kind: ProofKind::Authentication,
        class: s("phishing_resistant"),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: Some(300_000),
        independence: Independence::None,
        consumption: Consumption::SingleUse,
        source: None,
        assurance: BTreeMap::new(),
    };
    let mut strict_parent = grant(1, None);
    strict_parent.requirements.insert(term.clone());
    assert!(!child_within_parent(
        &grant(0, None),
        &strict_parent,
        &alice,
        &cat
    ));
    let mut strict_child = grant(0, None);
    strict_child.requirements.insert(term);
    assert!(child_within_parent(
        &strict_child,
        &strict_parent,
        &alice,
        &cat
    ));
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    fn bound() -> impl Strategy<Value = Bound> {
        let opt = || proptest::option::of(-3_i64..3);
        prop_oneof![
            proptest::collection::btree_set(
                prop_oneof![Just(s("a")), Just(s("b")), Just(s("c"))],
                1..3
            )
            .prop_map(Bound::Enum),
            (opt(), opt(), prop_oneof![Just(s("try")), Just(s("eur"))])
                .prop_map(|(min, max, unit)| Bound::Range { min, max, unit }),
            (0_u64..4).prop_map(Bound::CountMax),
            (0_u64..4, 0_u64..4).prop_map(|(a, b)| Bound::Interval(Window {
                from: a.min(b),
                until: a.max(b)
            })),
            any::<bool>().prop_map(Bound::Flag),
            resource().prop_map(Bound::Resource),
            subject().prop_map(Bound::Subject),
            proptest::collection::btree_set(purpose(), 1..3).prop_map(Bound::Purpose),
        ]
    }

    fn purpose() -> impl Strategy<Value = PurposeRef> {
        prop_oneof![
            Just(PurposeRef::Code(s("support"))),
            Just(PurposeRef::Code(s("complaint"))),
            Just(PurposeRef::Code(s("refund-check"))),
            Just(PurposeRef::Code(s("complaint-escalation"))),
            Just(PurposeRef::Work(d(3))),
        ]
    }

    fn resource() -> impl Strategy<Value = ResourceSelector> {
        let seg = || prop_oneof![Just(s("o")), Just(s("eu"))];
        prop_oneof![
            proptest::collection::vec(seg(), 0..3).prop_map(|p| ResourceSelector::Exact(
                ResourceRef {
                    namespace: s("shop"),
                    path: p,
                    incarnation: 0
                }
            )),
            (
                proptest::collection::vec(seg(), 0..3),
                proptest::option::of(prop_oneof![Just(s("order")), Just(s("cart"))]),
                proptest::collection::btree_map(
                    prop_oneof![Just(s("t")), Just(s("r"))],
                    (0_i64..2).prop_map(EqValue::Int),
                    0..2
                ),
            )
                .prop_map(|(prefix, kind, attrs)| ResourceSelector::Structural(
                    Structural {
                        namespace: s("shop"),
                        prefix,
                        kind,
                        attrs
                    }
                )),
        ]
    }

    fn subject() -> impl Strategy<Value = SubjectSelector> {
        prop_oneof![
            (1_u8..3).prop_map(|n| SubjectSelector::Party(Id([n; 16]))),
            proptest::collection::btree_set(
                prop_oneof![Just(s("staff")), Just(s("eu"))].prop_map(|c| Conjunct {
                    claim_class: c,
                    value: None
                }),
                1..3
            )
            .prop_map(SubjectSelector::Pred),
            Just(SubjectSelector::Public),
        ]
    }

    fn authority() -> impl Strategy<Value = AuthoritySet> {
        (
            proptest::collection::btree_set(
                prop_oneof![Just(action("pay", "refund")), Just(action("pay", "charge"))],
                0..3,
            ),
            proptest::bool::ANY,
            resource(),
            proptest::collection::btree_map(prop_oneof![Just(s("x")), Just(s("y"))], bound(), 0..3),
            proptest::option::of(subject()),
            proptest::option::of(proptest::collection::btree_set(purpose(), 1..3)),
        )
            .prop_map(
                |(exact, with_prefix, resource, params, recipient, purpose)| {
                    let mut prefix = BTreeSet::new();
                    if with_prefix {
                        prefix.insert((s("pay"), d(1)));
                    }
                    AuthoritySet {
                        actions: ActionSet { exact, prefix },
                        resource,
                        params,
                        recipient,
                        purpose,
                    }
                },
            )
    }

    fn norm_bound(b: &Bound, cat: &Catalog) -> Option<Bound> {
        bound_normalize(b, cat).unwrap()
    }

    fn norm(a: &AuthoritySet, cat: &Catalog) -> Option<AuthoritySet> {
        normalize(a, cat).unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

        #[test]
        fn bound_le_is_reflexive_and_transitive(a in bound(), b in bound(), c in bound()) {
            let cat = catalog();
            if let (Some(a), Some(b), Some(c)) = (norm_bound(&a, &cat), norm_bound(&b, &cat), norm_bound(&c, &cat)) {
                prop_assert!(bound_le(&a, &a, &cat));
                if bound_le(&a, &b, &cat) && bound_le(&b, &c, &cat) {
                    prop_assert!(bound_le(&a, &c, &cat));
                }
            }
        }

        #[test]
        fn bound_meet_is_the_greatest_lower_bound(a in bound(), b in bound(), x in bound()) {
            let cat = catalog();
            if let (Some(a), Some(b), Some(x)) = (norm_bound(&a, &cat), norm_bound(&b, &cat), norm_bound(&x, &cat)) {
                match bound_meet(&a, &b, &cat) {
                    Some(m) => {
                        prop_assert!(bound_le(&m, &a, &cat));
                        prop_assert!(bound_le(&m, &b, &cat));
                        if bound_le(&x, &a, &cat) && bound_le(&x, &b, &cat) {
                            prop_assert!(bound_le(&x, &m, &cat));
                        }
                        prop_assert_eq!(bound_meet(&b, &a, &cat), Some(m.clone()));
                        prop_assert_eq!(norm_bound(&m, &cat), Some(m));
                    }
                    None => prop_assert!(!(bound_le(&x, &a, &cat) && bound_le(&x, &b, &cat))),
                }
            }
        }

        #[test]
        fn authority_meet_is_the_greatest_lower_bound(a in authority(), b in authority(), x in authority()) {
            let cat = catalog();
            if let (Some(a), Some(b), Some(x)) = (norm(&a, &cat), norm(&b, &cat), norm(&x, &cat)) {
                prop_assert!(subsumes(&a, &a, &cat));
                match meet(&a, &b, &cat) {
                    Some(m) => {
                        prop_assert!(subsumes(&m, &a, &cat));
                        prop_assert!(subsumes(&m, &b, &cat));
                        if subsumes(&x, &a, &cat) && subsumes(&x, &b, &cat) {
                            prop_assert!(subsumes(&x, &m, &cat));
                        }
                        let n = norm(&m, &cat);
                        prop_assert_eq!(n.as_ref().and_then(|n| norm(n, &cat)), n);
                    }
                    None => prop_assert!(!(subsumes(&x, &a, &cat) && subsumes(&x, &b, &cat))),
                }
            }
        }
    }

    fn widen(x: AuthoritySet) -> impl Strategy<Value = AuthoritySet> {
        (
            proptest::collection::btree_set(
                prop_oneof![Just(action("pay", "refund")), Just(action("pay", "charge"))],
                0..3,
            ),
            proptest::bool::ANY,
            proptest::bool::ANY,
            proptest::collection::vec(proptest::bool::ANY, 2),
            0_u8..3,
            proptest::bool::ANY,
        )
            .prop_map(
                move |(extra, add_prefix, whole_namespace, drop, recipient, drop_purpose)| {
                    let mut a = x.clone();
                    a.actions.exact.extend(extra);
                    if add_prefix {
                        a.actions.prefix.insert((s("pay"), d(1)));
                    }
                    if whole_namespace {
                        a.resource = structural("shop", &[], None, &[]);
                    }
                    for (k, dropped) in [s("x"), s("y")].iter().zip(drop) {
                        if dropped {
                            a.params.remove(k);
                        }
                    }
                    match recipient {
                        0 => {}
                        1 => a.recipient = None,
                        _ => a.recipient = Some(SubjectSelector::Public),
                    }
                    if drop_purpose {
                        a.purpose = None;
                    }
                    a
                },
            )
    }

    fn common_lower_bound() -> impl Strategy<Value = (AuthoritySet, AuthoritySet, AuthoritySet)> {
        authority().prop_flat_map(|x| (widen(x.clone()), widen(x.clone()), Just(x)))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

        #[test]
        fn authority_meet_keeps_every_common_lower_bound((a, b, x) in common_lower_bound()) {
            let cat = catalog();
            if let (Some(a), Some(b), Some(x)) = (norm(&a, &cat), norm(&b, &cat), norm(&x, &cat)) {
                prop_assert!(subsumes(&x, &a, &cat) && subsumes(&x, &b, &cat));
                let m = meet(&a, &b, &cat);
                prop_assert!(m.is_some());
                prop_assert!(subsumes(&x, &m.unwrap(), &cat));
            }
        }
    }
}

mod vectors;
