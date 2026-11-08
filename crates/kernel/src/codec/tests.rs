use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::ToString;
use alloc::vec;

use super::*;

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn action() -> ActionRef {
    ActionRef {
        namespace: "pay".to_string(),
        name: "refund".to_string(),
        major: 1,
        schema: d(9),
    }
}

fn sample() -> CanonicalAuthority {
    let mut params = BTreeMap::new();
    params.insert(
        "amount".to_string(),
        Bound::Range {
            min: None,
            max: Some(50_000),
            unit: "try".to_string(),
        },
    );
    params.insert(
        "reason".to_string(),
        Bound::Enum(
            ["late".to_string(), "damaged".to_string()]
                .into_iter()
                .collect(),
        ),
    );
    params.insert(
        "order".to_string(),
        Bound::Resource(ResourceSelector::Structural(Structural {
            namespace: "shop".to_string(),
            prefix: vec!["orders".to_string()],
            kind: Some("order".to_string()),
            attrs: [("region".to_string(), EqValue::Text("eu".to_string()))]
                .into_iter()
                .collect(),
        })),
    );
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: [action()].into_iter().collect(),
                prefix: [("pay".to_string(), d(1))].into_iter().collect(),
            },
            resource: ResourceSelector::Exact(ResourceRef {
                namespace: "shop".to_string(),
                path: vec!["m1".to_string()],
                incarnation: 3,
            }),
            params,
            recipient: Some(SubjectSelector::Pred(
                [Conjunct {
                    claim_class: "customer".to_string(),
                    value: Some(EqValue::Bool(true)),
                }]
                .into_iter()
                .collect(),
            )),
            purpose: Some(
                [
                    PurposeRef::Code("complaint".to_string()),
                    PurposeRef::Work(d(4)),
                ]
                .into_iter()
                .collect(),
            ),
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 1_000,
                until: 2_000,
            },
            conditions: [WhileCondition::InstanceAlive(Id([5; 16]))]
                .into_iter()
                .collect(),
            budget: [BudgetTerm {
                dimension: BudgetDimension::Amount("try".to_string()),
                capacity: 100_000,
                window: BudgetWindow::RollingSeconds(86_400),
            }]
            .into_iter()
            .collect(),
        },
        delegation: DelegationTerms {
            depth: 2,
            downstream_holder_class: Some(SubjectSelector::Party(Id([6; 16]))),
        },
        requirements: [RequirementTerm {
            proof_kind: ProofKind::Authentication,
            class: "phishing_resistant".to_string(),
            count: 1,
            binding: Binding::IntentDigest,
            freshness_ms: Some(300_000),
            independence: Independence::None,
            consumption: Consumption::SingleUse,
            source: None,
            assurance: BTreeMap::new(),
        }]
        .into_iter()
        .collect(),
    }
}

// OP-106 m.1, m.4
#[test]
fn canonical_authority_round_trips() {
    let a = sample();
    let bytes = a.to_bytes().unwrap();
    assert_eq!(CanonicalAuthority::from_bytes(&bytes), Ok(a.clone()));
    assert_eq!(
        CanonicalAuthority::from_bytes(&bytes)
            .unwrap()
            .to_bytes()
            .unwrap(),
        bytes
    );
    let empty = CanonicalAuthority {
        delegation: DelegationTerms::default(),
        requirements: BTreeSet::new(),
        ..a
    };
    assert_eq!(
        CanonicalAuthority::from_bytes(&empty.to_bytes().unwrap()),
        Ok(empty)
    );
}

fn with(v: &Value, key: &str, val: Value) -> Value {
    let Value::Map(mut entries) = v.clone() else {
        panic!()
    };
    entries.retain(|(k, _)| *k != Value::text(key));
    entries.push((Value::text(key), val));
    Value::Map(entries)
}

// OP-108 m.4, OP-109 m.4
#[test]
fn unknown_fields_and_written_defaults_are_rejected() {
    let a = sample();
    let v = a.delegation.to_value();
    assert_eq!(
        DelegationTerms::from_value(&with(&v, "depth", Value::Unsigned(0))),
        Err(ModelError::Range)
    );
    assert_eq!(
        DelegationTerms::from_value(&with(&v, "delegable", Value::Bool(true))),
        Err(ModelError::Unknown)
    );

    let term = a.requirements.iter().next().unwrap().to_value();
    assert_eq!(
        RequirementTerm::from_value(&with(&term, "count", Value::Unsigned(1))),
        Err(ModelError::Range)
    );
    assert_eq!(
        RequirementTerm::from_value(&with(&term, "binding", Value::text("none"))),
        Err(ModelError::Range)
    );
    assert_eq!(
        RequirementTerm::from_value(&with(&term, "consumption", Value::text("reusable"))),
        Err(ModelError::Range)
    );
    assert_eq!(
        RequirementTerm::from_value(&with(&term, "proof_kind", Value::text("vibe"))),
        Err(ModelError::Unknown)
    );

    let set = a.authority.to_value();
    assert_eq!(
        AuthoritySet::from_value(&with(&set, "negation", Value::Bool(true))),
        Err(ModelError::Unknown)
    );
    assert_eq!(
        AuthoritySet::from_value(&with(&set, "params", Value::Map(vec![]))),
        Err(ModelError::Range)
    );
}

// OP-109 m.10: sets are sorted by encoded bytes, without repeats
#[test]
fn sets_must_be_canonical() {
    let b = Value::Map(vec![(
        Value::text("enum"),
        Value::Array(vec![Value::text("b"), Value::text("a")]),
    )]);
    assert_eq!(Bound::from_value(&b), Err(ModelError::SetOrder));
    let b = Value::Map(vec![(
        Value::text("enum"),
        Value::Array(vec![Value::text("a"), Value::text("a")]),
    )]);
    assert_eq!(Bound::from_value(&b), Err(ModelError::SetOrder));
    let b = Value::Map(vec![(
        Value::text("enum"),
        Value::Array(vec![Value::text("b"), Value::text("aa")]),
    )]);
    assert!(Bound::from_value(&b).is_ok());
    let b = Value::Map(vec![(Value::text("enum"), Value::Array(vec![]))]);
    assert_eq!(Bound::from_value(&b), Err(ModelError::Range));
}

// OP-106 m.16, m.20, OP-109 m.6
#[test]
fn primitive_shapes_are_checked() {
    assert_eq!(
        Window::from_value(&Value::Array(vec![Value::Unsigned(2), Value::Unsigned(1)])),
        Err(ModelError::Range)
    );
    assert_eq!(
        Id::from_value(&Value::Bytes(vec![0; 15])),
        Err(ModelError::Range)
    );
    assert_eq!(
        <Digest as Canonical>::from_value(&Value::Bytes(vec![0; 32])),
        Err(ModelError::Shape)
    );
    let bad_ns = with(&action().to_value(), "namespace", Value::text("Pay"));
    assert_eq!(ActionRef::from_value(&bad_ns), Err(ModelError::Range));
    let bad_ns = with(&action().to_value(), "namespace", Value::text("pay..x"));
    assert_eq!(ActionRef::from_value(&bad_ns), Err(ModelError::Range));
    let ok_ns = with(
        &action().to_value(),
        "namespace",
        Value::text("pay.admin-tools"),
    );
    assert!(ActionRef::from_value(&ok_ns).is_ok());
    assert_eq!(
        SubjectSelector::from_value(&Value::text("everyone")),
        Err(ModelError::Shape)
    );
}

fn golden() -> alloc::vec::Vec<(&'static str, alloc::vec::Vec<u8>)> {
    let a = sample();
    let minimal = CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: [action()].into_iter().collect(),
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
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms::default(),
        requirements: BTreeSet::new(),
    };
    vec![
        ("canonical_authority.full", a.to_bytes().unwrap()),
        ("canonical_authority.minimal", minimal.to_bytes().unwrap()),
        (
            "bound.range.negative",
            Bound::Range {
                min: Some(-40),
                max: Some(i64::MAX),
                unit: "celsius".to_string(),
            }
            .to_bytes()
            .unwrap(),
        ),
        (
            "subject.public",
            SubjectSelector::Public.to_bytes().unwrap(),
        ),
        ("digest", d(0xab).to_bytes().unwrap()),
    ]
}

// OP-56, OP-106 m.23, m.24
#[test]
fn golden_vectors_match() {
    extern crate std;
    use core::fmt::Write as _;
    use std::string::String;
    let mut json = String::from(
        "{\n \"rule\": \"OP-106 m.1, m.4, OP-109 m.10\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"codec.encode\",\n \"cases\": [\n",
    );
    let cases = golden();
    for (i, (name, bytes)) in cases.iter().enumerate() {
        let hex = bytes.iter().fold(String::new(), |mut h, b| {
            let _ = write!(h, "{b:02x}");
            h
        });
        let sep = if i + 1 == cases.len() { "" } else { "," };
        // TI-RT12
        let rules = crate::vector_rules::field(match *name {
            "canonical_authority.full" => &["L0-ENC-1", "L0-ENC-4", "L0-ENC-6"],
            "canonical_authority.minimal" => &["L0-ENC-1", "L0-ENC-4", "L0-ENC-5"],
            "bound.range.negative" => &["L0-ENC-1", "L0-ENC-7"],
            "digest" => &["L0-ENC-1", "L0-ENC-20", "L0-ENC-21"],
            _ => &["L0-ENC-1"],
        });
        let _ = writeln!(
            json,
            "  {{\"id\": \"{name}\", {rules}, \"cbor\": \"{hex}\"}}{sep}"
        );
    }
    json.push_str(" ]\n}\n");
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/core/1/codec.json"
        );
        std::fs::write(path, &json).unwrap();
        return;
    }
    assert_eq!(
        include_str!("../../../../conformance/vectors/core/1/codec.json"),
        json,
        "run with ACCESS_UPDATE_VECTORS=1 and review the diff"
    );
}

// OP-108 m.4: stored values with unknown parts are read as not understood
#[test]
fn stored_values_with_unknown_parts_are_not_understood() {
    let a = sample();
    let bytes = a.to_bytes().unwrap();
    assert_eq!(
        decode_stored::<CanonicalAuthority>(&bytes),
        Ok(Stored::Known(a.clone()))
    );
    let newer = with(&a.to_value(), "geo_fence", Value::Bool(true));
    let newer = suiss_crypto::dcbor::encode(&newer, Limits::CEILING).unwrap();
    assert_eq!(
        decode_stored::<CanonicalAuthority>(&newer),
        Ok(Stored::NotUnderstood)
    );
    assert_eq!(
        CanonicalAuthority::from_bytes(&newer),
        Err(ModelError::Unknown)
    );
    let mut non_canonical = bytes.clone();
    non_canonical.push(0);
    assert!(matches!(
        decode_stored::<CanonicalAuthority>(&non_canonical),
        Err(ModelError::Cbor(_))
    ));
}

// OP-106 m.1, m.4: every variant decodes back to itself
#[test]
fn remaining_variants_round_trip() {
    for p in [PurposeRef::Aim(d(7)), PurposeRef::Work(d(8))] {
        assert_eq!(PurposeRef::from_value(&p.to_value()), Ok(p));
    }
    let bytes = EqValue::Bytes(vec![1, 2, 3]);
    assert_eq!(EqValue::from_value(&bytes.to_value()), Ok(bytes));
    let held = WhileCondition::ClaimHeld {
        class: "employee".to_string(),
        subject: SubjectSelector::Party(Id([2; 16])),
        acceptance: d(3),
    };
    assert_eq!(WhileCondition::from_value(&held.to_value()), Ok(held));
    let term = BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 5,
        window: BudgetWindow::Total,
    };
    assert_eq!(BudgetTerm::from_value(&term.to_value()), Ok(term));
}

// OP-108 m.4: a word from another field is not a budget dimension or window
#[test]
fn budget_words_are_field_specific() {
    let term = BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 5,
        window: BudgetWindow::Total,
    }
    .to_value();
    assert_eq!(
        BudgetTerm::from_value(&with(&term, "dimension", Value::text("total"))),
        Err(ModelError::Shape)
    );
    assert_eq!(
        BudgetTerm::from_value(&with(&term, "window", Value::text("count"))),
        Err(ModelError::Shape)
    );
}

// OP-109 m.4: the default independence written out is rejected; other words are malformed
#[test]
fn written_default_independence_is_rejected() {
    let a = sample();
    let mut term = a.requirements.iter().next().unwrap().clone();
    term.count = 2;
    term.independence = Independence::DistinctParty;
    let v = term.to_value();
    assert_eq!(RequirementTerm::from_value(&v), Ok(term));
    assert_eq!(
        RequirementTerm::from_value(&with(&v, "independence", Value::text("none"))),
        Err(ModelError::Range)
    );
    assert_eq!(
        RequirementTerm::from_value(&with(&v, "independence", Value::text("party"))),
        Err(ModelError::Shape)
    );
}

// L0-ENC-13
#[test]
fn selector_condition_limit_is_inclusive() {
    let selector = |n: usize| {
        ResourceSelector::Structural(Structural {
            namespace: "shop".to_string(),
            prefix: vec![],
            kind: None,
            attrs: (0..n)
                .map(|i| (alloc::format!("a{i:02}"), EqValue::Int(1)))
                .collect(),
        })
    };
    let max = selector(MAX_SELECTOR_CONDITIONS);
    assert_eq!(ResourceSelector::from_value(&max.to_value()), Ok(max));
    assert_eq!(
        ResourceSelector::from_value(&selector(MAX_SELECTOR_CONDITIONS + 1).to_value()),
        Err(ModelError::Range)
    );
}
