use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec;

use super::*;
use crate::model::{ActionSet, Structural};

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn action(name: &str) -> ActionRef {
    ActionRef {
        namespace: "pay".to_string(),
        name: name.to_string(),
        major: 1,
        schema: d(9),
    }
}

fn order(id: &str) -> ResourceRef {
    ResourceRef {
        namespace: "shop".to_string(),
        path: vec!["orders".to_string(), id.to_string()],
        incarnation: 0,
    }
}

fn intent() -> IntentEnvelope {
    IntentEnvelope {
        action: action("refund"),
        resources: vec![order("o1")],
        params: [(
            "amount".to_string(),
            ParamValue::Amount {
                value: 12_000,
                unit: "try".to_string(),
            },
        )]
        .into_iter()
        .collect(),
        opaque: [("note".to_string(), d(7))].into_iter().collect(),
        recipient: Some(Id([1; 16])),
        purpose: Some(PurposeRef::Code("complaint".to_string())),
        context: ContextRefs {
            work: Some(d(8)),
            ..ContextRefs::default()
        },
        validity: Window {
            from: 10,
            until: 20,
        },
    }
}

fn grant() -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: [action("refund")].into_iter().collect(),
            prefix: BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: "shop".to_string(),
            prefix: vec!["orders".to_string()],
            kind: None,
            attrs: alloc::collections::BTreeMap::new(),
        }),
        params: [(
            "amount".to_string(),
            Bound::Range {
                min: None,
                max: Some(50_000),
                unit: "try".to_string(),
            },
        )]
        .into_iter()
        .collect(),
        recipient: Some(SubjectSelector::Party(Id([1; 16]))),
        purpose: Some(
            [PurposeRef::Code("complaint".to_string())]
                .into_iter()
                .collect(),
        ),
    }
}

// OP-106 m.22, §9.5
#[test]
fn digest_is_over_canonical_bytes_with_context() {
    let e = intent();
    let bytes = e.to_bytes().unwrap();
    assert_eq!(IntentEnvelope::from_bytes(&bytes), Ok(e.clone()));
    assert_eq!(intent_digest(&e).unwrap(), digest(Context::Intent, &bytes));
    let mut other = e.clone();
    other.params.insert(
        "amount".to_string(),
        ParamValue::Amount {
            value: 12_001,
            unit: "try".to_string(),
        },
    );
    assert_ne!(intent_digest(&other).unwrap(), intent_digest(&e).unwrap());
    let mut opaque = e.clone();
    opaque.opaque.insert("note".to_string(), d(6));
    assert_ne!(intent_digest(&opaque).unwrap(), intent_digest(&e).unwrap());
}

// OP-108 m.12: there is no nonce field
#[test]
fn nonce_is_not_part_of_the_envelope() {
    let Value::Map(mut entries) = intent().to_value() else {
        panic!()
    };
    entries.push((Value::text("nonce"), Value::Bytes(vec![1; 16])));
    assert_eq!(
        IntentEnvelope::from_value(&Value::Map(entries)),
        Err(ModelError::Unknown)
    );
}

#[test]
fn coverage_rules() {
    let cat = Catalog::default();
    assert!(covers(&grant(), &intent(), &cat));

    let mut big = intent();
    big.params.insert(
        "amount".to_string(),
        ParamValue::Amount {
            value: 60_000,
            unit: "try".to_string(),
        },
    );
    assert!(!covers(&grant(), &big, &cat));

    let mut eur = intent();
    eur.params.insert(
        "amount".to_string(),
        ParamValue::Amount {
            value: 1,
            unit: "eur".to_string(),
        },
    );
    assert!(!covers(&grant(), &eur, &cat));

    let mut wrong_type = intent();
    wrong_type
        .params
        .insert("amount".to_string(), ParamValue::Count(1));
    assert!(!covers(&grant(), &wrong_type, &cat));

    let mut missing = intent();
    missing.params.clear();
    assert!(!covers(&grant(), &missing, &cat));

    let mut other_recipient = intent();
    other_recipient.recipient = Some(Id([2; 16]));
    assert!(!covers(&grant(), &other_recipient, &cat));

    let mut two = intent();
    two.resources.push(ResourceRef {
        namespace: "shop".to_string(),
        path: vec!["carts".to_string()],
        incarnation: 0,
    });
    assert!(!covers(&grant(), &two, &cat));

    let mut action_charge = intent();
    action_charge.action = action("charge");
    assert!(!covers(&grant(), &action_charge, &cat));

    let mut pred = grant();
    pred.recipient = Some(SubjectSelector::Pred(
        [crate::model::Conjunct {
            claim_class: "customer".to_string(),
            value: None,
        }]
        .into_iter()
        .collect(),
    ));
    assert!(!covers(&pred, &intent(), &cat));
}
