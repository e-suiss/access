use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;

use super::*;

fn action(major: u64, schema: u8) -> ActionRef {
    ActionRef {
        namespace: String::from("acme.pay"),
        name: String::from("transfer"),
        major,
        schema: Digest([schema; 32]),
    }
}

fn mapping(relation: Relation) -> Mapping {
    Mapping {
        from: action(1, 1),
        to: action(2, 2),
        relation,
        ops: vec![
            MappingOp::Rename {
                from: String::from("payee"),
                to: String::from("beneficiary"),
            },
            MappingOp::Enum {
                field: String::from("rail"),
                values: BTreeMap::from([(String::from("sepa_inst"), String::from("sepa"))]),
            },
            MappingOp::Constant {
                field: String::from("channel"),
                value: EqValue::Text(String::from("api")),
            },
            MappingOp::Scale {
                field: String::from("amount"),
                factor: 100,
            },
            MappingOp::Drop {
                field: String::from("note"),
            },
        ],
    }
}

// OP-157 m.3 (b), §9.13.4
#[test]
fn a_mapping_round_trips_and_its_digest_pins_relation_and_order() {
    let m = mapping(Relation::Narrowing);
    assert_eq!(Mapping::from_value(&m.to_value()), Ok(m.clone()));
    let d = mapping_digest(&m).unwrap();
    assert_eq!(d, context_digest(CONTEXT, &m.to_bytes().unwrap()));
    assert_ne!(mapping_digest(&mapping(Relation::Broadening)).unwrap(), d);
    let mut reordered = m.clone();
    reordered.ops.reverse();
    assert_ne!(mapping_digest(&reordered).unwrap(), d);
}

// OP-157 m.3 (b), INV-8, OP-108 m.4
#[test]
fn only_the_closed_algebra_decodes() {
    let mut m = mapping(Relation::Narrowing).to_value();
    if let Value::Map(entries) = &mut m {
        for (k, v) in entries.iter_mut() {
            if *k == Value::text("ops") {
                *v = Value::Array(vec![tagged(
                    "call",
                    map([("field", Some(Value::text("x")))]),
                )]);
            }
        }
    }
    assert_eq!(Mapping::from_value(&m), Err(ModelError::Unknown));
    let scale = tagged(
        "scale",
        map([
            ("factor", Some(Value::Unsigned(1))),
            ("field", Some(Value::text("amount"))),
        ]),
    );
    assert_eq!(MappingOp::from_value(&scale), Err(ModelError::Range));
    let mut other = mapping(Relation::Narrowing);
    other.to.name = String::from("refund");
    assert_eq!(
        Mapping::from_value(&other.to_value()),
        Err(ModelError::Range)
    );
}

// E10, OP-157 m.3 (r)
#[test]
fn only_non_broadening_relations_may_apply() {
    assert!(Relation::RepresentationEquivalent.non_broadening());
    assert!(Relation::Narrowing.non_broadening());
    assert!(!Relation::Broadening.non_broadening());
    assert!(!Relation::Incompatible.non_broadening());
}

// OP-157 m.3 (b), TN-73
#[test]
fn a_case_reference_is_a_digest_of_system_and_case() {
    let a = crate::digest::case_ref("zendesk", "4411").unwrap();
    assert_ne!(a, crate::digest::case_ref("zendesk", "4412").unwrap());
    assert_ne!(a, crate::digest::case_ref("freshdesk", "4411").unwrap());
    let p = crate::model::PurposeRef::Case(a);
    assert_eq!(crate::model::PurposeRef::from_value(&p.to_value()), Ok(p));
}
