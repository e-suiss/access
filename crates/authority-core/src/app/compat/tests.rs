use std::collections::BTreeMap;

use access_kernel::codec::Canonical;
use access_kernel::compat::{Mapping, MappingOp, Relation};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::meta::{self, ContentState, Ended, EndedHow, kind};
use access_kernel::model::{ActionRef, Id, Window};
use access_kernel::schema::schemas_key;
use suiss_crypto::dcbor::Value;

use super::*;
use crate::domain::Snapshot;

fn action(major: u64) -> ActionRef {
    ActionRef {
        namespace: "shop".to_owned(),
        name: "pay".to_owned(),
        major,
        schema: Digest([u8::try_from(major).unwrap(); 32]),
    }
}

fn mapping(relation: Relation) -> Mapping {
    Mapping {
        from: action(1),
        to: action(2),
        relation,
        ops: vec![MappingOp::Rename {
            from: "minor".to_owned(),
            to: "amount".to_owned(),
        }],
    }
}

fn intent(major: u64) -> IntentEnvelope {
    IntentEnvelope {
        action: action(major),
        resources: Vec::new(),
        params: BTreeMap::from([("minor".to_owned(), ParamValue::Count(3))]),
        provenance: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 1 << 50,
        },
    }
}

fn pinned(relation: Relation, at: u64) -> Pinned {
    let m = mapping(relation);
    Pinned {
        digest: compat::mapping_digest(&m).unwrap(),
        mapping: m,
        at,
    }
}

const DAY_MS: u64 = 86_400_000;

// SEC16, OP-157 m.3 (r), (o), Ek B 5666
#[test]
fn the_pin_age_counts_only_a_mapping_in_probation_that_applies() {
    let probation = 14 * DAY_S;
    let at = 1_000 * DAY_MS;
    let p = [pinned(Relation::Narrowing, at)];
    assert_eq!(
        pin_age_s(&p, &intent(2), probation, at + 13 * DAY_MS),
        i64::try_from(13 * DAY_S).unwrap()
    );
    assert_eq!(pin_age_s(&p, &intent(2), probation, at + 15 * DAY_MS), -1);
    assert_eq!(pin_age_s(&p, &intent(1), probation, at + DAY_MS), -1);
    assert_eq!(pin_age_s(&[], &intent(2), probation, at), -1);
    // E10
    let broad = [pinned(Relation::Broadening, at)];
    assert_eq!(pin_age_s(&broad, &intent(2), probation, at + DAY_MS), -1);
}

fn acceptance(mappings: &[Digest], ended: bool, widened: Option<u64>) -> ContentState {
    let window = Window {
        from: 0,
        until: 1 << 50,
    };
    ContentState {
        content: Value::Map(vec![
            (Value::text("use"), Value::text("schema-definition")),
            (Value::text("validity"), window.to_value()),
            (
                Value::text("mappings"),
                Value::Array(mappings.iter().map(Canonical::to_value).collect()),
            ),
        ]),
        since: 7,
        widened,
        ended: ended.then_some(Ended {
            at: 9,
            how: EndedHow::Revoked,
        }),
    }
}

fn view(states: &[(Id, ContentState)]) -> Snapshot {
    let mut snap = Snapshot::default();
    let ids = Value::Array(states.iter().map(|(id, _)| id.to_value()).collect());
    let mut rows = vec![(schemas_key("shop"), Some(ids), 1)];
    for (id, st) in states {
        rows.push((meta::key(kind::ACCEPTANCE, id), Some(st.to_value()), 1));
    }
    snap.fill(rows);
    snap
}

// PI-19, OP-157 m.3 (r), Ek B 5667
#[test]
fn only_a_live_acceptance_pins_and_a_revoked_one_drops_the_pin() {
    let d = Digest([5; 32]);
    let other = Digest([6; 32]);
    let snap = view(&[
        (Id([1; 16]), acceptance(&[d], false, Some(8))),
        (Id([2; 16]), acceptance(&[other], true, None)),
    ]);
    let pins = pins(&snap, "shop", 10);
    assert_eq!(pins.get(&d), Some(&8));
    assert!(!pins.contains_key(&other));
    assert!(super::pins(&view(&[]), "shop", 10).is_empty());
}

// OP-157 m.3 (n), m.8 (m)
#[test]
fn probation_defaults_to_fourteen_days() {
    let snap = Snapshot::default();
    snap.restart();
    assert_eq!(probation_s(&snap), 14 * DAY_S);
    let mut set = Snapshot::default();
    set.fill([(
        meta::policy_default_key(PROBATION_DAYS),
        Some(Value::Unsigned(3)),
        1,
    )]);
    assert_eq!(probation_s(&set), 3 * DAY_S);
}
