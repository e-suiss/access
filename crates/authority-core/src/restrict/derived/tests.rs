use std::collections::BTreeMap;

use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::model::{ActionRef, Id, ResourceRef, Window as Validity};

use super::*;

fn intent(cents: i64) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: ActionRef {
            namespace: String::from("pay"),
            name: String::from("transfer"),
            major: 1,
            schema: Digest([9; 32]),
        },
        resources: vec![ResourceRef {
            namespace: String::from("pay"),
            path: vec![String::from("acct")],
            incarnation: 0,
        }],
        params: BTreeMap::from([(
            String::from("amount"),
            ParamValue::Amount {
                value: cents,
                unit: String::from(THRESHOLD_UNIT),
            },
        )]),
        opaque: BTreeMap::new(),
        recipient: Some(Id([7; 16])),
        purpose: None,
        context: ContextRefs::default(),
        validity: Validity { from: 0, until: 1 },
    }
}

// RT26, SI-8, OP-159 m.3 (m)
#[test]
fn the_whitelist_is_closed_and_cited_values_read_back() {
    assert_eq!(NAMES.len(), 12);
    let v = Derived {
        party_consumption: 12,
        claim_age_s: NONE,
        threshold_adjacent: 3,
        ..Derived::empty()
    };
    assert_eq!(Derived::from_cited(&v.cited()), Some(v.clone()));
    let Value::Map(mut entries) = v.cited() else {
        panic!("cited is a map")
    };
    entries.push((Value::text("reputation"), Value::Unsigned(1)));
    assert_eq!(Derived::from_cited(&Value::Map(entries)), None);
    assert_eq!(v.json()["claim_age_s"], -1);
}

// §13.7.6, U18
#[test]
fn adjacency_is_within_80_percent_below_a_tier_threshold() {
    let ct1 = u64::try_from(CT1_MAX).unwrap();
    assert!(adjacent(ct1));
    assert!(adjacent(ct1 / 5 * 4));
    assert!(!adjacent(ct1 / 5 * 4 - 1));
    assert!(!adjacent(ct1 + 1));
    assert!(adjacent(u64::try_from(CT2_MAX).unwrap()));
}

// U18, OP-157 m.3 (o)
#[test]
fn an_adjacent_exercise_counts_itself_and_draws_its_counters() {
    let party = Id([1; 16]);
    let now = 3 * WINDOW_MS + 5;
    let counted = Counted {
        payee: None,
        consumption: 1_000,
        adjacent: 2,
        transitions: None,
    };
    let w = window(&intent(90_000), Some(&party), &counted, now);
    assert_eq!(w.values.threshold_adjacent, 3);
    assert_eq!(w.values.party_consumption, 91_000);
    let bucket = buckets(now)[0];
    assert_eq!(buckets(now), vec![bucket, bucket - WINDOW_MS]);
    assert_eq!(buckets(5), vec![0]);
    let t = target(&intent(1)).unwrap();
    assert_eq!(
        w.increments,
        vec![
            (consumption_key(&party, bucket), 90_000),
            (adjacent_key(&party, &t, bucket), 1),
        ]
    );
    let far = window(&intent(10_000), Some(&party), &counted, now);
    assert_eq!(far.values.threshold_adjacent, 0);
    assert_eq!(
        window(&intent(90_000), None, &counted, now),
        Window::default()
    );
}

// U18, OP-157 m.3 (q)
#[test]
fn a_new_holder_counts_once_per_episode() {
    let party = Id([1; 16]);
    let grant = Id([2; 16]);
    let fresh = Counted {
        payee: None,
        transitions: Some((grant, 40, 5, false)),
        ..Counted::default()
    };
    let w = window(&intent(1), Some(&party), &fresh, WINDOW_MS);
    assert_eq!(w.values.selector_transitions, 6);
    assert!(
        w.increments
            .contains(&(transition_seen_key(&grant, &party, 40), 1))
    );
    let seen = Counted {
        payee: None,
        transitions: Some((grant, 40, 6, true)),
        ..Counted::default()
    };
    let w = window(&intent(1), Some(&party), &seen, WINDOW_MS);
    assert_eq!(w.values.selector_transitions, 6);
    let bucket = buckets(WINDOW_MS)[0];
    assert!(
        !w.increments
            .iter()
            .any(|(k, _)| *k == transitions_key(&grant, bucket))
    );
}

// OP-159 m.3 (m)
#[test]
fn an_unseen_payee_is_marked_by_the_allow_and_a_seen_one_is_not() {
    let payee = Digest([5; 32]);
    let fresh = window(
        &intent(100),
        None,
        &Counted {
            payee: Some((payee, false)),
            ..Counted::default()
        },
        0,
    );
    assert_eq!(fresh.values.payee_seen, 0);
    assert_eq!(fresh.increments, vec![(payee_seen_key(&payee), 1)]);
    let seen = window(
        &intent(100),
        None,
        &Counted {
            payee: Some((payee, true)),
            ..Counted::default()
        },
        0,
    );
    assert_eq!(seen.values.payee_seen, 1);
    assert_eq!(seen.increments.len(), 0);
    assert_eq!(Derived::from_cited(&seen.values.cited()), Some(seen.values));
}
