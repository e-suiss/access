use std::collections::BTreeMap;

use access_kernel::digest::Digest;
use access_kernel::model::Window;

use super::*;

fn body(namespace: &str, path: &[&str], incarnation: u64, event: &str) -> Value {
    Value::Map(vec![
        (Value::text("namespace"), Value::text(namespace)),
        (
            Value::text("path"),
            Value::Array(path.iter().map(|p| Value::text(p)).collect()),
        ),
        (Value::text("incarnation"), Value::Unsigned(incarnation)),
        (Value::text("event"), Value::text(event)),
    ])
}

fn claim(b: &Value) -> (Statement, Vec<u8>) {
    let tagged = dcbor::encode(
        &Value::Array(vec![Value::text(CLASS), b.clone()]),
        Limits::CEILING,
    )
    .unwrap();
    let s = Statement {
        domain: Digest([1; 32]),
        issuer: Id([2; 16]),
        subject: Id([2; 16]),
        class: String::from(CLASS),
        value: Some(EqValue::Bytes(
            context_digest(BODY_CONTEXT, &tagged).0.to_vec(),
        )),
        issued_at: 0,
        validity: Window { from: 0, until: 1 },
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes: None,
    };
    (s, dcbor::encode(b, Limits::CEILING).unwrap())
}

// OP-156 m.3 (k)
#[test]
fn a_lifecycle_claim_reads_its_body() {
    let (s, b) = claim(&body("ride", &["vehicles", "34-abc-12"], 2, "reincarnate"));
    let l = read(&s, Some(&b)).unwrap();
    assert_eq!(l.event, Event::Reincarnate);
    assert_eq!(
        l.resource,
        ResourceRef {
            namespace: String::from("ride"),
            path: vec![String::from("vehicles"), String::from("34-abc-12")],
            incarnation: 2,
        }
    );
    assert_eq!(read(&s, None), Err(MALFORMED));
    let (mut other, _) = claim(&body("ride", &["v"], 2, "reincarnate"));
    other.value = s.value.clone();
    let (_, wrong) = claim(&body("ride", &["v"], 3, "reincarnate"));
    assert_eq!(read(&other, Some(&wrong)), Err(MALFORMED));
    for bad in [
        body("ride", &[], 1, "create"),
        body("Ride", &["v"], 1, "create"),
        body("ride", &["v"], 1, "resurrect"),
        body("ride", &["v"], u64::MAX, "create"),
    ] {
        let (s, b) = claim(&bad);
        assert_eq!(read(&s, Some(&b)), Err(MALFORMED), "{bad:?}");
    }
}

// INV-32, E14
#[test]
fn a_create_must_go_above_every_incarnation_seen() {
    let at = |n, event| Lifecycle {
        resource: ResourceRef {
            namespace: String::from("ride"),
            path: vec![String::from("v")],
            incarnation: n,
        },
        event,
    };
    assert!(!reuses(&at(0, Event::Create), None));
    assert!(reuses(&at(0, Event::Create), Some(0)));
    assert!(reuses(&at(1, Event::Reincarnate), Some(1)));
    assert!(reuses(&at(0, Event::Reincarnate), Some(1)));
    assert!(!reuses(&at(2, Event::Reincarnate), Some(1)));
    assert!(!reuses(&at(1, Event::Delete), Some(1)));
}
