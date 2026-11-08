#![allow(clippy::unwrap_used, reason = "test")]

use super::*;

fn package() -> Value {
    json!({
        "namespace": "shop",
        "catalog_version": 3,
        "actions": [{
            "name": "refund",
            "major": 1,
            "effect_class": "irreversible",
            "params": { "amount": "amount", "note": "text" },
        }],
        "classes": [
            { "action": "refund", "parameter": "amount", "class": "amount" },
            { "action": "refund", "parameter": "note", "class": "opaque" },
        ],
        "compatibility": { "from": 2, "relation": "narrowing" },
    })
}

// L1-ADP-18, §8.17.10.2, E12
#[test]
fn a_package_names_its_typed_draft() {
    let d = draft_of(&package()).unwrap();
    assert_eq!(d.namespace, "shop");
    assert_eq!(d.catalog_version, 3);
    assert_eq!(d.actions.len(), 1);
    assert_eq!(
        d.classes[&(String::from("refund"), String::from("amount"))],
        ParamClass::Relevant(Affects::Amount)
    );
    assert_eq!(
        d.compatibility,
        Some(Compatibility {
            from: 2,
            relation: Relation::Narrowing
        })
    );
    let mut extra = package();
    extra["accept"] = json!(true);
    assert_eq!(draft_of(&extra), Err(AdpError("package")));
    let mut twice = package();
    twice["classes"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "action": "refund", "parameter": "note", "class": "flag" }));
    assert_eq!(draft_of(&twice), Err(AdpError("package")));
}

// L1-ADP-18
#[test]
fn the_package_digest_is_order_independent_and_binds_every_member() {
    let a = package();
    let b: Value = serde_json::from_str(
        r#"{"classes":[{"parameter":"amount","action":"refund","class":"amount"},
        {"action":"refund","class":"opaque","parameter":"note"}],"catalog_version":3,
        "compatibility":{"relation":"narrowing","from":2},"namespace":"shop",
        "actions":[{"major":1,"name":"refund","effect_class":"irreversible",
        "params":{"note":"text","amount":"amount"}}]}"#,
    )
    .unwrap();
    assert_eq!(package_digest(&a), package_digest(&b));
    let mut c = package();
    c["catalog_version"] = json!(4);
    assert_ne!(package_digest(&a), package_digest(&c));
}

// L1-ADP-18, TN-20
#[test]
fn a_request_names_one_to_sixteen_distinct_domains() {
    let d = |n: u8| json!(b64url_encode(&[n; 32]));
    assert_eq!(domains(Some(&json!([d(1), d(2)]))).unwrap().len(), 2);
    assert!(domains(Some(&json!([]))).is_err());
    assert!(domains(Some(&json!([d(1), d(1)]))).is_err());
    let many: Vec<Value> = (0..=16).map(d).collect();
    assert!(domains(Some(&Value::Array(many))).is_err());
    assert!(domains(Some(&json!(["AA"]))).is_err());
}
