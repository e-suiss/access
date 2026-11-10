use super::*;
use crate::testkit::j;

fn rp(params: &str) -> Json {
    j(&format!(r#"{{"openid_relying_party":{{{params}}}}}"#))
}

fn applied(policy: &str, metadata: &str) -> Result<Json, PolicyError> {
    apply(&rp(policy), &rp(metadata))
}

// IDP-19
#[test]
fn each_operator_applies_in_order() {
    let md = r#""a":"x","list":["p","q","r"],"scope":["s1"],"must":1"#;
    assert_eq!(
        applied(r#""a":{"value":"v"}"#, md)
            .unwrap()
            .get("openid_relying_party")
            .unwrap()
            .get("a"),
        Some(&j(r#""v""#))
    );
    let gone = applied(r#""a":{"value":null}"#, md).unwrap();
    assert!(gone.get("openid_relying_party").unwrap().get("a").is_none());
    let added = applied(r#""scope":{"add":["s2"]}"#, md).unwrap();
    assert_eq!(
        added.get("openid_relying_party").unwrap().get("scope"),
        Some(&j(r#"["s1","s2"]"#))
    );
    let defaulted = applied(r#""b":{"default":"d"},"a":{"default":"z"}"#, md).unwrap();
    let o = defaulted.get("openid_relying_party").unwrap();
    assert_eq!(o.get("b"), Some(&j(r#""d""#)));
    assert_eq!(o.get("a"), Some(&j(r#""x""#)));
    assert!(applied(r#""a":{"one_of":["x","y"]}"#, md).is_ok());
    assert_eq!(
        applied(r#""a":{"one_of":["y"]}"#, md),
        Err(PolicyError::Value)
    );
    let narrowed = applied(r#""list":{"subset_of":["q","r","s"]}"#, md).unwrap();
    assert_eq!(
        narrowed.get("openid_relying_party").unwrap().get("list"),
        Some(&j(r#"["q","r"]"#))
    );
    let emptied = applied(r#""list":{"subset_of":["z"]}"#, md).unwrap();
    assert!(
        emptied
            .get("openid_relying_party")
            .unwrap()
            .get("list")
            .is_none()
    );
    assert!(applied(r#""list":{"superset_of":["p"]}"#, md).is_ok());
    assert_eq!(
        applied(r#""list":{"superset_of":["z"]}"#, md),
        Err(PolicyError::Value)
    );
    assert!(applied(r#""must":{"essential":true}"#, md).is_ok());
    assert_eq!(
        applied(r#""absent":{"essential":true}"#, md),
        Err(PolicyError::Essential)
    );
    assert!(apply(&j(r#"{"other":{"a":{"value":"v"}}}"#), &rp(md)).is_ok());
}

// IDP-19
#[test]
fn merging_follows_each_operator() {
    let m = merge(
        &rp(r#""s":{"add":["a"],"subset_of":["a","b","c"],"superset_of":["a"],"essential":true}"#),
        &rp(r#""s":{"add":["b"],"subset_of":["a","b"],"superset_of":["b"],"essential":false},"t":{"one_of":["x","y"]}"#),
    )
    .unwrap();
    let s = m.get("openid_relying_party").unwrap().get("s").unwrap();
    assert_eq!(s.get("add"), Some(&j(r#"["a","b"]"#)));
    assert_eq!(s.get("subset_of"), Some(&j(r#"["a","b"]"#)));
    assert_eq!(s.get("superset_of"), Some(&j(r#"["a","b"]"#)));
    assert_eq!(s.get("essential"), Some(&Json::Bool(true)));
    let one = merge(
        &rp(r#""t":{"one_of":["x","y"]}"#),
        &rp(r#""t":{"one_of":["y","z"]}"#),
    )
    .unwrap();
    assert_eq!(
        one.get("openid_relying_party")
            .unwrap()
            .get("t")
            .unwrap()
            .get("one_of"),
        Some(&j(r#"["y"]"#))
    );
    assert!(merge(&rp(r#""v":{"value":"a"}"#), &rp(r#""v":{"value":"a"}"#)).is_ok());
    assert!(merge(&rp(r#""v":{"default":"a"}"#), &rp(r#""v":{"default":"a"}"#)).is_ok());
}

// IDP-19
#[test]
fn a_conflict_refuses() {
    let conflict = |a: &str, b: &str| merge(&rp(a), &rp(b));
    assert_eq!(
        conflict(r#""v":{"value":"a"}"#, r#""v":{"value":"b"}"#),
        Err(PolicyError::Conflict)
    );
    assert_eq!(
        conflict(r#""v":{"one_of":["a"]}"#, r#""v":{"one_of":["b"]}"#),
        Err(PolicyError::Conflict)
    );
    assert_eq!(
        conflict(r#""v":{"default":"a"}"#, r#""v":{"default":"b"}"#),
        Err(PolicyError::Conflict)
    );
    assert_eq!(
        conflict(r#""v":{"value":"a"}"#, r#""v":{"one_of":["b","c"]}"#),
        Err(PolicyError::Conflict)
    );
    assert_eq!(
        conflict(r#""v":{"subset_of":["a"]}"#, r#""v":{"add":["b"]}"#),
        Err(PolicyError::Conflict)
    );
    assert_eq!(
        conflict(r#""v":{"subset_of":["a"]}"#, r#""v":{"superset_of":["b"]}"#),
        Err(PolicyError::Conflict)
    );
    assert_eq!(
        conflict(r#""v":{"one_of":["a"]}"#, r#""v":{"subset_of":["a"]}"#),
        Err(PolicyError::Conflict)
    );
    assert_eq!(
        conflict(r#""v":{"essential":true}"#, r#""v":{"value":null}"#),
        Err(PolicyError::Conflict)
    );
    assert_eq!(PolicyError::Conflict.code(), "oidf-policy-conflict");
}

// IDP-19
#[test]
fn an_unknown_operator_or_shape_refuses() {
    assert_eq!(
        merge(&rp(r#""v":{"regexp":"^a"}"#), &rp("")),
        Err(PolicyError::Operator)
    );
    assert_eq!(
        applied(r#""v":{"regexp":"^a"}"#, ""),
        Err(PolicyError::Operator)
    );
    assert_eq!(
        merge(&rp(r#""v":{"add":"a"}"#), &rp("")),
        Err(PolicyError::Shape)
    );
    assert_eq!(
        merge(&rp(r#""v":{"essential":1}"#), &rp("")),
        Err(PolicyError::Shape)
    );
    assert_eq!(
        merge(&rp(r#""v":{"default":null}"#), &rp("")),
        Err(PolicyError::Shape)
    );
    assert_eq!(merge(&j("[]"), &rp("")), Err(PolicyError::Shape));
}
