#![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test code")]

use serde_json::json;

use super::*;

fn body() -> Json {
    json!({
        "name": "wiki",
        "engine": "nginx",
        "host": "wiki.example.com",
        "upstream": "http://10.0.0.5:8080",
        "client_id": "wiki-proxy",
        "pep": b64url_encode(&[7; 32]),
        "action": {
            "namespace": "apps",
            "name": "use",
            "major": 1,
            "schema": b64url_encode(&[9; 32]),
        },
        "namespace": "apps",
        "routes": ["/", "/admin"],
    })
}

// OP-156 m.3 (a), (l)
#[test]
fn rest_bodies_compile_to_their_catalog_six_action() {
    let r = ProxyChange::register(&body()).unwrap();
    assert_eq!(r.action(), IdpAction::ProxyRegister);
    assert_eq!(r.path(), ["proxy", "wiki"]);
    let ProxyChange::Register(reg) = &r else {
        panic!("{r:?}")
    };
    assert_eq!(reg.audience(), "https://wiki.example.com");
    assert_eq!(
        reg.redirect_uri(),
        "https://wiki.example.com/access-proxy/v1/callback"
    );
    assert_eq!(from_json(&to_json(reg)).unwrap(), *reg);
    assert_eq!(
        ProxyChange::update("wiki", &body()).unwrap().action(),
        IdpAction::ProxyUpdate
    );
    assert!(ProxyChange::update("other", &body()).is_err());
    assert_eq!(
        ProxyChange::retire("wiki", &json!({})).unwrap().action(),
        IdpAction::ProxyRetire
    );
    assert_eq!(
        ProxyChange::plain_headers("wiki", &json!({"enabled": true}))
            .unwrap()
            .action(),
        IdpAction::ProxyPlainHeaders
    );
    assert_eq!(
        ProxyChange::plain_headers("wiki", &json!({"enabled": false}))
            .unwrap()
            .action(),
        IdpAction::ProxyPlainHeadersClose
    );
    assert_ne!(
        ProxyChange::PlainHeaders(String::from("wiki")).body(),
        ProxyChange::PlainHeadersClose(String::from("wiki")).body()
    );
}

// OP-156 m.3 (l), TI-9
#[test]
fn a_registration_outside_the_rules_is_refused() {
    let with = |k: &str, v: Json| {
        let mut b = body();
        b.as_object_mut().unwrap().insert(String::from(k), v);
        ProxyChange::register(&b)
    };
    assert!(with("engine", json!("grpc")).is_err());
    assert!(with("host", json!("localhost")).is_err());
    assert!(with("host", json!("wiki.example.com:443")).is_err());
    assert!(with("pep", json!("short")).is_err());
    assert!(with("routes", json!([])).is_err());
    assert!(with("routes", json!(["/", "/Admin", "/admin"])).is_err());
    assert!(with("upstream", json!("ftp://x")).is_err());
    assert!(with("plain_headers", json!(true)).is_err());
    assert!(with("name", json!("Wiki")).is_err());
    let mut b = body();
    b.as_object_mut().unwrap().remove("routes");
    let ProxyChange::Register(r) = ProxyChange::register(&b).unwrap() else {
        panic!()
    };
    assert_eq!(r.routes, ["/"]);
    assert!(ProxyChange::retire("wiki", &json!({"x": 1})).is_err());
    assert!(ProxyChange::plain_headers("wiki", &json!({"enabled": "yes"})).is_err());
}
