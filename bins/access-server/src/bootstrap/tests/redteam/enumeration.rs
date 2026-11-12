//! AS-19, CR-40, TN-76, CVE-2026-4633: account enumeration through the hosted login and
//! recovery on the real router. An existing account, one that never existed and a differently
//! spelled one get the same status, the same answer members and the same response headers at
//! every step an attacker can reach without a credential.

use std::collections::BTreeSet;

use access_identity_webauthn::domain::decoy::MAX_DECOYS;

use super::super::super::recovery::{Page, Recording, account, hosted};
use super::*;

fn shape(status: StatusCode, json: &serde_json::Value, headers: &axum::http::HeaderMap) -> String {
    let members: BTreeSet<String> = json
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| !matches!(k.as_str(), "attempt" | "action" | "flow" | "id"))
                .map(|(k, v)| match (k.as_str(), v) {
                    (_, serde_json::Value::String(_)) => k.clone(),
                    ("nodes", serde_json::Value::Array(nodes)) => {
                        let kinds: Vec<String> = nodes
                            .iter()
                            .map(|n| format!("{}/{}/{}", n["type"], n["name"], n["method"]))
                            .collect();
                        format!("nodes={kinds:?}")
                    }
                    (_, other) => format!("{k}={other}"),
                })
                .collect()
        })
        .unwrap_or_default();
    let names: BTreeSet<String> = headers
        .keys()
        .map(|h| h.as_str().to_owned())
        .filter(|h| !matches!(h.as_str(), "date" | "x-request-id" | "traceparent"))
        .collect();
    format!("{status} {members:?} {names:?}")
}

fn relative(action: &str) -> String {
    action
        .strip_prefix("/realms/acme")
        .unwrap_or(action)
        .to_owned()
}

// AS-19, CR-40, TN-57
#[tokio::test]
async fn as_19_recovery_start_answers_the_same_for_every_identifier() {
    let c = console("redteam-enum-recovery", false).await;
    let app = hosted(&c, Recording::default());
    let _rae = account(&c, "rae@example.com", true).await;
    let mut seen = Vec::new();
    for who in [
        "rae@example.com",
        "nobody@example.com",
        "RAE@example.com",
        "rae@example.org",
    ] {
        let mut p = Page::default();
        let got = p
            .call(
                &app,
                &Method::POST,
                "/v1/recovery",
                Some(serde_json::json!({ "identifier": who, "method": "sent_code" })),
            )
            .await;
        seen.push((who, shape(got.status, &got.json, &got.headers)));
    }
    let first = seen[0].1.clone();
    for (who, s) in &seen {
        assert_eq!(s, &first, "{who} is told apart");
    }
}

// AS-19, CVE-2026-4633, TN-76
#[tokio::test]
async fn as_19_the_login_identifier_and_password_steps_answer_the_same_for_every_account() {
    let c = console("redteam-enum-login", false).await;
    let app = hosted(&c, Recording::default());
    let _ann = account(&c, "ann@example.com", true).await;
    let mut identified = Vec::new();
    let mut refused = Vec::new();
    let mut lengths = Vec::new();
    for who in [
        "ann@example.com",
        "nobody@example.com",
        "nobody@example.net",
    ] {
        let mut p = Page::default();
        let flow = p.call(&app, &Method::POST, "/v1/login/flows", None).await;
        assert_eq!(flow.status, StatusCode::CREATED, "{}", flow.json);
        let action = relative(flow.json["action"].as_str().unwrap());
        let at = p
            .call(
                &app,
                &Method::POST,
                &action,
                Some(
                    serde_json::json!({ "method": "identifier", "fields": { "identifier": who } }),
                ),
            )
            .await;
        identified.push((who, shape(at.status, &at.json, &at.headers)));
        lengths.push((who, passkeys(&at.json)));
        let next = relative(at.json["action"].as_str().unwrap_or(&action));
        let bad = p
            .call(
                &app,
                &Method::POST,
                &next,
                Some(serde_json::json!({ "method": "password", "fields": { "password": "not the one" } })),
            )
            .await;
        assert!(!bad.headers.contains_key(header::LOCATION), "{who}");
        refused.push((who, shape(bad.status, &bad.json, &bad.headers)));
    }
    for set in [&identified, &refused] {
        for (who, s) in set {
            assert_eq!(s, &set[0].1, "{who} is told apart");
        }
    }
    // OP-159 m.11 (g)
    for (who, n) in &lengths {
        assert!((1..=usize::from(MAX_DECOYS)).contains(n), "{who}: {n}");
        let mut p = Page::default();
        let flow = p.call(&app, &Method::POST, "/v1/login/flows", None).await;
        let action = relative(flow.json["action"].as_str().unwrap());
        let again = p
            .call(
                &app,
                &Method::POST,
                &action,
                Some(
                    serde_json::json!({ "method": "identifier", "fields": { "identifier": who } }),
                ),
            )
            .await;
        assert_eq!(passkeys(&again.json), *n, "{who}");
    }
}

/// How many credentials the identifier step's passkey options allow.
fn passkeys(json: &serde_json::Value) -> usize {
    json["nodes"]
        .as_array()
        .and_then(|nodes| nodes.iter().find(|n| n["type"] == "passkey_get"))
        .and_then(|n| n["options"]["allowCredentials"].as_array())
        .map_or(0, Vec::len)
}
