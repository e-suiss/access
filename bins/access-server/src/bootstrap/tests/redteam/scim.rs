//! AS-18, CR-10, SAI-2, GHSA-xxwr-vvr3-2g9f: hostile SCIM filters and Set changes against the
//! real SCIM router. A filter that probes a never-returned attribute, nests past the limit or
//! is too long is refused before it is evaluated; filter syntax inside a value is a literal; a
//! Set change of a read-only member is refused and changes nothing.

use access_http::api::domain::page::encode;

use super::super::scim::{scim_router, user};
use super::*;

async fn register(c: &Console, name: &str) -> String {
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/scim-clients",
            ("registerScimClient", None),
            serde_json::json!({ "name": name }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    w.body["client_secret"].as_str().unwrap().to_owned()
}

fn listing(filter: &str) -> String {
    format!("/Users?filter={}", encode(filter))
}

// AS-18, CR-10, SAI-2, R-4
#[tokio::test]
async fn as_18_hostile_filters_are_refused_before_they_are_evaluated() {
    let c = console("redteam-scim-filter", true).await;
    let s = scim_router(&c);
    let secret = register(&c, "redteam").await;
    for name in ["ada@contoso.example", "bob@contoso.example"] {
        let (st, _, body) = s
            .call(Method::POST, "/Users", &secret, Some(user(name, name)), &[])
            .await;
        assert_eq!(st, StatusCode::CREATED, "{body}");
    }
    let deep = format!("{}userName pr{}", "(".repeat(40), ")".repeat(40));
    let long = format!("userName eq \"{}\"", "a".repeat(9_000));
    for f in [
        "password pr",
        "password eq \"x\"",
        "name.formatted pr and password co \"a\"",
        deep.as_str(),
        long.as_str(),
        "userName eq",
        "userName eq \"a\" or",
        "unknownAttribute eq \"x\"",
    ] {
        let (st, _, body) = s.call(Method::GET, &listing(f), &secret, None, &[]).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{f}: {body}");
        let kind = if f.len() > 4096 {
            "invalidValue"
        } else {
            "invalidFilter"
        };
        assert_eq!(body["scimType"], kind, "{f}: {body}");
    }
    for f in [
        "userName eq \"*\"",
        "userName eq \"x' OR '1'='1\"",
        "userName eq \"ada@contoso.example\\\" or userName pr or \\\"\"",
        "userName eq \"%\"",
        "userName eq \"\\u0000\"",
    ] {
        let (st, _, body) = s.call(Method::GET, &listing(f), &secret, None, &[]).await;
        assert_eq!(st, StatusCode::OK, "{f}: {body}");
        assert_eq!(body["totalResults"], 0, "{f}: {body}");
    }
    let (st, _, body) = s
        .call(
            Method::GET,
            &listing("userName eq \"ada@contoso.example\""),
            &secret,
            None,
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["totalResults"], 1, "{body}");
}

// AS-18, GHSA-xxwr-vvr3-2g9f
#[tokio::test]
async fn as_18_a_set_change_of_a_read_only_member_is_refused_and_changes_nothing() {
    let c = console("redteam-scim-set", true).await;
    let s = scim_router(&c);
    let secret = register(&c, "redteam").await;
    let (st, _, created) = s
        .call(
            Method::POST,
            "/Users",
            &secret,
            Some(user("ada@contoso.example", "e-ada")),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    let path = format!("/Users/{}", created["id"].as_str().unwrap());
    let (_, _, before) = s.call(Method::GET, &path, &secret, None, &[]).await;
    let schemas = [access_identity_scim::domain::patch::PATCH_SCHEMA];
    for op in [
        serde_json::json!({ "op": "replace", "path": "id", "value": "forged" }),
        serde_json::json!({ "op": "add", "path": "groups", "value": [{ "value": "admins" }] }),
        serde_json::json!({ "op": "replace", "path": "meta.created", "value": "1970-01-01T00:00:00Z" }),
        serde_json::json!({ "op": "replace", "path": "password", "value": "probe" }),
    ] {
        let body = serde_json::json!({ "schemas": schemas, "Operations": [
            { "op": "replace", "path": "displayName", "value": "Changed" },
            op,
        ]});
        let (st, _, answer) = s
            .call(Method::PATCH, &path, &secret, Some(body.clone()), &[])
            .await;
        if st.is_success() {
            assert_eq!(answer["id"], before["id"], "{body}");
            assert_eq!(answer["groups"], before["groups"], "{body}");
            assert_eq!(
                answer["meta"]["created"], before["meta"]["created"],
                "{body}"
            );
            assert!(answer.get("password").is_none(), "{body}");
        } else {
            assert_eq!(st, StatusCode::BAD_REQUEST, "{body}: {answer}");
            let (_, _, now) = s.call(Method::GET, &path, &secret, None, &[]).await;
            assert_eq!(
                now, before,
                "a refused request changed the resource: {body}"
            );
        }
    }
    let whole = serde_json::json!({ "schemas": schemas, "Operations": [
        { "op": "replace", "value": { "displayName": "Whole", "groups": [{ "value": "admins" }], "id": "forged" } },
    ]});
    let (st, _, answer) = s
        .call(Method::PATCH, &path, &secret, Some(whole), &[])
        .await;
    if st.is_success() {
        assert_eq!(answer["id"], before["id"]);
        assert_eq!(answer["groups"], before["groups"]);
    }
    let (_, _, after) = s.call(Method::GET, &path, &secret, None, &[]).await;
    assert_eq!(after["id"], before["id"]);
    assert_eq!(after["groups"], before["groups"]);
}
