//! The realm-admin resources over HTTP (OP-151 m.2 M1, m.3 (s)): every write is the caller's
//! AIS compiled into one Exercise, a write without it changes nothing, reads see only the
//! realm's own resources, updates are conditional, and no resource carries a credential.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod admin;

use access_http::api::manifest::{Access, MANIFEST, Route};
use access_http::api::schema::openapi;
use access_kernel::json::b64url_encode;
use axum::body::Body;
use axum::http::{Request, StatusCode};

use admin::{HIDDEN_KEY, Harness, REALM, ais, platform_domain, proof, read, realm_domain, send};

fn path_of(row: &Route) -> String {
    row.path
        .split('/')
        .map(|s| match s {
            "{slug}" => REALM,
            s if s.starts_with('{') => "k1",
            s => s,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn write(row: &Route, nonce: [u8; 16], ais: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(row.verb.method())
        .uri(path_of(row))
        .header("content-type", "application/json")
        .header("idempotency-key", b64url_encode(&nonce))
        .header("if-match", "*");
    if let Some(a) = ais {
        b = b.header("x-access-ais", a);
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

fn realm_writes() -> impl Iterator<Item = &'static Route> {
    MANIFEST
        .iter()
        .filter(|r| r.access == Access::Write && r.path.starts_with("/admin/v1/realms/"))
}

// §9.7, TN-110, OP-151 m.3 (s): for every realm write, no AIS, another realm's or the platform's
// Instance, a statement for another domain, or a nonce already spent on another request
// leaves the log where it was; the caller's own AIS moves it by one Exercise
#[tokio::test]
async fn every_realm_write_without_its_actor_proof_changes_nothing() {
    let h = Harness::new();
    let router = h.router();
    let own = h.instance(realm_domain());
    let platform = h.instance(platform_domain());
    let mut n = 0_u8;
    for row in realm_writes() {
        let op = row.operation_id;
        n += 1;
        let nonce = [n; 16];
        let before = h.position();
        let refused = [
            write(row, nonce, None, "{}"),
            write(
                row,
                nonce,
                Some(&ais(&platform, realm_domain(), nonce, h.now())),
                "{}",
            ),
            write(
                row,
                nonce,
                Some(&ais(&own, platform_domain(), nonce, h.now())),
                "{}",
            ),
        ];
        for (i, request) in refused.into_iter().enumerate() {
            let (r, body) = send(&router, request).await;
            assert!(
                matches!(r.status(), StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
                "{op} case {i}: {} {body}",
                r.status()
            );
            assert_eq!(h.position(), before, "{op} case {i}");
        }
        // TN-125: a job's envelope is checked in its own test
        if op == "createJob" {
            continue;
        }
        let signed = ais(&own, realm_domain(), nonce, h.now());
        let (r, body) = send(&router, write(row, nonce, Some(&signed), "{}")).await;
        assert!(r.status().is_success(), "{op}: {} {body}", r.status());
        assert_eq!(h.position(), before + 1, "{op}: one Exercise");
        assert!(
            body["exercise_id"].is_string() && body["position"].is_string(),
            "{op}"
        );
        // IDI-4: the RP ID answer marks the change irreversible
        assert_eq!(body["irreversible"] == true, op == "putRpId", "{op}");
        let (r, _) = send(&router, write(row, nonce, Some(&signed), "{\"other\":1}")).await;
        // TN-126: a kept answer refuses the key at once; a secret answer is never kept, and
        // the spent nonce refuses the Exercise
        assert!(
            matches!(
                r.status(),
                StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST
            ),
            "{op}: a spent nonce: {}",
            r.status()
        );
        assert_eq!(h.position(), before + 1, "{op}");
    }
}

// TN-113, OP-151 m.3 (s): a resource of another realm is 404 like a missing one, and a token
// of another realm never reads this one
#[tokio::test]
async fn reads_see_only_the_realms_own_resources() {
    let h = Harness::new();
    let router = h.router();
    let token = h.token("r", "access-admin:realm:acme", &["realm.read"], 600_000);
    for collection in ["clients", "groups", "accounts", "upstream-idps"] {
        let path = format!("/admin/v1/realms/{REALM}/{collection}/{HIDDEN_KEY}");
        let (r, body) = send(&router, read(&path, &token)).await;
        assert_eq!(
            (r.status(), body["code"].as_str()),
            (StatusCode::NOT_FOUND, Some("not_found")),
            "{collection}"
        );
        let (r, body) = send(
            &router,
            read(&format!("/admin/v1/realms/{REALM}/{collection}"), &token),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "{collection}");
        assert_eq!(body["items"].as_array().unwrap().len(), 2, "{collection}");
    }
    let other = h.token("o", "access-admin:realm:other", &["realm.read"], 600_000);
    let (r, _) = send(
        &router,
        read(&format!("/admin/v1/realms/{REALM}/clients"), &other),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

// OP-65: a list filters with the SCIM subset over its own attributes only
#[tokio::test]
async fn lists_filter_over_their_attributes() {
    let h = Harness::new();
    let router = h.router();
    let token = h.token("r", "access-admin:realm:acme", &["realm.read"], 600_000);
    let base = format!("/admin/v1/realms/{REALM}/clients");
    let query = |q: &str| {
        Request::get(format!("{base}?{q}"))
            .header("authorization", format!("DPoP {token}"))
            .header("dpop", proof("GET", &base))
            .body(Body::empty())
            .unwrap()
    };
    let (r, body) = send(&router, query("filter=client_id%20eq%20%22a%22")).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    let (r, body) = send(&router, query("filter=secret_hash%20pr")).await;
    assert_eq!(
        (r.status(), body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("unknown-filter-attribute"))
    );
}

// OP-65, RFC 9110 §13.1.1: an update names the version it replaces: 428 without If-Match, 412
// for another version, and the ETag a read returned goes through
#[tokio::test]
async fn updates_are_conditional_on_the_etag() {
    let h = Harness::new();
    let router = h.router();
    let actor = h.instance(realm_domain());
    let token = h.token("r", "access-admin:realm:acme", &["realm.read"], 600_000);
    let path = format!("/admin/v1/realms/{REALM}/groups/staff");
    let (r, _) = send(&router, read(&path, &token)).await;
    let tag = r.headers()["etag"].to_str().unwrap().to_owned();
    let put = |nonce: [u8; 16], if_match: Option<&str>| {
        let mut b = Request::patch(&path)
            .header("idempotency-key", b64url_encode(&nonce))
            .header("x-access-ais", ais(&actor, realm_domain(), nonce, h.now()));
        if let Some(m) = if_match {
            b = b.header("if-match", m);
        }
        b.body(Body::from(r#"{"display_name":"Staff"}"#)).unwrap()
    };
    let (r, body) = send(&router, put([1; 16], None)).await;
    assert_eq!(
        (r.status(), body["code"].as_str()),
        (
            StatusCode::PRECONDITION_REQUIRED,
            Some("precondition-required")
        )
    );
    let (r, _) = send(&router, put([2; 16], Some("\"stale\""))).await;
    assert_eq!(r.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(h.position(), 0);
    let (r, body) = send(&router, put([3; 16], Some(&tag))).await;
    assert_eq!(r.status(), StatusCode::OK, "{body}");
    assert_eq!(h.position(), 1);
    assert!(r.headers().contains_key("etag"));
}

// TN-110, PI-7: drafting a write returns the intent its AIS signs and changes nothing; an
// operation that is not a realm write cannot be drafted
#[tokio::test]
async fn a_draft_returns_the_intent_and_changes_nothing() {
    let h = Harness::new();
    let router = h.router();
    let token = h.token("r", "access-admin:realm:acme", &["realm.read"], 600_000);
    let path = format!("/admin/v1/realms/{REALM}/intents");
    let draft = |body: &str| {
        Request::post(&path)
            .header("authorization", format!("DPoP {token}"))
            .header("dpop", proof("POST", &path))
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    let (r, body) = send(
        &router,
        draft(r#"{"operation":"putGroup","key":"staff","body":{"display_name":"Staff"}}"#),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "{body}");
    assert_eq!(body["operation"], "putGroup");
    assert_eq!(body["intent_digest"].as_str().unwrap().len(), 43);
    assert!(body["body"]["validity"].is_object());
    for bad in [
        r#"{"operation":"getClient"}"#,
        r#"{"operation":"setPassword"}"#,
        "{}",
    ] {
        let (r, body) = send(&router, draft(bad)).await;
        assert_eq!(body["code"], "unknown-operation", "{bad}");
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(h.position(), 0);
    assert_eq!(h.proposals(), 0);
}

// TN-61, TNI-6, CR-38, OP-151 m.3 (s): no resource schema of the contract has a credential
// member; a client secret appears only in a write's one-time answer
#[test]
fn no_resource_schema_carries_a_credential() {
    let doc = openapi();
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    for name in [
        "Account",
        "Client",
        "Group",
        "UpstreamIdp",
        "WriteBody",
        "DraftRequest",
    ] {
        let props = schemas[name]["properties"].as_object().unwrap();
        for member in props.keys() {
            for banned in [
                "password",
                "secret",
                "totp",
                "otp",
                "passkey",
                "credential",
                "hash",
                "pin",
            ] {
                let allowed = member == "client_secret_ref";
                assert!(allowed || !member.contains(banned), "{name}.{member}");
            }
        }
    }
    let result = schemas["WriteResult"]["properties"].as_object().unwrap();
    assert!(result.contains_key("client_secret"));
}
