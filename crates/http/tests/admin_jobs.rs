//! Bulk jobs over HTTP (TN-125, X20): the envelope's AIS signs the job, each item is its own
//! write under its own AIS, a sequential job stops at the first failure with 424 for the rest,
//! and the per-item file names each Exercise or refusal.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod admin;

use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use admin::{HIDDEN_KEY, Harness, REALM, ais, ais_over, read, realm_domain, send};

const JOBS: &str = "/admin/v1/realms/acme/jobs";

fn post(path: &str, nonce: [u8; 16], body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("idempotency-key", b64url_encode(&nonce))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn settle(h: &Harness, id: &str) -> Value {
    let token = h.token("jobs", "access-admin:realm:acme", &["realm.read"], 600_000);
    let router = h.router();
    for _ in 0..10_000 {
        let (_, body) = send(&router, read(&format!("{JOBS}/{id}"), &token)).await;
        if body["status"] != "running" {
            return body;
        }
        tokio::task::yield_now().await;
    }
    panic!("the job did not finish")
}

// TN-125, TN-110, X20: a sequential job runs each item as its own Exercise; after a refused
// item the rest are failed dependencies (424); the envelope counts each kind and the per-item
// file names the Exercise or the problem
#[tokio::test]
async fn a_sequential_job_commits_items_one_by_one_and_stops_at_a_failure() {
    let h = Harness::new();
    let router = h.router();
    let own = h.instance(realm_domain());
    let token = h.token("t", "access-admin:realm:acme", &["realm.read"], 600_000);
    let item = |n: u8, key: &str| {
        json!({"operation": "suspendAccount", "key": key,
               "body": {"ais": ais(&own, realm_domain(), [n; 16], h.now())}})
    };
    let body = json!({"mode": "sequential",
                      "operations": [item(1, "a1"), item(2, HIDDEN_KEY), item(3, "a3")]});
    // TN-110: the envelope's AIS signs the job digest the draft names
    let (r, drafted) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri(format!("/admin/v1/realms/{REALM}/intents"))
            .header("authorization", format!("DPoP {token}"))
            .header(
                "dpop",
                admin::proof("POST", &format!("/admin/v1/realms/{REALM}/intents")),
            )
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"operation": "createJob", "body": body}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "{drafted}");
    let digest: [u8; 32] = b64url_decode(drafted["intent_digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut wrong = body.clone();
    wrong["ais"] = json!(ais(&own, realm_domain(), [9; 16], h.now()));
    let (r, refused) = send(&router, post(JOBS, [9; 16], &wrong)).await;
    assert_eq!(
        (r.status(), refused["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("job-intent-mismatch"))
    );
    assert_eq!(h.position(), 0, "a refused job runs nothing");
    let mut envelope = body.clone();
    envelope["ais"] = json!(ais_over(
        &own,
        realm_domain(),
        [10; 16],
        h.now(),
        Mode::Commit,
        Digest(digest)
    ));
    let (r, job) = send(&router, post(JOBS, [10; 16], &envelope)).await;
    assert_eq!(r.status(), StatusCode::ACCEPTED, "{job}");
    let id = job["job_id"].as_str().unwrap().to_owned();
    let done = settle(&h, &id).await;
    assert_eq!(done["status"], "partial");
    assert_eq!(
        (&done["committed"], &done["failed"]),
        (&json!(1), &json!(2))
    );
    assert_eq!(h.position(), 1, "one Exercise per committed item");
    let (_, items) = send(&router, read(&format!("{JOBS}/{id}/items"), &token)).await;
    let items = items["items"].as_array().unwrap();
    assert_eq!(items[0]["status"], "committed");
    assert!(items[0]["exercise_id"].is_string());
    assert_eq!(
        (&items[1]["status"], &items[1]["problem"]),
        (&json!("rejected"), &json!("not_found"))
    );
    assert_eq!(
        (&items[2]["status"], &items[2]["http_status"]),
        (&json!("failed_dependency"), &json!(424))
    );
}

// TN-125: in a parallel job the items are independent; an item whose AIS is another
// Instance's is refused on its own line and the others commit
#[tokio::test]
async fn a_parallel_job_keeps_going_and_refuses_a_foreign_item_ais() {
    let h = Harness::new();
    let router = h.router();
    let own = h.instance(realm_domain());
    let other = h.instance(realm_domain());
    let body = json!({"mode": "parallel", "operations": [
        {"operation": "suspendAccount", "key": "a1",
         "body": {"ais": ais(&other, realm_domain(), [1; 16], h.now())}},
        {"operation": "suspendAccount", "key": "a2",
         "body": {"ais": ais(&own, realm_domain(), [2; 16], h.now())}},
    ]});
    let token = h.token("t", "access-admin:realm:acme", &["realm.read"], 600_000);
    let path = format!("/admin/v1/realms/{REALM}/intents");
    let (_, drafted) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri(&path)
            .header("authorization", format!("DPoP {token}"))
            .header("dpop", admin::proof("POST", &path))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"operation": "createJob", "body": body}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    let digest: [u8; 32] = b64url_decode(drafted["intent_digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut envelope = body;
    envelope["ais"] = json!(ais_over(
        &own,
        realm_domain(),
        [5; 16],
        h.now(),
        Mode::Commit,
        Digest(digest)
    ));
    let (r, job) = send(&router, post(JOBS, [5; 16], &envelope)).await;
    assert_eq!(r.status(), StatusCode::ACCEPTED, "{job}");
    let done = settle(&h, job["job_id"].as_str().unwrap()).await;
    assert_eq!(done["status"], "partial");
    assert_eq!(
        (&done["committed"], &done["failed"]),
        (&json!(1), &json!(1))
    );
    let (_, items) = send(
        &router,
        read(
            &format!("{JOBS}/{}/items", job["job_id"].as_str().unwrap()),
            &token,
        ),
    )
    .await;
    assert_eq!(items["items"][0]["problem"], "ais-rejected");
    assert_eq!(items["items"][1]["status"], "committed");
}
