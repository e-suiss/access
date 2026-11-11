//! Access reviews through the console's BFF against the real admin surface, sequencer and store
//! (OP-157 m.3 (w), m.6 (a), OP-153 m.3 (gg), IDP-39 (3), LFP-18, Ek B 5563, 5564, 5565): a
//! campaign is scheduled and read, its items are the signed-in reader's own lineage, a keep is
//! accepted only over its own digest and moves no authority.

use access_http::adp::payload::canonical_authority_to_json;
use access_internal_api::idp::IdpAction;
use access_kernel::meta::{self as kmeta, kind};

use super::writes::{canonical, exercise_of, role};
use super::*;

const REVIEWS: &str = "/admin/v1/realms/acme/reviews";

async fn keep(c: &Console, grant: &str, digest: Digest) -> (StatusCode, serde_json::Value) {
    let n = access_crypto::random::bytes::<16>().unwrap();
    let ais = c
        .browser
        .ais(c.domain, &n, digest, Mode::Commit, c.idp_anchor());
    let (r, out) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                &format!("/console/api/proxy/admin/realms/acme/reviews/q4/items/{grant}/keep"),
                "x",
            )
            .header("x-access-ais", ais)
            .header("idempotency-key", b64url_encode(&n))
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    (
        r.status(),
        serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null),
    )
}

async fn kept(c: &Console) -> usize {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let rows = t.list_audit(500).await.unwrap();
    t.commit().await.unwrap();
    rows.iter()
        .filter(|r| r.event_type == "review.kept")
        .count()
}

// IDP-39 (3), LFP-18, OP-157 m.3 (w), m.6 (a), (f), OP-153 m.3 (gg), Ek B 5563, 5564, 5565
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_campaign_is_served_for_the_signed_in_reviewer_and_a_keep_moves_no_authority() {
    let c = console("mgmt-review", true).await;
    let w = c
        .rest_write(
            &Method::POST,
            REVIEWS,
            ("scheduleReview", None),
            serde_json::json!({ "name": "q4", "period_days": 90, "scope": "manager_team" }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    assert!(w.body["exercise_id"].is_string(), "{}", w.body);
    let again = c
        .rest_write(
            &Method::POST,
            REVIEWS,
            ("scheduleReview", None),
            serde_json::json!({ "name": "q4", "period_days": 30, "scope": "manager_team" }),
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    let one = c.admin_get(&format!("{REVIEWS}/q4")).await;
    assert_eq!(one.status, StatusCode::OK, "{}", one.body);
    assert_eq!(one.body["status"], "live", "{}", one.body);

    let idp = kmeta::object_id(&c.domain, kind::ANCHOR, IDP_ANCHOR);
    let issue = serde_json::json!({ "grant_issue": {
        "basis": { "anchor": b64url_encode(&idp.0) },
        "holder": { "party": b64url_encode(&access_kernel::model::Id([0x0e; 16]).0) },
        "authority": canonical_authority_to_json(&canonical(role(&[IdpAction::AccountSuspend]))).unwrap(),
    } });
    let issued = c.meta_write("grant_issue", issue, c.idp_anchor()).await;
    assert_eq!(issued.body["decision"], true, "{}", issued.body);
    let grant = b64url_encode(&kmeta::object_id(&exercise_of(&issued), kind::GRANT, 0).0);

    // IDP-39 (3)
    let items = c.admin_get(&format!("{REVIEWS}/q4/items")).await;
    assert_eq!(items.status, StatusCode::OK, "{}", items.body);
    let list = items.body["items"].as_array().unwrap();
    let item = list
        .iter()
        .find(|i| i["grant"] == grant.as_str())
        .unwrap_or_else(|| panic!("{}", items.body));
    assert_eq!(item["remove"]["operation"], "revokeGrant");
    assert_eq!(
        item["remove"]["basis"]["anchor"],
        b64url_encode(&idp.0),
        "{item}"
    );
    let none = c.admin_get(&format!("{REVIEWS}/q9/items")).await;
    assert_eq!(none.body["items"], serde_json::json!([]), "{}", none.body);

    // OP-157 m.6 (a), LFP-18
    let before = c.w.domains.head(c.domain).await.unwrap().0;
    let (status, body) = keep(&c, &grant, Digest([0x11; 32])).await;
    assert_ne!(status, StatusCode::OK, "another digest: {body}");
    assert_eq!(kept(&c).await, 0);
    let target = format!("{REVIEWS}/q4/items/{grant}/keep");
    let done = c
        .rest_write(
            &Method::POST,
            &target,
            ("keepReviewItem", Some(&format!("q4:{grant}"))),
            serde_json::json!({}),
            None,
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    assert_eq!(done.body["kept"], true, "{}", done.body);
    assert_eq!(kept(&c).await, 1);
    assert_eq!(c.w.domains.head(c.domain).await.unwrap().0, before);

    let closed = c
        .rest_write(
            &Method::POST,
            &format!("{REVIEWS}/q4/close"),
            ("closeReview", Some("q4")),
            serde_json::json!({}),
            None,
        )
        .await;
    assert!(closed.status.is_success(), "{}", closed.body);
    let after = c.admin_get(&format!("{REVIEWS}/q4")).await;
    assert_eq!(after.body["status"], "closed", "{}", after.body);
}
