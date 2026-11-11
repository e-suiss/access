//! The realm's `rate_limit_rps` on the real server path (OP-35, OP-158 m.3 (v), TN-24, B3, B19,
//! MD-8): `putRateLimit` commits `idp.realm.rate_limit`, and the realm's identity routes draw
//! from that rate in layer B; sign-out and revocation never draw, and a counter that cannot
//! answer refuses.

use std::sync::Arc;

use access_http::quota::{RequestQuotas, Taken, Unavailable, meter};

use super::*;

fn fixed() -> u64 {
    1_800_000_000_000
}

async fn status_of(router: &axum::Router, method: Method, path: &str) -> (StatusCode, String) {
    let (r, body) = send(
        router,
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let retry = r
        .headers()
        .get(header::RETRY_AFTER)
        .map(|v| v.to_str().unwrap().to_owned());
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    (
        r.status(),
        format!(
            "{} {}",
            v["type"].as_str().unwrap_or(""),
            retry.unwrap_or_default()
        ),
    )
}

// OP-35, OP-158 m.3 (v), TN-24, B3, B19
#[tokio::test]
async fn a_realm_rate_limit_is_committed_and_bounds_its_identity_routes() {
    let c = console("rate-limit", false).await;
    let set = c
        .put_setting(
            "rate-limit",
            "putRateLimit",
            serde_json::json!({ "rps": 1 }),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{}", set.body);
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert_eq!(
        access_store::quota::rate_limit(&mut t).await.unwrap(),
        Some(1)
    );
    t.commit().await.unwrap();

    let routes = meter(
        c.oauth.clone(),
        Arc::new(crate::quota::PgRequestQuotas::new(
            c.w.db.router.clone(),
            c.w.db.app.clone(),
            fixed,
        )),
    );
    let authorize = "/realms/acme/authorize?client_id=x";
    for _ in 0..access_http::quota::BURST_S {
        let (s, _) = status_of(&routes, Method::GET, authorize).await;
        assert_ne!(s, StatusCode::TOO_MANY_REQUESTS);
    }
    let (s, why) = status_of(&routes, Method::GET, authorize).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(why, "urn:suiss:access:problem:quota-exceeded 1");
    for _ in 0..3 {
        let (s, _) = status_of(&routes, Method::POST, "/realms/acme/revoke").await;
        assert_ne!(s, StatusCode::TOO_MANY_REQUESTS, "revocation never draws");
        let (s, _) = status_of(&routes, Method::GET, "/realms/acme/end-session").await;
        assert_ne!(s, StatusCode::TOO_MANY_REQUESTS, "logout never draws");
    }

    // §12.5.4, TN-127
    let (status, view, _) = c.rest_read("/admin/v1/realms/acme/rate-limits").await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(
        (view["rate_limit_rps"].as_u64(), view["default"].as_bool()),
        (Some(1), Some(false))
    );
    let buckets = view["usage"]["buckets"].as_array().unwrap();
    let realm = buckets
        .iter()
        .find(|b| b["name"] == access_http::quota::BUCKET)
        .unwrap();
    assert_eq!(realm["now_percent"], 100);
    assert_eq!(realm["above_threshold"], true);
    assert!(
        view["usage"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| { e["kind"] == "quota-exceeded" && e["last_hour"].as_u64() >= Some(1) })
    );
    assert_ne!(view["usage"]["top_consumers"].as_array().unwrap().len(), 0);
    assert_eq!(view["usage"]["threshold_percent"], 80);

    let zero = c
        .put_setting(
            "rate-limit",
            "putRateLimit",
            serde_json::json!({ "rps": 0 }),
        )
        .await;
    assert_eq!(zero.status, StatusCode::BAD_REQUEST, "{}", zero.body);
}

/// Counters that cannot answer.
struct Down;

impl RequestQuotas for Down {
    fn take(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Taken, Unavailable>> + Send {
        std::future::ready(Err(Unavailable))
    }
}

// MD-8
#[tokio::test]
async fn a_request_counter_that_cannot_answer_refuses() {
    let c = console("rate-limit-down", false).await;
    let routes = meter(c.oauth.clone(), Arc::new(Down));
    let (s, _) = status_of(&routes, Method::GET, "/realms/acme/authorize?client_id=x").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (s, _) = status_of(&routes, Method::POST, "/realms/acme/revoke").await;
    assert_ne!(
        s,
        StatusCode::SERVICE_UNAVAILABLE,
        "revocation needs no counter"
    );
}

// GHSA-84jc-3hj2-hwc7, SA-27
#[tokio::test]
async fn an_unauthenticated_request_is_refused_before_its_body_is_parsed() {
    let c = console("auth-before-body", false).await;
    let garbage = "{\"rps\": [[[[[[[[[[[[[[[[";
    let (r, body) = send(
        &c.management,
        Request::put("/admin/v1/realms/acme/settings/rate-limit")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(garbage))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let adp = access_http::adp::adapters::router(
        access_http::adp::app::Service::new(c.w.domains.clone(), 64 * 1024),
        access_http::adp::adapters::Discovery {
            issuer: String::from("https://access.test"),
        },
    );
    let (r, body) = send(
        &adp,
        Request::post("/access/v1/evaluation")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(garbage))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(String::from_utf8_lossy(&body).contains("pep-unauthenticated"));
}
