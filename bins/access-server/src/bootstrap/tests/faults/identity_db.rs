//! Identity database unreachable: introspection answers `active=false`, refresh 503 with
//! `Retry-After` (§16.7.1, OP-45).

use axum::http::StatusCode;

use super::super::management::send;
use super::{form, identity};

// FO-18, OP-45, EP-1, EP-2, EP-3, G50, MD-8, §16.7.1, §17.7.2, Ek B 6002, 6003, 6005
#[tokio::test(flavor = "multi_thread")]
async fn fo_18_with_the_identity_database_cut_off_nothing_is_issued_and_introspection_is_inactive()
{
    let (w, oauth) = identity("fo-18-identity-db").await;
    let refresh = "grant_type=refresh_token&refresh_token=rt-unknown&client_id=cli_none";
    let (r, body) = send(&oauth, form("/token", refresh, None)).await;
    assert_ne!(
        r.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        String::from_utf8_lossy(&body)
    );

    access_store::testing::refuse_connections(&w.db, true)
        .await
        .unwrap();
    // G50, EP-2: 503 + Retry-After, never invalid_grant
    let (r, body) = send(&oauth, form("/token", refresh, None)).await;
    let text = String::from_utf8_lossy(&body).into_owned();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "{text}");
    assert!(r.headers().get("retry-after").is_some());
    assert!(!text.contains("invalid_grant"), "{text}");
    // EP-3: active=false, never 503
    let (r, body) = send(
        &oauth,
        form(
            "/introspect",
            "token=at-any",
            Some("Basic Y2xpOnNlY3JldA=="),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v, serde_json::json!({ "active": false }));
    // OP-45 rule 4: no revocation is taken while it cannot be kept
    let (r, _) = send(
        &oauth,
        form("/revoke", "token=rt-any", Some("Basic Y2xpOnNlY3JldA==")),
    )
    .await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(r.headers().get("retry-after").is_some());

    access_store::testing::refuse_connections(&w.db, false)
        .await
        .unwrap();
}
