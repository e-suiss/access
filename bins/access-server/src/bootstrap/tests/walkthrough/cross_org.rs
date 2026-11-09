//! Another organization (§11.19, §9.15A.3, §11.11.6): the other organization's Party acts
//! through its own Instance; its own `IdP`'s identity assertion, pinned by the realm's
//! `actor-binding` Acceptance, carries identity only; authority in this domain comes only from
//! this domain's root, as a local extensional Grant to that Party (cross-domain delegation);
//! and when that Grant is revoked the same assertion gets nothing.

use axum::http::StatusCode;
use serde_json::json;

use super::super::exchange::{IDP, ISSUER, Realm, UPSTREAM, act_chain, claims_of, idp_jwt};
use super::*;

// §11.19, §9.15A.3, §11.11.6, EI-6, E26, AG-29, MD-18, PI-13, OP-154 m.3 (ff), Ek B 4455, 4457
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_organizations_identity_is_only_identity_and_authority_is_this_domains_grant() {
    let r = Realm::open("walk-cross-org").await;
    let now_s = now_ms() / 1000;
    let jag = |jti: &str| {
        idp_jwt(
            &r.idp,
            "oauth-id-jag+jwt",
            &json!({
                "iss": IDP, "aud": ISSUER, "sub": "partner-7781", "client_id": r.client,
                "jti": jti, "iat": now_s, "exp": now_s + 240, "resource": UPSTREAM,
                "email": "someone@partner.example",
            }),
        )
    };
    // EI-6, §11.11.6
    let (status, body) = r.bearer(jag("x-1"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // §9.15A.3
    let (status, body) = r
        .bearer(jag("x-2"), Some((&r.stranger, r.g2, Capacity::Own)))
        .await;
    assert_eq!(body["error"], "invalid_grant", "{status} {body}");
    let (status, body) = r
        .bearer(
            jag("x-3"),
            Some((&r.stranger, r.stranger_own, Capacity::Own)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let c = claims_of(body["access_token"].as_str().unwrap());
    assert_eq!(c["aud"], UPSTREAM);
    assert!(act_chain(&c).is_empty(), "{c}");
    // E26
    let text = c.to_string();
    assert!(
        !text.contains("someone@partner.example") && !text.contains("partner-7781"),
        "{text}"
    );

    // §9.15A.3
    super::root_revoke(&r.w, r.domain, r.stranger_own.grant, r.stranger.party).await;
    let (_, body) = r
        .bearer(
            jag("x-4"),
            Some((&r.stranger, r.stranger_own, Capacity::Own)),
        )
        .await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
    r.w.domains.release().await;
}
