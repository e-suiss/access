//! The DCR backward-compatibility profile on the real server path (OP-154 m.3 (j), §11.4.5
//! #31-35, OP-153 m.3 (gg)): the policy is a REST write compiled to `idp.client.dcr_policy` or
//! `dcr_policy_tighten`; `/register` takes only an initial access token the policy names, refuses
//! what RFC 7591 lets a client ask that Access does not take, counts registrations, and a
//! tightened policy retires what it no longer admits.

use super::*;

const TOKEN: &str = "initial-access-token-one";
const OTHER: &str = "initial-access-token-two";

fn digest(tx: &str) -> String {
    b64url_encode(&suiss_crypto::digest::sha256(tx.as_bytes()))
}

async fn policy(c: &Console, enabled: bool, tokens: &[&str]) -> super::writes::Written {
    c.rest_write(
        &Method::PUT,
        "/admin/v1/realms/acme/settings/dcr-policy",
        ("putDcrPolicy", None),
        serde_json::json!({
            "enabled": enabled,
            "domains": ["app.example"],
            "initial_access_tokens": tokens.iter().map(|tx| digest(tx)).collect::<Vec<_>>(),
        }),
        None,
    )
    .await
}

async fn register(
    c: &Console,
    token: Option<&str>,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::post("/realms/acme/register")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(iat) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {iat}"));
    }
    let (reply, bytes) = send(&c.oauth, req.body(Body::from(body.to_string())).unwrap()).await;
    (
        reply.status(),
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn app(redirect: &str) -> serde_json::Value {
    serde_json::json!({ "client_name": "Legacy App", "redirect_uris": [redirect] })
}

async fn authorize(c: &Console, client_id: &str) -> Response<Body> {
    let mut q = String::from("response_type=code&client_id=");
    access_identity_oauth::domain::issuer::form_encode(client_id, &mut q);
    q.push_str("&redirect_uri=");
    access_identity_oauth::domain::issuer::form_encode("https://app.example/cb", &mut q);
    q.push_str("&state=status&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");
    send(
        &c.oauth,
        Request::get(format!("/realms/acme/authorize?{q}"))
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .0
}

// §10.1.2, §11.4.5 #31-35, OP-154 m.3 (j), MD-14, Ek B 4165
#[tokio::test]
async fn dcr_is_off_until_decided_and_takes_only_its_initial_access_tokens() {
    let c = console("mgmt-dcr", true).await;
    // §10.1.2: off by default
    let (status, _) = register(&c, Some(TOKEN), &app("https://app.example/cb")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let w = policy(&c, true, &[TOKEN, OTHER]).await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);

    let (status, body) = register(&c, None, &app("https://app.example/cb")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body) =
        register(&c, Some("not-one-of-them"), &app("https://app.example/cb")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // §11.4.5 #32
    let (status, body) = register(&c, Some(TOKEN), &app("https://*.app.example/cb")).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_redirect_uri"))
    );
    // §11.4.5 #34, SEP-837: an explicit error, not a silent refusal
    let (status, body) = register(&c, Some(TOKEN), &app("http://127.0.0.1:4242/cb")).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_redirect_uri"))
    );
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("native")
    );
    let mut secret = app("https://app.example/cb");
    secret["token_endpoint_auth_method"] = serde_json::json!("client_secret_basic");
    let (status, body) = register(&c, Some(TOKEN), &secret).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_client_metadata"))
    );
    // §11.4.5 #35: a host outside the policy
    let (status, _) = register(&c, Some(TOKEN), &app("https://elsewhere.example/cb")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, first) = register(&c, Some(TOKEN), &app("https://app.example/cb")).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let client = first["client_id"].as_str().unwrap().to_owned();
    assert!(client.starts_with("dcr_"));
    // §11.4.5 #33
    assert_eq!(first["issuer"], "https://access.test/realms/acme");
    assert!(first.get("client_secret").is_none());
    let (status, second) = register(&c, Some(OTHER), &app("https://app.example/cb")).await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    let kept = second["client_id"].as_str().unwrap().to_owned();
    // OP-154 m.8 (h): a client the realm did not register needs a registered resource and the Approval Surface
    let reply = authorize(&c, &client).await;
    assert_eq!(reply.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&reply).contains("error=invalid_target"),
        "AG-8: it names a registered resource, {}",
        location(&reply)
    );

    // §11.4.5 #31: ten registrations an hour from one prefix
    let mut last = StatusCode::CREATED;
    for _ in 0..10 {
        last = register(&c, Some(TOKEN), &app("https://app.example/cb"))
            .await
            .0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);

    // §11.4.5 #35: tightening retires what the policy no longer admits
    let w = policy(&c, true, &[OTHER]).await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let reply = authorize(&c, &client).await;
    assert_ne!(
        reply.status(),
        StatusCode::SEE_OTHER,
        "the retired client is unknown"
    );
    let reply = authorize(&c, &kept).await;
    assert_eq!(
        reply.status(),
        StatusCode::SEE_OTHER,
        "the client of a kept token stays"
    );
    let mut tx =
        access_store::identity::TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
            .await
            .unwrap();
    assert!(tx.dcr_client(&client).await.unwrap().is_none());
    assert!(tx.dcr_client(&kept).await.unwrap().is_some());
    tx.commit().await.unwrap();
    let w = policy(&c, false, &[]).await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let (status, _) = register(&c, Some(OTHER), &app("https://app.example/cb")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    c.w.domains.release().await;
}
