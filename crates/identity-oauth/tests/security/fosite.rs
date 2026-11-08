//! The Fosite error-class regression corpus (§10.4.7, MD-1): one table per class of bug that
//! OAuth server libraries have shipped, each row run against the real authorization server.

use access_identity_oauth::app::oauth::Reply;
use access_identity_oauth::domain::request::Params;
use access_kernel::json::b64url_encode;
use aws_lc_rs::digest::{SHA256, digest};

use crate::support::{
    At, CB, CHALLENGE, Cluster, JWT_BEARER, NATIVE, VERIFIER, basic, body, error, location,
    new_key, now, query, query_opt, sign,
};

fn s256(verifier: &str) -> String {
    b64url_encode(digest(&SHA256, verifier.as_bytes()).as_ref())
}

fn is_problem(r: &Reply) -> bool {
    matches!(r, Reply::Problem { status: 400, .. })
}

// IDP-7, must-never #16, TN-104, X41, AG-6, §11.4.5 #3, §17.9.6, OP-146 m.5 (h): a redirect URI
// that is not byte-identical to a registered one is shown as a problem, never followed, whatever
// the spelling trick; loopback frees only the port
#[tokio::test]
async fn redirect_uri_tricks_are_never_followed() {
    let c = Cluster::new(&["fos-a"]).await;
    let a = c.at(0);
    let cookie = Some(a.f.cookie.as_str());
    for (presented, class) in [
        ("https://shop.example/cb/", "trailing slash"),
        ("https://shop.example/cb.evil.example", "prefix match"),
        ("https://shop.example/cbx", "prefix match"),
        ("https://shop.example/cb/../cb", "dot segments"),
        ("https://shop.example/./cb", "dot segments"),
        ("https://shop.example/cb?x=1", "added query"),
        ("https://shop.example/cb#frag", "fragment"),
        ("https://shop.example/cb%2F", "percent-encoded slash"),
        ("https://shop.example/%63b", "percent-encoded path"),
        ("https://shop.example/CB", "path case"),
        ("HTTPS://shop.example/cb", "scheme case"),
        ("https://SHOP.example/cb", "host case"),
        ("https://shop.example:443/cb", "default port"),
        ("https://shop.example./cb", "trailing dot host"),
        ("https://shop.example@evil.example/cb", "user info"),
        (
            "https://evil.example/cb?https://shop.example/cb",
            "embedded registered URI",
        ),
        ("//shop.example/cb", "scheme-relative"),
        ("http://shop.example/cb", "scheme downgrade"),
        ("https://shop.example/cb\n", "trailing control character"),
        (" https://shop.example/cb", "leading space"),
        ("https://*.example/cb", "wildcard"),
        ("https://shop.example/*", "wildcard path"),
        ("http://127.0.0.1:61234/native/x", "loopback path"),
        ("http://127.0.0.1:61234/native?x=1", "loopback query"),
        ("http://127.0.0.1.evil.example/native", "loopback lookalike"),
        ("http://127.0.0.2:61234/native", "other loopback address"),
        ("https://127.0.0.1:61234/native", "loopback scheme"),
        ("http://127.0.0.1:0x10/native", "loopback port spelling"),
        ("http://127.0.0.1:123456/native", "loopback port length"),
        ("http://localhost:61234/native", "loopback host swap"),
    ] {
        let r = a.authorize(&[("redirect_uri", presented)], cookie).await;
        assert!(is_problem(&r), "{class}: {presented}: {r:?}");
    }
    for presented in [CB, NATIVE, "http://127.0.0.1:61234/native"] {
        let to = location(&a.authorize(&[("redirect_uri", presented)], cookie).await);
        assert!(to.starts_with(&format!("{presented}?code=")), "{to}");
    }
}

// TN-104, X41, RFC 6749 §4.1.2.1, RFC 9126 §4: nothing is redirected before the client and
// redirect URI are both known good, whatever else is wrong with the request
#[tokio::test]
async fn errors_never_open_a_redirect() {
    let c = Cluster::new(&["fos-b"]).await;
    let a = c.at(0);
    let cookie = Some(a.f.cookie.as_str());
    for pairs in [
        vec![("client_id", "")],
        vec![("client_id", "cli_00000000000000000000000zzz")],
        vec![
            ("client_id", "cli_00000000000000000000000zzz"),
            ("redirect_uri", "https://evil.example/cb"),
        ],
        vec![("redirect_uri", "")],
        vec![
            ("redirect_uri", "https://evil.example/cb"),
            ("scope", "admin"),
        ],
        vec![
            ("redirect_uri", "https://evil.example/cb"),
            ("response_type", "token"),
        ],
        vec![
            ("redirect_uri", "https://evil.example/cb"),
            ("prompt", "none"),
        ],
        vec![("request_uri", "https://evil.example/request.jwt")],
        vec![(
            "request_uri",
            "urn:ietf:params:oauth:request_uri:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )],
    ] {
        let r = a.authorize(&pairs, cookie).await;
        assert!(is_problem(&r), "{pairs:?}: {r:?}");
        let signed_out = a.authorize(&pairs, None).await;
        assert!(is_problem(&signed_out), "{pairs:?}: {signed_out:?}");
    }
    // RFC 6749 §3.1: a repeated parameter is malformed before anything is looked up
    assert!(Params::parse("client_id=a&client_id=b").is_err());
    assert!(Params::parse("redirect_uri=a&redirect_uri=b").is_err());
    // §10.4.6: the post-logout redirect URI is exact too
    for uri in [
        "https://shop.example/bye/",
        "https://evil.example/bye",
        "https://shop.example/byeX",
    ] {
        let r = a
            .end_session(
                &[
                    ("client_id", &a.f.public),
                    ("post_logout_redirect_uri", uri),
                ],
                None,
            )
            .await;
        assert!(is_problem(&r), "{uri}: {r:?}");
    }
}

// IDP-7, TN-34, TN-101, §10.4.1, RFC 9700 §2.1.1, RFC 7636 §4.3, Kanidm GHSA-hh34: past the
// redirect URI every malformed request goes back with error, state and iss; there is no
// implicit or hybrid response, no plain or absent PKCE method, no other response mode, no
// request object and no unknown scope
#[tokio::test]
async fn authorization_request_downgrades_are_refused() {
    let c = Cluster::new(&["fos-c"]).await;
    let a = c.at(0);
    let cookie = Some(a.f.cookie.as_str());
    let long_state = "s".repeat(1025);
    for (pairs, expected) in [
        (vec![("code_challenge", "")], "invalid_request"),
        (vec![("code_challenge_method", "")], "invalid_request"),
        (vec![("code_challenge_method", "plain")], "invalid_request"),
        (vec![("code_challenge_method", "s256")], "invalid_request"),
        (
            vec![
                ("code_challenge_method", "plain"),
                ("code_challenge", VERIFIER),
            ],
            "invalid_request",
        ),
        (
            vec![("code_challenge", &CHALLENGE[..42])],
            "invalid_request",
        ),
        (
            vec![(
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMx",
            )],
            "invalid_request",
        ),
        (
            vec![(
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM",
            )],
            "invalid_request",
        ),
        (vec![("response_type", "")], "invalid_request"),
        (
            vec![("response_type", "token")],
            "unsupported_response_type",
        ),
        (
            vec![("response_type", "id_token")],
            "unsupported_response_type",
        ),
        (
            vec![("response_type", "code id_token")],
            "unsupported_response_type",
        ),
        (
            vec![("response_type", "code token")],
            "unsupported_response_type",
        ),
        (
            vec![("response_type", "id_token token")],
            "unsupported_response_type",
        ),
        (vec![("response_type", "none")], "unsupported_response_type"),
        (vec![("response_type", "CODE")], "unsupported_response_type"),
        (vec![("response_mode", "fragment")], "invalid_request"),
        (vec![("response_mode", "form_post")], "invalid_request"),
        (vec![("response_mode", "query.jwt")], "invalid_request"),
        (vec![("response_mode", "jwt")], "invalid_request"),
        (vec![("response_mode", "web_message")], "invalid_request"),
        (
            vec![("request", "eyJhbGciOiJub25lIn0.e30.")],
            "request_not_supported",
        ),
        (vec![("scope", "openid offline_access")], "invalid_scope"),
        (vec![("scope", "openid email profile")], "invalid_scope"),
        (vec![("scope", "admin")], "invalid_scope"),
        (vec![("prompt", "none login")], "invalid_request"),
        (vec![("prompt", "consent")], "invalid_request"),
        (vec![("prompt", "select_account")], "invalid_request"),
        (vec![("max_age", "-1")], "invalid_request"),
        (vec![("max_age", "1e3")], "invalid_request"),
        (vec![("resource", "https://api.example")], "invalid_target"),
        (
            vec![("resource", "https://fos-c.id.test/")],
            "invalid_target",
        ),
        (vec![("dpop_jkt", "not-a-thumbprint")], "invalid_request"),
        (vec![("state", long_state.as_str())], "invalid_request"),
    ] {
        let to = location(&a.authorize(&pairs, cookie).await);
        assert!(to.starts_with(&format!("{CB}?error=")), "{pairs:?}: {to}");
        assert_eq!(query(&to, "error"), expected, "{pairs:?}");
        assert_eq!(query(&to, "iss"), a.issuer(), "{pairs:?}");
        assert!(query_opt(&to, "code").is_none(), "{pairs:?}");
    }
}

// RFC 9207 §2, TN-11, RFC 6749 §4.1.2: state comes back exactly as sent, encoded once; iss is
// this realm's issuer on success and on error, exactly once; no state is invented
#[tokio::test]
async fn state_and_iss_resist_mix_up() {
    let c = Cluster::new(&["fos-d"]).await;
    let a = c.at(0);
    let cookie = Some(a.f.cookie.as_str());
    for state in [
        "a&b=c",
        "x y+z",
        "%41",
        "ü",
        "&iss=https://evil.example",
        "a#b",
    ] {
        let to = location(&a.authorize(&[("state", state)], cookie).await);
        assert_eq!(query(&to, "state"), state, "{to}");
        assert_eq!(query(&to, "iss"), a.issuer(), "{to}");
        assert_eq!(to.matches("iss=").count(), 1, "{to}");
        assert!(!to.contains('#'), "{to}");
        let err = location(
            &a.authorize(&[("state", state), ("scope", "nope")], cookie)
                .await,
        );
        assert_eq!(query(&err, "state"), state, "{err}");
        assert_eq!(query(&err, "iss"), a.issuer(), "{err}");
        assert_eq!(err.matches("iss=").count(), 1, "{err}");
    }
    let to = location(&a.authorize(&[("state", "")], cookie).await);
    assert!(query_opt(&to, "state").is_none(), "{to}");
    let to = location(
        &a.authorize(&[("state", ""), ("prompt", "none")], None)
            .await,
    );
    assert!(query_opt(&to, "state").is_none(), "{to}");
    assert_eq!(query(&to, "iss"), a.issuer());
}

// IDP-7, CR-39, RFC 7636 §4.1 and §4.6, Kanidm GHSA-hh34, RFC 6749 §4.1.3: the exchange
// checks the verifier's form as well as its hash, the exact redirect URI and the client; a
// short, long or ill-formed verifier is refused even when its hash matches
#[tokio::test]
async fn code_exchange_downgrades_are_refused() {
    // GHSA-hh34-7jqq-3f73
    let c = Cluster::new(&["fos-e"]).await;
    let a = c.at(0);
    let cookie = Some(a.f.cookie.as_str());
    let short = "a".repeat(42);
    let long = "a".repeat(129);
    let slashed = format!("{}/", "a".repeat(43));
    for (verifier, class) in [
        (short.as_str(), "42 characters"),
        (long.as_str(), "129 characters"),
        (slashed.as_str(), "outside the unreserved set"),
    ] {
        let challenge = s256(verifier);
        let to = location(&a.authorize(&[("code_challenge", &challenge)], cookie).await);
        let code = query(&to, "code");
        let r = a
            .token(
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", &a.f.public),
                    ("code", &code),
                    ("redirect_uri", CB),
                    ("code_verifier", verifier),
                ],
                None,
            )
            .await;
        assert_eq!(error(&r), "invalid_grant", "{class}");
    }
    let loopback = "http://127.0.0.1:61234/native";
    for (change, class) in [
        (("code_verifier", ""), "no verifier"),
        (("code_verifier", CHALLENGE), "challenge as verifier"),
        (("code_verifier", &VERIFIER[..42]), "truncated verifier"),
        (("redirect_uri", ""), "no redirect URI"),
        (
            ("redirect_uri", "https://shop.example/cb/"),
            "other redirect URI",
        ),
        (("redirect_uri", NATIVE), "other registered redirect URI"),
        (
            ("code", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "unknown code",
        ),
        (("code", "x"), "malformed code"),
    ] {
        let code = a.code(&a.f.public).await;
        let mut p = vec![
            ("grant_type", "authorization_code"),
            ("client_id", a.f.public.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", CB),
            ("code_verifier", VERIFIER),
        ];
        p.retain(|(k, _)| *k != change.0);
        if !change.1.is_empty() {
            p.push(change);
        }
        assert_eq!(error(&a.token(&p, None).await), "invalid_grant", "{class}");
    }
    let to = location(&a.authorize(&[("redirect_uri", loopback)], cookie).await);
    let code = query(&to, "code");
    let other_port = [
        ("grant_type", "authorization_code"),
        ("client_id", a.f.public.as_str()),
        ("code", code.as_str()),
        ("redirect_uri", "http://127.0.0.1:61235/native"),
        ("code_verifier", VERIFIER),
    ];
    assert_eq!(error(&a.token(&other_port, None).await), "invalid_grant");
    for (grant_type, expected) in [
        ("", "invalid_request"),
        ("password", "unsupported_grant_type"),
        ("implicit", "unsupported_grant_type"),
        // §10.4.1: only a confidential client, and only for authority
        ("client_credentials", "unauthorized_client"),
        (
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "unsupported_grant_type",
        ),
        // TN-130: the exchange exists only for an Instance's AIS, never for a client's code
        (
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "invalid_request",
        ),
        ("AUTHORIZATION_CODE", "unsupported_grant_type"),
    ] {
        let code = a.code(&a.f.public).await;
        let mut p = vec![
            ("client_id", a.f.public.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", CB),
            ("code_verifier", VERIFIER),
            ("username", "alice"),
            ("password", "pw"),
        ];
        if !grant_type.is_empty() {
            p.push(("grant_type", grant_type));
        }
        assert_eq!(error(&a.token(&p, None).await), expected, "{grant_type}");
    }
    let code = a.code(&a.f.public).await;
    assert_eq!(
        error(&a.exchange_confidential(&code).await),
        "invalid_grant",
        "another client's code"
    );
    assert!(body(&a.exchange(&code).await, 200)["access_token"].is_string());
}

async fn assert_dead(a: &At<'_>, tokens: &serde_json::Value) {
    let access = tokens["access_token"].as_str().unwrap();
    assert!(
        matches!(a.userinfo(access).await, Reply::Json { status: 401, .. }),
        "the access token still works"
    );
    assert_eq!(a.introspect(access).await["active"], false);
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(error(&a.refresh(refresh).await), "invalid_grant");
}

// §11.4.5 #20, RFC 6749 §4.1.2, OP-146 m.16 (h): a code is redeemed once, also when the
// redemptions race; a second redemption revokes what the first one issued
#[tokio::test]
async fn code_reuse_and_races() {
    // GHSA-hh34-7jqq-3f73
    let c = Cluster::new(&["fos-f"]).await;
    let a = c.at(0);
    let code = a.code(&a.f.public).await;
    let first = body(&a.exchange(&code).await, 200);
    assert_eq!(error(&a.exchange(&code).await), "invalid_grant");
    assert_dead(&a, &first).await;

    for _ in 0..3 {
        let code = a.code(&a.f.public).await;
        let (x, y, z, w) = tokio::join!(
            a.exchange(&code),
            a.exchange(&code),
            a.exchange(&code),
            a.exchange(&code)
        );
        let wins: Vec<serde_json::Value> = [x, y, z, w]
            .iter()
            .filter(|r| matches!(r, Reply::Json { status: 200, .. }))
            .map(|r| body(r, 200))
            .collect();
        assert!(wins.len() <= 1, "{} redemptions of one code", wins.len());
        for w in &wins {
            assert_dead(&a, w).await;
        }
    }
}

// TN-31, RR-18, AS-M8, OP-146 m.16 (g), Refresh reuse'ta sunucu tarafı ardışık-kullanım
// toleransı yok: refresh tokens rotate; concurrent presentations of one token are a reuse,
// with no grace: the grant is revoked and the session epoch raised; the scope cannot grow and
// another client cannot redeem it
#[tokio::test]
async fn refresh_reuse_races_and_escalation() {
    let c = Cluster::new(&["fos-g"]).await;
    let a = c.at(0);
    let t = a.tokens().await;
    let r = t["refresh_token"].as_str().unwrap();
    let other_client = a
        .token(
            &[("grant_type", "refresh_token"), ("refresh_token", r)],
            Some(&a.basic()),
        )
        .await;
    assert_eq!(error(&other_client), "invalid_grant");
    let wider = a
        .token(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &a.f.public),
                ("refresh_token", r),
                ("scope", "openid offline_access"),
            ],
            None,
        )
        .await;
    assert_eq!(error(&wider), "invalid_scope");
    // §2.2.2 #2, §7.1, L24, S-1, S-2
    let resource = a
        .token(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &a.f.public),
                ("refresh_token", r),
                ("scope", "openid orders:write"),
            ],
            None,
        )
        .await;
    assert_eq!(error(&resource), "invalid_scope");
    assert_eq!(
        body(&resource, 400)["error_description"],
        access_identity_oauth::domain::scope::RESOURCE_SCOPE
    );
    let same = body(
        &a.token(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &a.f.public),
                ("refresh_token", r),
                ("scope", "openid"),
            ],
            None,
        )
        .await,
        200,
    );
    assert!(same["access_token"].is_string());

    let cookie = a.sign_in(now() - 1000).await;
    let code = {
        let to = location(&a.authorize(&[], Some(&cookie)).await);
        query(&to, "code")
    };
    let t = body(&a.exchange(&code).await, 200);
    let r = t["refresh_token"].as_str().unwrap();
    let (x, y, z, w) = tokio::join!(a.refresh(r), a.refresh(r), a.refresh(r), a.refresh(r));
    let results = [x, y, z, w];
    let wins: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| matches!(r, Reply::Json { status: 200, .. }))
        .map(|r| body(r, 200))
        .collect();
    assert!(wins.len() <= 1, "{} rotations of one token", wins.len());
    for r in results
        .iter()
        .filter(|r| !matches!(r, Reply::Json { status: 200, .. }))
    {
        assert_eq!(error(r), "invalid_grant");
    }
    for w in &wins {
        assert_dead(&a, w).await;
    }
    assert_dead(&a, &t).await;
    assert!(
        !a.signed_in(&cookie).await,
        "the reuse did not end the session"
    );
}

// RFC 6749 §2.3, RFC 7523 §3, CR-38, §10.4.5, MD-3, CR-5, OP-146 m.13 (f): a client
// authenticates only by its registered method; mixed, unsigned, symmetric, foreign, stale and
// replayed credentials are all refused
#[tokio::test]
async fn client_authentication_confusion() {
    let c = Cluster::new(&["fos-h"]).await;
    let a = c.at(0);
    let token_uri = format!("{}/token", a.issuer());
    let id = a.f.keyed.clone();
    let assertion_with = |header: &str, payload: String| sign(&a.f.client_key, header, &payload);
    let claims = |iss: &str, sub: &str, aud: &str, exp: u64, jti: &str| {
        format!(
            r#"{{"iss":"{iss}","sub":"{sub}","aud":"{aud}","exp":{exp},"iat":{},"jti":"{jti}"}}"#,
            now() / 1000
        )
    };
    let later = now() / 1000 + 60;
    let unsigned = |header: &str| {
        format!(
            "{}.{}.",
            b64url_encode(header.as_bytes()),
            b64url_encode(claims(&id, &id, a.issuer(), later, "u-1").as_bytes())
        )
    };
    let foreign = sign(
        &new_key(),
        r#"{"alg":"ES256","typ":"JWT"}"#,
        &claims(&id, &id, a.issuer(), later, "f-1"),
    );
    let replayed = a.assertion(a.issuer());
    let code = a.code(&a.f.keyed).await;
    let first = a
        .token(
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
                ("client_assertion_type", JWT_BEARER),
                ("client_assertion", &replayed),
            ],
            None,
        )
        .await;
    assert!(body(&first, 200)["access_token"].is_string());

    let rows: Vec<(&str, Option<String>, Vec<(&str, String)>, &str)> = vec![
        ("no credentials", None, vec![], "invalid_request"),
        (
            "confidential as public",
            None,
            vec![("client_id", a.f.confidential.clone())],
            "invalid_client",
        ),
        (
            "wrong secret",
            Some(basic(&a.f.confidential, "wrong")),
            vec![],
            "invalid_client",
        ),
        (
            "empty secret",
            Some(basic(&a.f.confidential, "")),
            vec![],
            "invalid_client",
        ),
        (
            "public with a secret",
            Some(basic(&a.f.public, "x")),
            vec![],
            "invalid_client",
        ),
        (
            "basic for a keyed client",
            Some(basic(&a.f.keyed, &a.f.secret)),
            vec![],
            "invalid_client",
        ),
        (
            "basic and another client_id",
            Some(a.basic()),
            vec![("client_id", a.f.public.clone())],
            "invalid_request",
        ),
        (
            "basic and an assertion",
            Some(a.basic()),
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                ("client_assertion", a.assertion(a.issuer())),
            ],
            "invalid_request",
        ),
        (
            "bearer scheme",
            Some(String::from("Bearer abc")),
            vec![],
            "invalid_request",
        ),
        (
            "basic without colon",
            Some(format!(
                "Basic {}",
                crate::support::b64_std(&a.f.confidential)
            )),
            vec![],
            "invalid_request",
        ),
        (
            "assertion without type",
            None,
            vec![("client_assertion", a.assertion(a.issuer()))],
            "invalid_request",
        ),
        (
            "assertion of another type",
            None,
            vec![
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:saml2-bearer".into(),
                ),
                ("client_assertion", a.assertion(a.issuer())),
            ],
            "invalid_request",
        ),
        (
            "assertion for a secret client",
            None,
            vec![
                ("client_id", a.f.confidential.clone()),
                ("client_assertion_type", JWT_BEARER.into()),
                ("client_assertion", a.assertion(a.issuer())),
            ],
            "invalid_client",
        ),
        (
            "alg none",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                (
                    "client_assertion",
                    unsigned(r#"{"alg":"none","typ":"JWT"}"#),
                ),
            ],
            "invalid_client",
        ),
        (
            "alg HS256",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                (
                    "client_assertion",
                    unsigned(r#"{"alg":"HS256","typ":"JWT"}"#),
                ),
            ],
            "invalid_client",
        ),
        (
            "alg EdDSA",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                (
                    "client_assertion",
                    assertion_with(
                        r#"{"alg":"EdDSA","typ":"JWT"}"#,
                        claims(&id, &id, a.issuer(), later, "e-1"),
                    ),
                ),
            ],
            "invalid_client",
        ),
        (
            "ES256 header, other key",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                ("client_assertion", foreign),
            ],
            "invalid_client",
        ),
        (
            "iss is not sub",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                (
                    "client_assertion",
                    assertion_with(
                        r#"{"alg":"ES256","typ":"JWT"}"#,
                        claims(&a.f.public, &id, a.issuer(), later, "i-1"),
                    ),
                ),
            ],
            "invalid_client",
        ),
        (
            "foreign audience",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                (
                    "client_assertion",
                    assertion_with(
                        r#"{"alg":"ES256","typ":"JWT"}"#,
                        claims(&id, &id, "https://other.id.test", later, "a-1"),
                    ),
                ),
            ],
            "invalid_client",
        ),
        (
            "audience array with another",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                (
                    "client_assertion",
                    assertion_with(
                        r#"{"alg":"ES256","typ":"JWT"}"#,
                        format!(
                            r#"{{"iss":"{id}","sub":"{id}","aud":["{}","https://evil.example"],"exp":{later},"iat":{},"jti":"a-2"}}"#,
                            a.issuer(),
                            now() / 1000
                        ),
                    ),
                ),
            ],
            "invalid_client",
        ),
        (
            "expired",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                (
                    "client_assertion",
                    assertion_with(
                        r#"{"alg":"ES256","typ":"JWT"}"#,
                        claims(&id, &id, a.issuer(), now() / 1000 - 120, "x-1"),
                    ),
                ),
            ],
            "invalid_client",
        ),
        (
            "replayed jti",
            None,
            vec![
                ("client_assertion_type", JWT_BEARER.into()),
                ("client_assertion", replayed.clone()),
            ],
            "invalid_client",
        ),
        (
            "token endpoint audience, other client id",
            None,
            vec![
                ("client_id", a.f.public.clone()),
                ("client_assertion_type", JWT_BEARER.into()),
                (
                    "client_assertion",
                    assertion_with(
                        r#"{"alg":"ES256","typ":"JWT"}"#,
                        claims(&id, &id, &token_uri, later, "t-1"),
                    ),
                ),
            ],
            "invalid_client",
        ),
    ];
    for (class, auth, extra, expected) in rows {
        let code = a.code(&a.f.confidential).await;
        let mut p: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("code_verifier", VERIFIER),
        ];
        for (k, v) in &extra {
            p.push((k, v));
        }
        let r = a.token(&p, auth.as_deref()).await;
        assert_eq!(error(&r), expected, "{class}: {r:?}");
        if expected == "invalid_client" {
            assert!(
                matches!(r, Reply::Json { status: 401, .. }),
                "{class}: {r:?}"
            );
        }
    }
}
