//! Ek B Stage 5 "Bu aşamada doğrulanacak sınırlar": what the realm authorization server must
//! never offer, checked against the served metadata and the running server.

use access_crypto::dpop::NoncePolicy;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::domain::metadata::{SERVED, authorization_server};
use access_kernel::json::b64url_encode;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::Value;

use crate::support::{CB, Cluster, VERIFIER, body, error, location, now, query};

// TN-34, TN-101, IDP-7, RR-18, §10.4.1, §10.4.6, IDP-24, MD-3, CR-5, §16.4.10, OP-146 m.8 (d):
// the served metadata offers only the code flow with S256, no implicit or hybrid response, no
// ROPC or device grant, client credentials only for authority tokens (OP-150 m.2), no OIDC
// Session Management iframe, no Token Binding, no EdDSA, no unsigned or symmetric ID token and
// no request objects
#[test]
fn metadata_offers_no_forbidden_surface() {
    let issuer = Issuer::parse("https://acme.id.test").unwrap();
    let text = authorization_server(&issuer, &SERVED);
    let m: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(m["response_types_supported"], serde_json::json!(["code"]));
    assert_eq!(m["response_modes_supported"], serde_json::json!(["query"]));
    assert_eq!(
        m["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(
        m["grant_types_supported"],
        serde_json::json!(["authorization_code", "refresh_token", "client_credentials"])
    );
    for key in [
        "check_session_iframe",
        "frontchannel_logout_supported",
        "frontchannel_logout_session_supported",
        "token_binding_supported",
        "request_parameter_supported",
        "request_uri_parameter_supported",
        "request_object_signing_alg_values_supported",
        "device_authorization_endpoint",
        "registration_endpoint",
        "mtls_endpoint_aliases",
    ] {
        assert!(m.get(key).is_none(), "{key} is declared");
    }
    for forbidden in [
        "EdDSA",
        "HS256",
        "plain",
        "password",
        "implicit",
        "device_code",
        "id_token token",
        "client_secret_post",
        "client_secret_jwt",
    ] {
        let declared = m["id_token_signing_alg_values_supported"].to_string()
            + &m["dpop_signing_alg_values_supported"].to_string()
            + &m["code_challenge_methods_supported"].to_string()
            + &m["grant_types_supported"].to_string()
            + &m["response_types_supported"].to_string()
            + &m["token_endpoint_auth_methods_supported"].to_string();
        assert!(!declared.contains(forbidden), "{forbidden} in {declared}");
    }
    assert!(!text.contains("EdDSA"), "{text}");
    assert!(
        !m["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&Value::from("none"))
    );
    assert_eq!(
        m["subject_types_supported"],
        serde_json::json!(["pairwise"])
    );
}

// TN-10, TN-16, §17.9.6, §12.1.2, OP-146 m.4 (a), m.8 (b): Host only selects the realm; the issuer
// in every answer is the one stored on the realm's row, whatever the request spelled, and an
// origin the issuer does not name has no realm
#[tokio::test]
async fn the_issuer_never_comes_from_host() {
    let c = Cluster::new(&["bnd-a"]).await;
    let a = c.at(0);
    for (authority, found) in [
        ("bnd-a.id.test", true),
        ("BND-A.ID.TEST", true),
        ("bnd-a.id.test:443", true),
        ("bnd-a.id.test:8443", false),
        ("bnd-a.id.test.", false),
        ("evil.test", false),
        ("bnd-a.id.test@evil.test", false),
        ("id.test", false),
    ] {
        let r = c.oauth.realm(authority, None).await.unwrap();
        assert_eq!(r.is_some(), found, "{authority}");
        if let Some(realm) = r {
            assert_eq!(realm.issuer.as_str(), a.issuer(), "{authority}");
        }
    }
    assert!(
        c.oauth
            .realm("id.test", Some("bnd-a"))
            .await
            .unwrap()
            .is_none()
    );
    let to = location(&a.authorize(&[], Some(&a.f.cookie)).await);
    assert_eq!(query(&to, "iss"), a.issuer());
    let t = a.tokens().await;
    let at = crate::support::claims(t["access_token"].as_str().unwrap());
    assert_eq!(at["iss"], a.issuer());
}

// MD-18, TN-29, §12.2.1, OP-146 m.7 (b): there is no short-lived 60 s nonce model; a nonce
// stays good across its window, so a proof made minutes after its nonce was issued is accepted
#[tokio::test]
async fn dpop_nonces_are_not_a_sixty_second_model() {
    const { assert!(NoncePolicy::DEFAULT_PERIOD_MS >= 60 * 60 * 1000) };
    assert!(NoncePolicy::new(60_000, 120_000).is_err());
    let c = Cluster::new(&["bnd-b"]).await;
    let a = c.at(0);
    let issued = a.rings().authorization.issue(now() - 3 * 60_000).unwrap();
    let code = a.code(&a.f.public).await;
    let uri = format!("{}/token", a.issuer());
    let proof = a.proof_with("POST", &uri, None, &issued);
    let p = [
        ("grant_type", "authorization_code"),
        ("client_id", a.f.public.as_str()),
        ("code", code.as_str()),
        ("redirect_uri", CB),
        ("code_verifier", VERIFIER),
    ];
    assert!(body(&a.token_with(&p, None, &[&proof]).await, 200)["access_token"].is_string());
}

fn okp_proof(key: &Ed25519KeyPair, alg: &str, uri: &str, nonce: &str) -> String {
    let jwk = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
        b64url_encode(key.public_key().as_ref())
    );
    let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
    let header = format!(r#"{{"typ":"dpop+jwt","alg":"{alg}","jwk":{jwk}}}"#);
    let payload = format!(
        r#"{{"jti":"{jti}","htm":"POST","htu":"{uri}","iat":{},"nonce":"{nonce}"}}"#,
        now() / 1000
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

// MD-3, CR-5, RFC 9864, OP-144, §10.4.3: an Ed25519 DPoP proof is accepted under its fully
// specified name and refused under the polymorphic `EdDSA`
#[tokio::test]
async fn eddsa_is_refused_and_ed25519_accepted() {
    let c = Cluster::new(&["bnd-c"]).await;
    let a = c.at(0);
    let key = Ed25519KeyPair::generate().unwrap();
    let uri = format!("{}/token", a.issuer());
    for (alg, ok) in [("EdDSA", false), ("Ed25519", true)] {
        let code = a.code(&a.f.public).await;
        let nonce = a.rings().authorization.issue(now()).unwrap();
        let proof = okp_proof(&key, alg, &uri, &nonce);
        let p = [
            ("grant_type", "authorization_code"),
            ("client_id", a.f.public.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", CB),
            ("code_verifier", VERIFIER),
        ];
        let r = a.token_with(&p, None, &[&proof]).await;
        if ok {
            assert!(body(&r, 200)["access_token"].is_string(), "{alg}");
        } else {
            assert_eq!(error(&r), "invalid_dpop_proof", "{alg}");
        }
    }
}
