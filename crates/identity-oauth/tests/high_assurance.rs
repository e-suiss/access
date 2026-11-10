//! High-assurance and legacy client profiles on the real authorization server (OP-155 m.3 (k),
//! OP-153 m.3 (gg)): real PostgreSQL, a real identity signer, each profile written under an
//! `idp.client.*` ALLOW. FAPI 2.0, JAR, JARM, JWE, mutual TLS, the legacy secret methods, the
//! legacy bearer exception, the JWKS re-fetch and front-channel logout. Keys, certificates and
//! tokens are made at run time.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::needless_pass_by_value,
    clippy::unnecessary_to_owned,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "support/mod.rs"]
mod support;

use access_crypto::AwsLcBackend;
use access_identity_oauth::app::oauth::Reply;
use access_identity_oauth::domain::jwt::realm_key_set;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::oauth::TokenSigner as _;
use access_identity_oauth::ports::profile::{CertificateNames, CertificateRefused};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::verify::jws::{Origin, verify_compact};
use access_store::client_profiles::{ClientProfileRow, SealedJwtSecret};
use aws_lc_rs::agreement::{self, ECDH_P256};
use aws_lc_rs::encoding::AsDer as _;
use serde_json::Value;
use support::{
    At, CB, CHALLENGE, Cluster, JWT_BEARER, VERIFIER, body, claims, ec_jwk, error, location,
    new_key, now, query, query_opt, sign,
};

const FAPI: &str = "idp.client.profile";
const UPDATE: &str = "idp.client.update";

fn b64_std(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let v = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= n {
                out.push(char::from(A[((v >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn params(pairs: &[(&str, &str)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    )
    .unwrap()
}

/// A request object of the keyed client, signed with its key.
fn request_object(a: &At<'_>, extra: &str) -> String {
    let id = &a.f.keyed;
    sign(
        &a.f.client_key,
        r#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#,
        &format!(
            r#"{{"iss":"{id}","aud":"{}","client_id":"{id}","exp":{},"nbf":{},"response_type":"code","redirect_uri":"{CB}","scope":"openid","code_challenge":"{CHALLENGE}","code_challenge_method":"S256","state":"st","nonce":"n-1"{extra}}}"#,
            a.issuer(),
            now() / 1000 + 300,
            now() / 1000 - 5
        ),
    )
}

/// `/par` for the keyed client with its assertion and a DPoP proof.
async fn par(a: &At<'_>, extra: &[(&str, &str)], chain: &[Vec<u8>]) -> Reply {
    let assertion = a.assertion(a.issuer());
    let mut pairs: Vec<(&str, &str)> = vec![
        ("client_id", a.f.keyed.as_str()),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", assertion.as_str()),
    ];
    pairs.extend_from_slice(extra);
    let proof = a.proof("POST", &format!("{}/par", a.issuer()), None);
    a.oauth()
        .par_mtls(a.realm(), &params(&pairs), None, &[&proof], chain)
        .await
}

async fn redeem(a: &At<'_>, client: &str, uri: &str) -> String {
    let cookie = a.sign_in(now() - 1000).await;
    location(
        &a.oauth()
            .authorize(
                a.realm(),
                &params(&[("client_id", client), ("request_uri", uri)]),
                Some(&cookie),
            )
            .await,
    )
}

async fn keyed_exchange(a: &At<'_>, code: &str, dpop: bool) -> Reply {
    let assertion = a.assertion(a.issuer());
    let pairs = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", CB),
        ("code_verifier", VERIFIER),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", assertion.as_str()),
    ];
    if dpop {
        a.token(&pairs, None).await
    } else {
        a.token_with(&pairs, None, &[]).await
    }
}

async fn realm_jws(a: &At<'_>, token: &str, typ: &str) -> Value {
    let jwks = a.oauth().env().signer.jwks(a.realm().realm).await.unwrap();
    let keys = realm_key_set(jwks.as_bytes()).unwrap();
    let v = verify_compact(&AwsLcBackend, token, &keys, typ, Origin::Native).unwrap();
    serde_json::from_slice(&v.payload).unwrap()
}

// IDP-12, OP-155 m.3 (k), Ek B 4717, 5044
#[tokio::test]
async fn fapi2_clients_are_held_to_the_profile() {
    let c = Cluster::new(&["ha-fapi"]).await;
    let a = c.at(0);
    let fapi = ClientProfileRow {
        fapi2: true,
        ..ClientProfileRow::default()
    };
    // IDP-12
    for bad in [
        ClientProfileRow {
            rs256: true,
            ..fapi.clone()
        },
        ClientProfileRow {
            legacy_bearer: true,
            ..fapi.clone()
        },
        ClientProfileRow {
            legacy_auth: Some(String::from("client_secret_post")),
            ..fapi.clone()
        },
    ] {
        assert!(a.set_profile('c', FAPI, &bad).await.is_err());
    }
    a.set_profile('c', FAPI, &fapi).await.unwrap();

    // RFC 9126 §6
    let cookie = a.sign_in(now() - 1000).await;
    let to = location(
        &a.authorize(&[("client_id", a.f.keyed.as_str())], Some(&cookie))
            .await,
    );
    assert_eq!(query(&to, "error"), "invalid_request", "{to}");

    let plain = par(
        &a,
        &[
            ("response_type", "code"),
            ("redirect_uri", CB),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ],
        &[],
    )
    .await;
    assert_eq!(error(&plain), "invalid_request");

    let object = request_object(&a, "");
    let pushed = body(&par(&a, &[("request", object.as_str())], &[]).await, 201);
    let to = redeem(&a, &a.f.keyed, pushed["request_uri"].as_str().unwrap()).await;
    assert!(query_opt(&to, "code").is_none(), "{to}");
    let response = query(&to, "response");
    let jarm = realm_jws(&a, &response, "JWT").await;
    assert_eq!(jarm["iss"], a.issuer());
    assert_eq!(jarm["aud"], a.f.keyed.as_str());
    assert_eq!(jarm["state"], "st");
    let code = jarm["code"].as_str().unwrap().to_owned();
    let t = body(&keyed_exchange(&a, &code, true).await, 200);
    assert_eq!(t["token_type"], "DPoP");

    // OP-155 m.3 (k)
    let refresh = t["refresh_token"].as_str().unwrap().to_owned();
    let assertion = a.assertion(a.issuer());
    for _ in 0..2 {
        let assertion = a.assertion(a.issuer());
        let r = body(
            &a.token(
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh),
                    ("client_assertion_type", JWT_BEARER),
                    ("client_assertion", &assertion),
                ],
                None,
            )
            .await,
            200,
        );
        assert!(r.get("refresh_token").is_none(), "{r}");
    }
    let _ = assertion;

    // TN-27
    let pushed = body(&par(&a, &[("request", object.as_str())], &[]).await, 201);
    let to = redeem(&a, &a.f.keyed, pushed["request_uri"].as_str().unwrap()).await;
    let jarm = realm_jws(&a, &query(&to, "response"), "JWT").await;
    let unbound = keyed_exchange(&a, jarm["code"].as_str().unwrap(), false).await;
    assert_eq!(error(&unbound), "invalid_dpop_proof");

    // IDP-12
    a.set_profile('b', FAPI, &fapi).await.unwrap();
    let code = a.code(&a.f.public).await;
    let r = a
        .token(
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&a.basic()),
        )
        .await;
    assert_eq!(error(&r), "invalid_client");
}

// IDI-6, MD-3, Ek B 4707
#[tokio::test]
async fn request_objects_follow_the_client_allowlist() {
    let c = Cluster::new(&["ha-jar"]).await;
    let a = c.at(0);
    let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let (n, e) = access_crypto::rsa_id::pkcs1_parts(
        aws_lc_rs::signature::KeyPair::public_key(&pair).as_ref(),
    )
    .unwrap();
    a.c.oauth.env().keys.0.lock().unwrap().insert(
        a.f.keyed_jwks.clone(),
        format!(
            r#"{{"keys":[{},{{"kty":"RSA","kid":"r1","n":"{}","e":"{}"}}]}}"#,
            ec_jwk(&a.f.client_key).replace('{', r#"{"kid":"e1","#),
            b64url_encode(&n),
            b64url_encode(&e)
        )
        .into_bytes(),
    );
    let id = &a.f.keyed;
    let payload = format!(
        r#"{{"iss":"{id}","aud":"{}","client_id":"{id}","exp":{},"nbf":{},"response_type":"code","redirect_uri":"{CB}","code_challenge":"{CHALLENGE}","code_challenge_method":"S256"}}"#,
        a.issuer(),
        now() / 1000 + 300,
        now() / 1000 - 5
    );
    let input = format!(
        "{}.{}",
        b64url_encode(br#"{"alg":"RS256","kid":"r1"}"#),
        b64url_encode(payload.as_bytes())
    );
    let mut sig = vec![0; pair.public_modulus_len()];
    pair.sign(
        &aws_lc_rs::signature::RSA_PKCS1_SHA256,
        &aws_lc_rs::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .unwrap();
    let rs256 = format!("{input}.{}", b64url_encode(&sig));
    let r = par(&a, &[("request", rs256.as_str())], &[]).await;
    assert_eq!(error(&r), "invalid_request_object");
    let es256 = sign(&a.f.client_key, r#"{"alg":"ES256","kid":"e1"}"#, &payload);
    body(&par(&a, &[("request", es256.as_str())], &[]).await, 201);

    // OP-155 m.3 (k)
    let realm_key = agreement::PrivateKey::generate(&ECDH_P256).unwrap();
    let realm_public = realm_key.compute_public_key().unwrap();
    let to = access_crypto::jwe::RecipientKey::P256(realm_public.as_ref().to_vec());
    let encrypted = access_crypto::jwe::encrypt(&to, None, Some("JWT"), es256.as_bytes()).unwrap();
    let refused = par(&a, &[("request", encrypted.as_str())], &[]).await;
    assert_eq!(error(&refused), "invalid_request_object");
    let der: aws_lc_rs::encoding::EcPrivateKeyRfc5915Der<'_> = realm_key.as_der().unwrap();
    *a.c.oauth.env().request_keys.0.lock().unwrap() = Some(der.as_ref().to_vec());
    body(&par(&a, &[("request", encrypted.as_str())], &[]).await, 201);
}

fn enc_key() -> (agreement::PrivateKey, String) {
    let k = agreement::PrivateKey::generate(&ECDH_P256).unwrap();
    let p = k.compute_public_key().unwrap();
    let p = p.as_ref();
    let jwks = format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","use":"enc","kid":"enc-1","x":"{}","y":"{}"}}]}}"#,
        b64url_encode(&p[1..33]),
        b64url_encode(&p[33..])
    );
    (k, jwks)
}

fn open(key: access_crypto::jwe::DecryptKey, jwe: &str) -> String {
    assert_eq!(jwe.split('.').count(), 5, "{jwe}");
    String::from_utf8(access_crypto::jwe::decrypt(&key, jwe).unwrap().plaintext).unwrap()
}

// CR-4, RR-36, Ek B 4708, 4725, 5103, 5105
#[tokio::test]
async fn jarm_and_jwe_reach_the_client_only() {
    let c = Cluster::new(&["ha-jwe"]).await;
    let a = c.at(0);
    let rsa15 = ClientProfileRow {
        enc_alg: Some(String::from("RSA1_5")),
        enc_jwks: Some(String::from(r#"{"keys":[]}"#)),
        enc_id_token: true,
        ..ClientProfileRow::default()
    };
    assert!(
        a.set_profile('a', "idp.client.encryption", &rsa15)
            .await
            .is_err()
    );
    let (key, jwks) = enc_key();
    let der: aws_lc_rs::encoding::EcPrivateKeyRfc5915Der<'_> = key.as_der().unwrap();
    let der = der.as_ref().to_vec();
    let profile = ClientProfileRow {
        enc_alg: Some(String::from("ECDH-ES+A256KW")),
        enc_jwks: Some(jwks),
        enc_id_token: true,
        enc_userinfo: true,
        enc_jarm: true,
        ..ClientProfileRow::default()
    };
    a.set_profile('a', "idp.client.encryption", &profile)
        .await
        .unwrap();
    let decrypt = || access_crypto::jwe::DecryptKey::p256(&der).unwrap();

    // JARM §2.3.1, CR-4
    let cookie = a.sign_in(now() - 1000).await;
    let to = location(
        &a.authorize(&[("response_mode", "jwt")], Some(&cookie))
            .await,
    );
    let jarm = realm_jws(&a, &open(decrypt(), &query(&to, "response")), "JWT").await;
    assert_eq!(jarm["aud"], a.f.public.as_str());
    let code = jarm["code"].as_str().unwrap().to_owned();
    let t = body(&a.exchange(&code).await, 200);
    let id = realm_jws(&a, &open(decrypt(), t["id_token"].as_str().unwrap()), "JWT").await;
    assert_eq!(id["aud"], a.f.public.as_str());
    assert_eq!(id["nonce"], "n-1");
    let (_, other) = enc_key();
    let _ = other;
    let wrong = agreement::PrivateKey::generate(&ECDH_P256).unwrap();
    let wrong = access_crypto::jwe::DecryptKey::P256(wrong);
    assert!(access_crypto::jwe::decrypt(&wrong, t["id_token"].as_str().unwrap()).is_err());

    let r = a.userinfo(t["access_token"].as_str().unwrap()).await;
    let Reply::Jwt { body: jwe, .. } = r else {
        panic!("{r:?}");
    };
    let info = realm_jws(&a, &open(decrypt(), &jwe), "JWT").await;
    assert_eq!(info["aud"], a.f.public.as_str());
    assert_eq!(info["iss"], a.issuer());

    // JARM §2.3.4
    let cookie = a.sign_in(now() - 1000).await;
    let posted = a
        .authorize(&[("response_mode", "form_post.jwt")], Some(&cookie))
        .await;
    let Reply::FormPost { action, body: page } = posted else {
        panic!("{posted:?}");
    };
    assert_eq!(action, CB);
    assert!(page.contains("name=\"response\""));
}

// CR-4, Ek B 4726
#[tokio::test]
async fn rsa_oaep_256_is_a_client_opt_in() {
    let c = Cluster::new(&["ha-oaep"]).await;
    let a = c.at(0);
    let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let (n, e) = access_crypto::rsa_id::pkcs1_parts(
        aws_lc_rs::signature::KeyPair::public_key(&pair).as_ref(),
    )
    .unwrap();
    let profile = ClientProfileRow {
        enc_alg: Some(String::from("RSA-OAEP-256")),
        enc_jwks: Some(format!(
            r#"{{"keys":[{{"kty":"RSA","use":"enc","n":"{}","e":"{}"}}]}}"#,
            b64url_encode(&n),
            b64url_encode(&e)
        )),
        enc_id_token: true,
        ..ClientProfileRow::default()
    };
    a.set_profile('a', "idp.client.encryption", &profile)
        .await
        .unwrap();
    let t = a.tokens().await;
    let key = access_crypto::jwe::DecryptKey::rsa(pair.as_der().unwrap().as_ref()).unwrap();
    let id = realm_jws(&a, &open(key, t["id_token"].as_str().unwrap()), "JWT").await;
    assert_eq!(id["aud"], a.f.public.as_str());
    let header: Value = serde_json::from_slice(
        &b64url_decode(t["id_token"].as_str().unwrap().split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], "RSA-OAEP-256");
}

fn cert(names: &[&str]) -> Vec<u8> {
    let names: Vec<String> = names.iter().map(|n| String::from(*n)).collect();
    rcgen::generate_simple_self_signed(names)
        .unwrap()
        .cert
        .der()
        .to_vec()
}

fn x5t(leaf: &[u8]) -> String {
    b64url_encode(&access_crypto::webauthn::sha256(leaf))
}

async fn confidential_code(a: &At<'_>) -> String {
    let cookie = a.sign_in(now() - 1000).await;
    let to = location(
        &a.authorize(&[("client_id", a.f.confidential.as_str())], Some(&cookie))
            .await,
    );
    query(&to, "code")
}

async fn mtls_exchange(a: &At<'_>, code: &str, chain: &[Vec<u8>]) -> Reply {
    a.token_over(
        &[
            ("grant_type", "authorization_code"),
            ("client_id", a.f.confidential.as_str()),
            ("code", code),
            ("redirect_uri", CB),
            ("code_verifier", VERIFIER),
        ],
        None,
        &[],
        chain,
    )
    .await
}

// RFC 8705 §2.1, §3, TN-32, MD-8, Ek B 4692, 4713, 5091, 4854
#[tokio::test]
async fn mutual_tls_clients_bind_their_tokens_to_the_certificate() {
    let c = Cluster::new(&["ha-mtls"]).await;
    let a = c.at(0);
    let profile = ClientProfileRow {
        tls_auth: Some(String::from("tls_client_auth")),
        tls_name: Some((String::from("san_dns"), String::from("svc.example"))),
        ..ClientProfileRow::default()
    };
    // §10.4.3
    a.set_profile('a', UPDATE, &profile).await.unwrap();
    let r = a
        .token_over(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", a.f.public.as_str()),
                ("code", "x"),
            ],
            None,
            &[],
            &[cert(&["svc.example"])],
        )
        .await;
    assert_eq!(error(&r), "invalid_client");

    a.set_profile('b', UPDATE, &profile).await.unwrap();
    let good = cert(&["svc.example"]);
    let revoked = cert(&["svc.example"]);
    let two = cert(&["svc.example", "other.example"]);
    let other = cert(&["svc.example"]);
    {
        let mut m = a.c.oauth.env().certs.0.lock().unwrap();
        let names = |dns: &[&str]| CertificateNames {
            subject_dn: String::from("CN=svc"),
            dns: dns.iter().map(|d| String::from(*d)).collect(),
            ..CertificateNames::default()
        };
        m.insert(good.clone(), Ok(names(&["svc.example"])));
        m.insert(other.clone(), Ok(names(&["svc.example"])));
        m.insert(revoked.clone(), Err(CertificateRefused::Revoked));
        m.insert(two.clone(), Ok(names(&["svc.example", "other.example"])));
    }
    for refused in [&revoked, &two] {
        let code = confidential_code(&a).await;
        let r = mtls_exchange(&a, &code, std::slice::from_ref(refused)).await;
        assert_eq!(error(&r), "invalid_client");
    }
    let code = confidential_code(&a).await;
    let no_cert = mtls_exchange(&a, &code, &[]).await;
    assert_eq!(error(&no_cert), "invalid_client");
    let basic = a
        .token(
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&a.basic()),
        )
        .await;
    assert_eq!(error(&basic), "invalid_client");

    let code = confidential_code(&a).await;
    let t = body(
        &mtls_exchange(&a, &code, std::slice::from_ref(&good)).await,
        200,
    );
    assert_eq!(t["token_type"], "Bearer");
    let access = t["access_token"].as_str().unwrap();
    let at = claims(access);
    assert_eq!(at["cnf"]["x5t#S256"], x5t(&good));
    assert!(at["cnf"].get("jkt").is_none());

    let info = |chain: Vec<Vec<u8>>, scheme: &'static str| {
        let a = a.clone();
        let access = access.to_owned();
        async move {
            let uri = format!("{}/userinfo", a.issuer());
            let proof = a.proof("GET", &uri, Some(&access));
            a.oauth()
                .userinfo_mtls(
                    a.realm(),
                    "GET",
                    Some(&format!("{scheme} {access}")),
                    &[&proof],
                    &chain,
                )
                .await
        }
    };
    body(&info(vec![good.clone()], "Bearer").await, 200);
    assert_eq!(
        support::status(&info(vec![other.clone()], "Bearer").await),
        401
    );
    assert_eq!(support::status(&info(vec![], "Bearer").await), 401);
    assert_eq!(
        support::status(&info(vec![good.clone()], "DPoP").await),
        401
    );

    // RFC 8705 §2.1
    let refresh = t["refresh_token"].as_str().unwrap().to_owned();
    let r = a
        .token_over(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", a.f.confidential.as_str()),
                ("refresh_token", &refresh),
            ],
            None,
            &[],
            std::slice::from_ref(&good),
        )
        .await;
    assert_eq!(
        claims(body(&r, 200)["access_token"].as_str().unwrap())["cnf"]["x5t#S256"],
        x5t(&good)
    );
}

// RFC 8705 §2.2, Ek B 4692
#[tokio::test]
async fn self_signed_clients_present_a_registered_certificate() {
    let c = Cluster::new(&["ha-self"]).await;
    let a = c.at(0);
    let leaf = cert(&["self.example"]);
    let profile = ClientProfileRow {
        tls_auth: Some(String::from("self_signed_tls_client_auth")),
        tls_jwks: Some(format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"AA","y":"AA","x5c":["{}"]}}]}}"#,
            b64_std(&leaf)
        )),
        ..ClientProfileRow::default()
    };
    a.set_profile('b', UPDATE, &profile).await.unwrap();
    let code = confidential_code(&a).await;
    let refused = mtls_exchange(&a, &code, &[cert(&["self.example"])]).await;
    assert_eq!(error(&refused), "invalid_client");
    let code = confidential_code(&a).await;
    let t = body(
        &mtls_exchange(&a, &code, std::slice::from_ref(&leaf)).await,
        200,
    );
    assert_eq!(
        claims(t["access_token"].as_str().unwrap())["cnf"]["x5t#S256"],
        x5t(&leaf)
    );
}

// CR-38, OP-155 m.3 (k), Ek B 5088
#[tokio::test]
async fn client_secret_post_is_an_opt_in() {
    let c = Cluster::new(&["ha-post"]).await;
    let a = c.at(0);
    let post = |code: String| {
        let a = a.clone();
        async move {
            a.token(
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", a.f.confidential.as_str()),
                    ("client_secret", a.f.secret.as_str()),
                    ("code", &code),
                    ("redirect_uri", CB),
                    ("code_verifier", VERIFIER),
                ],
                None,
            )
            .await
        }
    };
    assert_eq!(
        error(&post(confidential_code(&a).await).await),
        "invalid_client"
    );
    let profile = ClientProfileRow {
        legacy_auth: Some(String::from("client_secret_post")),
        ..ClientProfileRow::default()
    };
    a.set_profile('b', "idp.client.auth_method_legacy", &profile)
        .await
        .unwrap();
    body(&post(confidential_code(&a).await).await, 200);
    let basic = a.exchange_confidential(&confidential_code(&a).await).await;
    assert_eq!(error(&basic), "invalid_client");
    let wrong = a
        .token(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", a.f.confidential.as_str()),
                ("client_secret", "not-the-secret"),
                ("code", &confidential_code(&a).await),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            None,
        )
        .await;
    assert_eq!(error(&wrong), "invalid_client");
}

fn hs256(secret: &[u8], id: &str, aud: &str) -> String {
    let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
    let input = format!(
        "{}.{}",
        b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        b64url_encode(
            format!(
                r#"{{"iss":"{id}","sub":"{id}","aud":"{aud}","exp":{},"iat":{},"jti":"{jti}"}}"#,
                now() / 1000 + 60,
                now() / 1000
            )
            .as_bytes()
        )
    );
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret);
    let tag = aws_lc_rs::hmac::sign(&key, input.as_bytes());
    format!("{input}.{}", b64url_encode(tag.as_ref()))
}

// CR-3, OP-148 m.16 (l), Ek B 5092
#[tokio::test]
async fn client_secret_jwt_uses_the_sealed_secret() {
    let c = Cluster::new(&["ha-csj"]).await;
    let a = c.at(0);
    let secret = access_crypto::random::bytes::<32>().unwrap().to_vec();
    let ciphertext = access_crypto::random::bytes::<48>().unwrap().to_vec();
    a.c.oauth
        .env()
        .secrets
        .0
        .lock()
        .unwrap()
        .insert(ciphertext.clone(), secret.clone());
    let profile = ClientProfileRow {
        legacy_auth: Some(String::from("client_secret_jwt")),
        jwt_secret: Some(SealedJwtSecret {
            kek_id: String::from("realm-kek:1"),
            wrapped: access_crypto::random::bytes::<40>().unwrap().to_vec(),
            nonce: access_crypto::random::bytes::<12>().unwrap().to_vec(),
            ciphertext,
        }),
        ..ClientProfileRow::default()
    };
    a.set_profile('b', "idp.client.auth_method_legacy", &profile)
        .await
        .unwrap();
    let id = a.f.confidential.clone();
    let exchange = |assertion: String| {
        let a = a.clone();
        async move {
            a.token(
                &[
                    ("grant_type", "authorization_code"),
                    ("client_assertion_type", JWT_BEARER),
                    ("client_assertion", &assertion),
                    ("code", &confidential_code(&a).await),
                    ("redirect_uri", CB),
                    ("code_verifier", VERIFIER),
                ],
                None,
            )
            .await
        }
    };
    let good = hs256(&secret, &id, a.issuer());
    body(&exchange(good.clone()).await, 200);
    assert_eq!(error(&exchange(good).await), "invalid_client");
    let other = access_crypto::random::bytes::<32>().unwrap();
    assert_eq!(
        error(&exchange(hs256(&other, &id, a.issuer())).await),
        "invalid_client"
    );
    assert_eq!(
        error(&a.exchange_confidential(&confidential_code(&a).await).await),
        "invalid_client"
    );
}

// TN-27, OP-155 m.3 (k), Ek B 5090
#[tokio::test]
async fn the_legacy_bearer_exception_is_one_clients() {
    let c = Cluster::new(&["ha-bear"]).await;
    let a = c.at(0);
    let unbound = a
        .token_with(
            &[
                ("grant_type", "authorization_code"),
                ("code", &confidential_code(&a).await),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&a.basic()),
            &[],
        )
        .await;
    assert_eq!(error(&unbound), "invalid_dpop_proof");
    let on = ClientProfileRow {
        legacy_bearer: true,
        ..ClientProfileRow::default()
    };
    a.set_profile('b', "idp.client.legacy_bearer", &on)
        .await
        .unwrap();
    let t = body(
        &a.token_with(
            &[
                ("grant_type", "authorization_code"),
                ("code", &confidential_code(&a).await),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&a.basic()),
            &[],
        )
        .await,
        200,
    );
    assert_eq!(t["token_type"], "Bearer");
    let access = t["access_token"].as_str().unwrap().to_owned();
    assert!(claims(&access).get("cnf").is_none());
    let bearer = |access: String| {
        let a = a.clone();
        async move {
            a.oauth()
                .userinfo(a.realm(), "GET", Some(&format!("Bearer {access}")), &[])
                .await
        }
    };
    body(&bearer(access.clone()).await, 200);
    let cc = a
        .token_with(
            &[("grant_type", "client_credentials")],
            Some(&a.basic()),
            &[],
        )
        .await;
    assert_eq!(error(&cc), "invalid_dpop_proof");
    a.set_profile(
        'b',
        "idp.client.legacy_bearer",
        &ClientProfileRow::default(),
    )
    .await
    .unwrap();
    assert_eq!(support::status(&bearer(access).await), 401);
}

// §10.4.5, Ek B 5098
#[tokio::test]
async fn an_unknown_kid_refetches_once_then_refuses() {
    let c = Cluster::new(&["ha-kid"]).await;
    let a = c.at(0);
    let k2 = new_key();
    let k3 = new_key();
    let doc = format!(
        r#"{{"keys":[{},{}]}}"#,
        ec_jwk(&a.f.client_key).replace('{', r#"{"kid":"k1","#),
        ec_jwk(&k2).replace('{', r#"{"kid":"k2","#)
    );
    let keyed = |key: &aws_lc_rs::signature::EcdsaKeyPair, kid: &str| {
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
        let id = &a.f.keyed;
        sign(
            key,
            &format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#),
            &format!(
                r#"{{"iss":"{id}","sub":"{id}","aud":"{}","exp":{},"iat":{},"jti":"{jti}"}}"#,
                a.issuer(),
                now() / 1000 + 60,
                now() / 1000
            ),
        )
    };
    let cc = |assertion: String| {
        let a = a.clone();
        async move {
            a.token(
                &[
                    ("grant_type", "client_credentials"),
                    ("client_assertion_type", JWT_BEARER),
                    ("client_assertion", &assertion),
                ],
                None,
            )
            .await
        }
    };
    let refetches = || {
        a.c.oauth
            .env()
            .keys
            .1
            .lock()
            .unwrap()
            .get(&a.f.keyed_jwks)
            .copied()
            .unwrap_or(0)
    };
    a.c.oauth
        .env()
        .keys
        .0
        .lock()
        .unwrap()
        .insert(a.f.keyed_jwks.clone(), doc.into_bytes());
    let r = cc(keyed(&k2, "k2")).await;
    assert_ne!(support::status(&r), 401, "{r:?}");
    assert_eq!(refetches(), 0);
    let r = cc(keyed(&k3, "k3")).await;
    assert_eq!(error(&r), "invalid_client");
    assert_eq!(refetches(), 1);
    let r = cc(keyed(&k3, "k3")).await;
    assert_eq!(error(&r), "invalid_client");
    assert_eq!(refetches(), 1);
}

// IDP-24, §10.4.6, Ek B 5096
#[tokio::test]
async fn front_channel_logout_is_a_realm_and_client_opt_in() {
    let c = Cluster::new(&["ha-fcl"]).await;
    let a = c.at(0);
    let profile = ClientProfileRow {
        frontchannel_logout_uri: Some(String::from("https://shop.example/fc")),
        ..ClientProfileRow::default()
    };
    a.set_profile('a', UPDATE, &profile).await.unwrap();
    let sign_out = || {
        let a = a.clone();
        async move {
            let cookie = a.sign_in(now() - 1000).await;
            let to = location(&a.authorize(&[], Some(&cookie)).await);
            let t = body(&a.exchange(&query(&to, "code")).await, 200);
            let id = t["id_token"].as_str().unwrap().to_owned();
            let sid = claims(&id)["sid"].as_str().unwrap().to_owned();
            let r = a
                .end_session(&[("id_token_hint", id.as_str())], Some(&cookie))
                .await;
            (r, sid)
        }
    };
    let (r, _) = sign_out().await;
    assert!(matches!(r, Reply::Redirect(_)), "{r:?}");
    a.enable_frontchannel().await;
    let (r, sid) = sign_out().await;
    let Reply::Page { body: page, frames } = r else {
        panic!("{r:?}");
    };
    assert_eq!(frames, vec![String::from("https://shop.example")]);
    let iss = access_identity_oauth::domain::issuer::Issuer::parse(a.issuer()).unwrap();
    let mut expected = String::from("https://shop.example/fc?iss=");
    access_identity_oauth::domain::issuer::form_encode(iss.as_str(), &mut expected);
    expected.push_str("&amp;sid=");
    expected.push_str(&sid);
    assert!(page.contains(&expected), "{page}");
}

// CR-2, MD-3, MD-6, OP-125, Ek B 5093, 5094, 5103, 5104, 5106
#[tokio::test]
async fn rs256_identity_assertions_are_a_client_opt_in() {
    let c = Cluster::new(&["ha-rs"]).await;
    let a = c.at(0);
    let before = a.oauth().env().signer.jwks(a.realm().realm).await.unwrap();
    assert!(!before.contains(r#""kty":"RSA""#));
    let without_opt_in = ClientProfileRow {
        id_token_alg: Some(String::from("RS256")),
        ..ClientProfileRow::default()
    };
    assert!(
        a.set_profile('a', "idp.client.alg_rs256", &without_opt_in)
            .await
            .is_err()
    );
    let rs = ClientProfileRow {
        rs256: true,
        id_token_alg: Some(String::from("RS256")),
        ..ClientProfileRow::default()
    };
    a.set_profile('a', "idp.client.alg_rs256", &rs)
        .await
        .unwrap();
    let cookie = a.sign_in(now() - 1000).await;
    let to = location(
        &a.authorize(&[("response_mode", "query.jwt")], Some(&cookie))
            .await,
    );
    let response = query(&to, "response");
    let t = body(
        &a.exchange(&claims(&response)["code"].as_str().unwrap().to_owned())
            .await,
        200,
    );
    let id = t["id_token"].as_str().unwrap();
    let header: Value =
        serde_json::from_slice(&b64url_decode(id.split('.').next().unwrap()).unwrap()).unwrap();
    assert_eq!(header["alg"], "RS256");
    let access: Value = serde_json::from_slice(
        &b64url_decode(
            t["access_token"]
                .as_str()
                .unwrap()
                .split('.')
                .next()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(access["alg"], "ES256");
    let jwks: Value =
        serde_json::from_str(&a.oauth().env().signer.jwks(a.realm().realm).await.unwrap()).unwrap();
    let rsa = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kty"] == "RSA")
        .unwrap()
        .clone();
    assert_eq!(rsa["kid"], header["kid"]);
    let n = b64url_decode(rsa["n"].as_str().unwrap()).unwrap();
    let e = b64url_decode(rsa["e"].as_str().unwrap()).unwrap();
    assert_eq!(n.len(), 384);
    for token in [id, response.as_str()] {
        let (input, sig) = token.rsplit_once('.').unwrap();
        let sig = b64url_decode(sig).unwrap();
        access_crypto::rsa_id::verify_strict(&n, &e, input.as_bytes(), &sig).unwrap();
        let mut padded = vec![0];
        padded.extend_from_slice(&sig);
        assert!(access_crypto::rsa_id::verify_strict(&n, &e, input.as_bytes(), &padded).is_err());
    }
}

// TN-14, Ek B 5095
#[tokio::test]
async fn userinfo_can_be_signed_by_the_realm_key() {
    let c = Cluster::new(&["ha-ui"]).await;
    let a = c.at(0);
    let profile = ClientProfileRow {
        userinfo_signed: true,
        ..ClientProfileRow::default()
    };
    a.set_profile('a', UPDATE, &profile).await.unwrap();
    let t = a.tokens().await;
    let r = a.userinfo(t["access_token"].as_str().unwrap()).await;
    let Reply::Jwt { body: jwt, .. } = r else {
        panic!("{r:?}");
    };
    let info = realm_jws(&a, &jwt, "JWT").await;
    assert_eq!(info["iss"], a.issuer());
    assert_eq!(info["aud"], a.f.public.as_str());
    assert!(info["sub"].is_string());
}

// RFC 7522, OP-154 m.3 (m), OP-155 m.3 (k), Ek B 4703
#[tokio::test]
async fn saml_assertions_are_one_clients_claim_input() {
    use access_identity_oauth::ports::profile::{SamlRefused, SamlSubject};
    let c = Cluster::new(&["ha-saml"]).await;
    let a = c.at(0);
    let subject = SamlSubject {
        issuer: String::from("https://idp.corp.example"),
        name_id: String::from("ann"),
        id: String::from("_a1"),
        not_on_or_after_ms: now() + 60_000,
        subject: None,
    };
    {
        let mut m = a.c.oauth.env().saml.0.lock().unwrap();
        m.insert(String::from("good"), Ok(subject.clone()));
        m.insert(
            String::from("good-2"),
            Ok(SamlSubject {
                id: String::from("_a2"),
                ..subject.clone()
            }),
        );
        m.insert(String::from("broken"), Err(SamlRefused::Signature));
    }
    let bearer = |assertion: &'static str| {
        let a = a.clone();
        async move {
            let client = a.assertion(a.issuer());
            a.token(
                &[
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:saml2-bearer",
                    ),
                    ("assertion", assertion),
                    ("client_assertion_type", JWT_BEARER),
                    ("client_assertion", &client),
                ],
                None,
            )
            .await
        }
    };
    assert_eq!(error(&bearer("good").await), "unauthorized_client");
    let profile = ClientProfileRow {
        saml_bearer_upstream: Some(String::from("corp-idp")),
        ..ClientProfileRow::default()
    };
    a.set_profile('c', "idp.client.saml_bearer", &profile)
        .await
        .unwrap();
    assert_eq!(error(&bearer("broken").await), "invalid_grant");
    let first = bearer("good").await;
    assert_eq!(error(&first), "invalid_grant");
    assert!(body_text(&first).contains("not a grant"), "{first:?}");
    let again = bearer("good").await;
    assert!(!body_text(&again).contains("not a grant"), "{again:?}");

    let exchange = |token_type: &'static str, token: &'static str| {
        let a = a.clone();
        async move {
            let client = a.assertion(a.issuer());
            a.token(
                &[
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    ("subject_token_type", token_type),
                    ("subject_token", token),
                    ("client_assertion_type", JWT_BEARER),
                    ("client_assertion", &client),
                ],
                None,
            )
            .await
        }
    };
    let saml2 = "urn:ietf:params:oauth:token-type:saml2";
    assert_eq!(
        error(&exchange("urn:ietf:params:oauth:token-type:saml1", "good-2").await),
        "invalid_request"
    );
    assert_eq!(error(&exchange(saml2, "broken").await), "invalid_grant");
    let taken = exchange(saml2, "good-2").await;
    assert!(
        !matches!(support::status(&taken), 400) || error(&taken) != "invalid_grant",
        "{taken:?}"
    );
    assert_eq!(error(&exchange(saml2, "good-2").await), "invalid_grant");
}

fn body_text(r: &Reply) -> String {
    match r {
        Reply::Json { body, .. } => body.clone(),
        other => format!("{other:?}"),
    }
}

// RFC 9701, OP-155 m.3 (k), Ek B 4717
#[tokio::test]
async fn introspection_answers_as_a_signed_jwt_when_asked() {
    let c = Cluster::new(&["ha-intro"]).await;
    let a = c.at(0);
    let code = a.code(&a.f.keyed).await;
    let t = body(&keyed_exchange(&a, &code, true).await, 200);
    let token = t["access_token"].as_str().unwrap().to_owned();
    let ask = |jwt: bool| {
        let a = a.clone();
        let token = token.clone();
        async move {
            let assertion = a.assertion(a.issuer());
            a.oauth()
                .introspect_as(
                    a.realm(),
                    &params(&[
                        ("token", token.as_str()),
                        ("client_assertion_type", JWT_BEARER),
                        ("client_assertion", assertion.as_str()),
                    ]),
                    None,
                    jwt,
                    &[],
                )
                .await
        }
    };
    assert_eq!(body(&ask(false).await, 200)["active"], true);
    let r = ask(true).await;
    let Reply::Jwt {
        body: jwt, media, ..
    } = r
    else {
        panic!("{r:?}");
    };
    assert_eq!(media, "application/token-introspection+jwt");
    let answer = realm_jws(&a, &jwt, "token-introspection+jwt").await;
    assert_eq!(answer["aud"], a.f.keyed.as_str());
    assert_eq!(answer["iss"], a.issuer());
    assert_eq!(answer["token_introspection"]["active"], true);
}

struct Crls(Vec<(String, Vec<u8>)>);

impl access_identity_x509::ports::Fetch for Crls {
    fn fetch<'a>(
        &'a self,
        request: access_identity_x509::ports::Request<'a>,
    ) -> access_identity_x509::ports::Fetched<'a> {
        let found = match request {
            access_identity_x509::ports::Request::Crl { url } => self
                .0
                .iter()
                .find(|(u, _)| u == url)
                .map(|(_, b)| b.clone()),
            access_identity_x509::ports::Request::Ocsp { .. } => None,
        };
        Box::pin(async move { found.ok_or(access_identity_x509::ports::Unreachable) })
    }
}

struct Accepts(Option<[u8; 16]>);

impl access_identity_x509::ports::CaTrust for Accepts {
    fn accepted(&self, _: [u8; 32], issuer: [u8; 16]) -> access_identity_x509::ports::Held<'_> {
        let yes = self.0 == Some(issuer);
        Box::pin(async move { Ok(yes) })
    }
}

// RFC 8705 §2.1, MD-8, OP-155 m.3 (k), (m), Ek B 4692, 4713
#[tokio::test]
async fn pki_clients_go_through_the_realm_ca_and_revocation() {
    use access_identity_oauth::adapters::certificates::X509ClientCertificates;
    use access_identity_x509::testing::{Ca, LeafSpec, serial};
    let c = Cluster::new(&["ha-pki"]).await;
    let a = c.at(0);
    let now_s = now() / 1000;
    let url = "http://crl.example/root.crl";
    let root = Ca::root_at("Client Root", now_s);
    let spec = |n: u8| LeafSpec {
        cn: "svc",
        email: Some("svc@example.com"),
        crl: Some(url),
        serial: n,
        ..LeafSpec::default()
    };
    let good = root.leaf(&spec(2)).der;
    let revoked = root.leaf(&spec(3)).der;
    let foreign = Ca::root_at("Other Root", now_s).leaf(&spec(4)).der;
    let crl = root.crl(&[&serial(&revoked)], now_s - 3600, now_s + 3600);
    let issuer = access_identity_x509::domain::login::ca_issuer(&root.der).unwrap();
    let real = |trusted: bool| -> std::sync::Arc<
        dyn access_identity_oauth::ports::profile::ClientCertificates + Sync,
    > {
        std::sync::Arc::new(X509ClientCertificates::new(
            a.c.db.app.clone(),
            std::sync::Arc::new(access_identity_x509::app::Revocation::new(
                std::sync::Arc::new(Crls(vec![(String::from(url), crl.clone())])),
            )),
            std::sync::Arc::new(Accepts(trusted.then_some(issuer))),
        ))
    };
    {
        let mut tx =
            access_store::identity::TenantTx::begin(&a.c.db.app, a.realm().tenant, a.realm().realm)
                .await
                .unwrap();
        let b = a.bound(&mut tx, "idp.realm.certificate_login").await;
        tx.put_certificate_login(
            &b,
            &access_store::certificate::CertificateLoginRow {
                enabled: true,
                rule: String::from("san_email"),
                anchors: vec![root.der.clone()],
                piv_policies: Vec::new(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    a.set_profile(
        'b',
        UPDATE,
        &ClientProfileRow {
            tls_auth: Some(String::from("tls_client_auth")),
            tls_name: Some((String::from("san_email"), String::from("svc@example.com"))),
            ..ClientProfileRow::default()
        },
    )
    .await
    .unwrap();
    *a.c.oauth.env().certs.1.lock().unwrap() = Some(real(true));
    for refused in [&revoked, &foreign] {
        let code = confidential_code(&a).await;
        let r = mtls_exchange(&a, &code, std::slice::from_ref(refused)).await;
        assert_eq!(error(&r), "invalid_client");
    }
    let code = confidential_code(&a).await;
    let t = body(
        &mtls_exchange(&a, &code, std::slice::from_ref(&good)).await,
        200,
    );
    assert_eq!(
        claims(t["access_token"].as_str().unwrap())["cnf"]["x5t#S256"],
        x5t(&good)
    );
    *a.c.oauth.env().certs.1.lock().unwrap() = Some(real(false));
    let code = confidential_code(&a).await;
    let r = mtls_exchange(&a, &code, std::slice::from_ref(&good)).await;
    assert_eq!(error(&r), "invalid_client");
}
