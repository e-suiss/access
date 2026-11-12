//! The realm's post-quantum signing profile on the real server path (CR-41, CR-43, CR-44, HL-27,
//! OP-159 m.3 (a), (d), (o), (p), (r), (t), OP-153 m.3 (gg)): `putSigningProfile` opens an
//! ML-DSA key set in the identity signer, the realm's JWKS publishes it as `AKP`, discovery
//! declares it, and only a client that registered ML-DSA gets ML-DSA tokens; FIPS and the
//! post-quantum profile exclude each other in either order; without an ML-DSA key store the
//! profile is refused.

use access_kernel::verify::cose::KeySet;
use access_kernel::verify::jws::{Origin, verify_compact};

use super::writes::Written;
use super::*;

const SIGNING: &str = "/admin/v1/realms/acme/signing";
const PROFILE: &str = "/admin/v1/realms/acme/settings/signing-profile";
const CRYPTO: &str = "/admin/v1/realms/acme/settings/crypto-profile";

async fn put(c: &Console, op: &str, path: &str, body: serde_json::Value) -> Written {
    c.rest_write(&Method::PUT, path, (op, None), body, None)
        .await
}

async fn signing(c: &Console) -> serde_json::Value {
    let (status, body, _) = c.rest_read(SIGNING).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn discovery(c: &Console, doc: access_identity_oauth::domain::metadata::Document) -> String {
    use access_identity_oauth::app::Reply;
    let d = access_identity_oauth::app::Discovery::new(
        PgDirectory::new(c.w.db.router.clone()).with_facts(c.w.db.app.clone()),
        SignerKeys::new(c.w.identity_signer.clone()),
    );
    match d.serve(doc, HOST, Some("acme")).await {
        Reply::Metadata(doc) | Reply::Jwks(doc) => doc,
        _ => panic!("no document"),
    }
}

async fn jwks(c: &Console) -> String {
    discovery(c, access_identity_oauth::domain::metadata::Document::Jwks).await
}

async fn id_token_algs(c: &Console) -> Vec<String> {
    let doc = discovery(
        c,
        access_identity_oauth::domain::metadata::Document::OpenIdConfiguration,
    )
    .await;
    let doc: serde_json::Value = serde_json::from_str(&doc).unwrap();
    doc["id_token_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| String::from(a.as_str().unwrap()))
        .collect()
}

/// The `AKP` keys of the realm's JWKS as a relying party reads them.
fn akp(doc: &str) -> KeySet {
    let doc: serde_json::Value = serde_json::from_str(doc).unwrap();
    let mut set = KeySet::default();
    for k in doc["keys"].as_array().unwrap() {
        if k["kty"] != "AKP" {
            continue;
        }
        assert!(k.get("priv").is_none(), "{k}");
        let alg = access_crypto::jose::JwsAlg::ml_dsa(k["alg"].as_str().unwrap()).unwrap();
        let key = access_kernel::verify::cose::PublicKey::MlDsa(
            alg.algorithm(),
            b64url_decode(k["pub"].as_str().unwrap()).unwrap(),
        );
        let kid: [u8; 32] = b64url_decode(k["kid"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(thumbprint(&key), kid);
        set.allowed.insert(alg.algorithm());
        set.insert(kid, key).unwrap();
    }
    set
}

/// A `client_secret_basic` client: its id and secret.
async fn client(c: &Console, name: &str) -> (String, String) {
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/clients",
            ("createClient", None),
            serde_json::json!({
                "display_name": name,
                "token_endpoint_auth_method": "client_secret_basic",
                "redirect_uris": [format!("https://{name}.example/cb")],
            }),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    (
        String::from(w.body["resource"]["client_id"].as_str().unwrap()),
        String::from(w.body["client_secret"].as_str().unwrap()),
    )
}

async fn client_alg(c: &Console, id: &str, alg: &str) -> Written {
    c.rest_write(
        &Method::PUT,
        &format!("/admin/v1/realms/acme/clients/{id}/signing-alg"),
        ("putClientSigningAlg", Some(id)),
        serde_json::json!({ "id_token_signed_response_alg": alg }),
        None,
    )
    .await
}

/// The client's RFC 9701 introspection answer as the realm signs it: its media type and body.
async fn introspection(c: &Console, (id, secret): &(String, String)) -> (String, String) {
    let basic = base64(format!("{id}:{secret}").as_bytes());
    let r = Request::post("/realms/acme/introspect")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/token-introspection+jwt")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .body(Body::from("token=not-a-token"))
        .unwrap();
    let (reply, bytes) = send(&c.oauth, r).await;
    assert_eq!(reply.status(), StatusCode::OK);
    let media = reply
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|h| String::from(h.to_str().unwrap()))
        .unwrap_or_default();
    (media, String::from_utf8(bytes).unwrap())
}

/// Standard base64 with padding (RFC 4648 §4), for HTTP Basic (RFC 6749 §2.3.1).
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn header_alg(jwt: &str) -> String {
    let head = jwt.split('.').next().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b64url_decode(head).unwrap()).unwrap();
    String::from(v["alg"].as_str().unwrap())
}

// CR-41, CR-43, MD-3, RR-36, OP-159 m.3 (a), (o), (p), (t), Ek B 6184
#[tokio::test]
async fn the_signing_profile_publishes_akp_and_signs_ml_dsa_only_for_clients_that_ask() {
    let c = console("signing-pq", true).await;
    let before = signing(&c).await;
    assert_eq!(before["signing_profile"], serde_json::Value::Null);
    assert_eq!(before["algorithms"], serde_json::json!(["ES256"]));
    assert_eq!(before["kex_share"], "optimistic");
    assert_eq!(before["fips"], false);
    assert_eq!(before["fips_module"], suiss_crypto::fips::BUILD);
    assert_eq!(before["pq_reanchor"], serde_json::Value::Null);
    assert!(akp(&jwks(&c).await).keys.is_empty());
    assert!(
        !id_token_algs(&c)
            .await
            .iter()
            .any(|a| a.starts_with("ML-DSA"))
    );
    let classic = client(&c, "classic").await;
    let pq = client(&c, "quantum").await;

    // OP-159 m.3 (o)
    let w = client_alg(&c, &pq.0, "ML-DSA-65").await;
    assert_eq!(w.status, StatusCode::CONFLICT, "{}", w.body);
    assert!(
        w.body.to_string().contains("algorithm-profile-conflict"),
        "{}",
        w.body
    );

    let w = put(
        &c,
        "putSigningProfile",
        PROFILE,
        serde_json::json!({"profile": "ml-dsa-65"}),
    )
    .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let open = signing(&c).await;
    assert_eq!(open["signing_profile"], "ml-dsa-65");
    assert_eq!(
        open["algorithms"],
        serde_json::json!(["ES256", "ML-DSA-65"])
    );
    let keys = akp(&jwks(&c).await);
    assert_eq!(
        keys.keys.len(),
        2,
        "the founding key and its published backup"
    );
    assert!(id_token_algs(&c).await.contains(&String::from("ML-DSA-65")));

    let w = client_alg(&c, &pq.0, "ML-DSA-87").await;
    assert_eq!(w.status, StatusCode::CONFLICT, "{}", w.body);
    let w = client_alg(&c, &pq.0, "ML-DSA-65").await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);

    // MD-3
    let (media, jwt) = introspection(&c, &classic).await;
    assert_eq!(media, "application/token-introspection+jwt");
    assert_eq!(header_alg(&jwt), "ES256");
    let (media, jwt) = introspection(&c, &pq).await;
    assert_eq!(media, "application/token-introspection+jwt");
    assert_eq!(header_alg(&jwt), "ML-DSA-65");
    // CR-43, OP-159 m.3 (p)
    assert!(jwt.len() <= 8192, "{}", jwt.len());
    let v = verify_compact(
        &access_crypto::AwsLcBackend,
        &jwt,
        &keys,
        "token-introspection+jwt",
        Origin::Native,
    )
    .unwrap();
    assert_eq!(v.algorithm, access_kernel::verify::cose::Algorithm::MlDsa65);
    let claims: serde_json::Value = serde_json::from_slice(&v.payload).unwrap();
    assert_eq!(claims["aud"], pq.0.as_str());
    assert_eq!(claims["token_introspection"]["active"], false);

    // CR-12 m.3, OP-159 m.3 (t)
    let w = put(
        &c,
        "putKexShare",
        "/admin/v1/realms/acme/settings/kex-share",
        serde_json::json!({"mode": "advertise-only"}),
    )
    .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    assert_eq!(signing(&c).await["kex_share"], "advertise-only");

    // OP-159 m.3 (a), TI-9
    let w = put(&c, "putSigningProfile", PROFILE, serde_json::json!({})).await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let closed = signing(&c).await;
    assert_eq!(closed["signing_profile"], serde_json::Value::Null);
    assert_eq!(closed["algorithms"], serde_json::json!(["ES256"]));
    assert!(akp(&jwks(&c).await).keys.is_empty());
    assert!(
        !id_token_algs(&c)
            .await
            .iter()
            .any(|a| a.starts_with("ML-DSA"))
    );
    let (media, body) = introspection(&c, &pq).await;
    assert_ne!(media, "application/token-introspection+jwt", "{body}");
    assert!(!body.starts_with("eyJ"), "{body}");
    let (_, jwt) = introspection(&c, &classic).await;
    assert_eq!(header_alg(&jwt), "ES256");

    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let events: Vec<String> = t
        .list_audit(64)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.event_type)
        .collect();
    t.commit().await.unwrap();
    for e in ["signing_profile.opened", "signing_profile.closed"] {
        assert!(events.iter().any(|x| x == e), "{e}: {events:?}");
    }
}

// CR-15, CR-44, HL-27, OP-158 m.9, OP-159 m.3 (r), Ek B 6267, 6334
#[tokio::test]
async fn fips_and_the_post_quantum_profile_exclude_each_other_in_either_order() {
    let c = console("signing-fips", true).await;
    let w = put(
        &c,
        "putCryptoProfile",
        CRYPTO,
        serde_json::json!({"fips": true}),
    )
    .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let w = put(
        &c,
        "putSigningProfile",
        PROFILE,
        serde_json::json!({"profile": "ml-dsa-65"}),
    )
    .await;
    assert_eq!(w.status, StatusCode::CONFLICT, "{}", w.body);
    assert!(
        w.body.to_string().contains("fips-pq-exclusive"),
        "{}",
        w.body
    );
    assert_eq!(
        signing(&c).await["signing_profile"],
        serde_json::Value::Null
    );
    assert!(akp(&jwks(&c).await).keys.is_empty());

    // CR-15, OP-158 m.9
    let (_, _, etag) = c.rest_read("/admin/v1/realms/acme/settings").await;
    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/jose-alg",
            ("putJoseAlg", None),
            serde_json::json!({"alg": "Ed25519"}),
            etag.as_deref(),
        )
        .await;
    assert_eq!(w.status, StatusCode::CONFLICT, "{}", w.body);
    assert!(
        w.body.to_string().contains("algorithm-profile-conflict"),
        "{}",
        w.body
    );

    let w = put(
        &c,
        "putCryptoProfile",
        CRYPTO,
        serde_json::json!({"fips": false}),
    )
    .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let w = put(
        &c,
        "putSigningProfile",
        PROFILE,
        serde_json::json!({"profile": "ml-dsa-65"}),
    )
    .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let w = put(
        &c,
        "putCryptoProfile",
        CRYPTO,
        serde_json::json!({"fips": true}),
    )
    .await;
    assert_eq!(w.status, StatusCode::CONFLICT, "{}", w.body);
    assert!(
        w.body.to_string().contains("fips-pq-exclusive"),
        "{}",
        w.body
    );
    let s = signing(&c).await;
    assert_eq!(s["fips"], false);
    assert_eq!(s["signing_profile"], "ml-dsa-65");
    // CR-15, OP-159 m.3 (r)
    assert_eq!(s["fips_module"], false);
}

// CR-18, TI-9, OP-159 m.3 (d), m.13 (a)
#[tokio::test]
async fn without_an_hsm_ml_dsa_mechanism_the_profile_is_refused_and_nothing_falls_back() {
    let name = format!("{}signing", super::super::PQ_IN_TOKEN);
    let c = console(&name, true).await;
    let probe = c.w.keys.ml_dsa_mechanisms().unwrap();
    assert!(!probe.available(), "{probe:?}");
    let w = put(
        &c,
        "putSigningProfile",
        PROFILE,
        serde_json::json!({"profile": "ml-dsa-65"}),
    )
    .await;
    assert_eq!(w.status, StatusCode::CONFLICT, "{}", w.body);
    assert!(
        w.body.to_string().contains("pq-key-unavailable"),
        "{}",
        w.body
    );
    assert_eq!(
        signing(&c).await["signing_profile"],
        serde_json::Value::Null
    );
    assert!(akp(&jwks(&c).await).keys.is_empty());
    assert!(
        !id_token_algs(&c)
            .await
            .iter()
            .any(|a| a.starts_with("ML-DSA"))
    );
}

// CR-4, RR-36, OP-159 m.3 (o), Ek B 6330
#[tokio::test]
async fn encrypted_identity_tokens_stay_classical_under_the_post_quantum_profile() {
    let c = console("signing-jwe", true).await;
    let w = put(
        &c,
        "putSigningProfile",
        PROFILE,
        serde_json::json!({"profile": "ml-dsa-65"}),
    )
    .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let (id, _) = client(&c, "sealed").await;
    for alg in [
        "ML-KEM-768",
        "ML-KEM-768+A256KW",
        "ECDH-ES+ML-KEM-768",
        "HPKE-0",
        "HPKE-1",
    ] {
        let w = c
            .rest_write(
                &Method::PUT,
                &format!("/admin/v1/realms/acme/clients/{id}/encryption"),
                ("putClientEncryption", Some(&id)),
                serde_json::json!({ "alg": alg, "jwks": { "keys": [] }, "id_token": true }),
                None,
            )
            .await;
        assert!(w.status.is_client_error(), "{alg}: {} {}", w.status, w.body);
    }
    let doc = discovery(
        &c,
        access_identity_oauth::domain::metadata::Document::OpenIdConfiguration,
    )
    .await;
    let doc: serde_json::Value = serde_json::from_str(&doc).unwrap();
    for (k, v) in doc.as_object().unwrap() {
        if k.ends_with("_encryption_alg_values_supported") {
            assert_eq!(
                v,
                &serde_json::json!(["ECDH-ES+A256KW", "RSA-OAEP-256"]),
                "{k}"
            );
        }
        if k.ends_with("_encryption_enc_values_supported") {
            assert_eq!(v, &serde_json::json!(["A256GCM"]), "{k}");
        }
    }
    let text = doc.to_string().to_ascii_lowercase();
    for pq in ["ml-kem", "hpke"] {
        assert!(!text.contains(pq), "{pq}");
    }
}

// CR-38, CR-43, OP-159 m.3 (p), Ek B 6224
#[tokio::test]
async fn the_largest_ml_dsa_token_fits_the_header_budget() {
    use access_crypto::budget::Carrier;
    let c = console("signing-budget", true).await;
    let w = put(
        &c,
        "putSigningProfile",
        PROFILE,
        serde_json::json!({"profile": "ml-dsa-87"}),
    )
    .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let pq = client(&c, "large").await;
    let w = client_alg(&c, &pq.0, "ML-DSA-87").await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let (media, jwt) = introspection(&c, &pq).await;
    assert_eq!(media, "application/token-introspection+jwt");
    assert_eq!(header_alg(&jwt), "ML-DSA-87");
    assert_eq!(Carrier::Header.check(jwt.len()), Ok(()), "{}", jwt.len());
    assert!(Carrier::Cookie.check(jwt.len()).is_err(), "{}", jwt.len());
    let keys = akp(&jwks(&c).await);
    let v = verify_compact(
        &access_crypto::AwsLcBackend,
        &jwt,
        &keys,
        "token-introspection+jwt",
        Origin::Native,
    )
    .unwrap();
    assert_eq!(v.algorithm, access_kernel::verify::cose::Algorithm::MlDsa87);
}
