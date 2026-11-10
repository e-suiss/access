//! The verifier through its router on real Postgres (OP-155 m.3 (p); IDP-21): a test PID
//! provider and attestation provider under a trusted list, a wallet that answers with SD-JWT VC
//! or mdoc over `direct_post.jwt`, and Claim Ingest as a recording port. The real Access side
//! (Acceptance, selection) is exercised in `access-server`'s bootstrap tests.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "test code"
)]

mod support;

use access_kernel::json::b64url_encode;
use access_vc_verifier::domain::cbor::Cbor;
use access_vc_verifier::domain::trust::{GRANTED, TrustedLists};
use axum::body::Body;
use axum::http::{Request, header};
use serde_json::{Value, json};
use suiss_crypto::signer::SoftSigner;
use support::*;

const ISS: &str = "https://issuer.test";

fn holder() -> SoftSigner {
    SoftSigner::generate_p256().unwrap().0
}

fn pid_claims() -> Vec<(&'static str, Value)> {
    vec![
        ("given_name", json!("Ada")),
        ("family_name", json!("Lovelace")),
        ("birthdate", json!("1815-12-10")),
        ("age_over_18", json!(true)),
    ]
}

async fn answer_sd_jwt(
    r: &Rig,
    query: &Value,
    issuer: &IssuerKey<'_>,
    vct: &str,
    names: &[&str],
    extra: &Value,
) -> (String, u16, Value) {
    let h = holder();
    let (id, object) = open(&r.router, query, None).await;
    let c = sd_jwt_vc(issuer, ISS, vct, &h, &pid_claims(), extra);
    let p = present(
        &c,
        names,
        &h,
        object["client_id"].as_str().unwrap(),
        object["nonce"].as_str().unwrap(),
    );
    let qid = query["credentials"][0]["id"].as_str().unwrap();
    let (status, body) = respond(&r.router, &id, &object, &json!({ qid: [p] })).await;
    (id, status, body)
}

fn classes(r: &Rig) -> Vec<(String, Value)> {
    r.access.0.lock().unwrap().clone()
}

// IDP-21, Ek B 4831, 4835, 5055
#[tokio::test]
async fn pid_from_a_listed_pid_provider_is_high() {
    let pki = pki("issuer.test");
    let r = rig(lists(&[(PID_TYPE, &pki.root)]), &[]).await;
    let (id, status, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &["given_name", "family_name", "age_over_18"],
        &json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (s, out) = result(&r.router, &id, None).await;
    assert_eq!(s, 200);
    assert_eq!(out["state"], "verified", "{out}");
    assert_eq!(out["credentials"][0]["loa_eidas"], 3);
    assert_eq!(out["credentials"][0]["issuer_standing"], "pid-provider");
    let sent: Vec<String> = out["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["class"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(sent, ["identity_binding_person", "vc_age_over_18"]);
    let ingested = classes(&r);
    assert_eq!(ingested.len(), 2);
    assert_eq!(ingested[0].1["carrier"], "cose");
    assert!(ingested[0].1["body"].is_string());
    assert!(!out.to_string().contains("Lovelace"));
}

// IDP-21, Ek B 4835, 5055
#[tokio::test]
async fn non_pid_never_sets_loa_eidas_high() {
    let pki = pki("issuer.test");
    let r = rig(lists(&[(PID_TYPE, &pki.root)]), &[]).await;
    let mut q = pid_query();
    q["credentials"][0]["meta"]["vct_values"] = json!(["urn:example:age"]);
    let (id, status, _) = answer_sd_jwt(
        &r,
        &q,
        &IssuerKey::X5c(&pki, false),
        "urn:example:age",
        &["given_name", "family_name", "age_over_18"],
        &json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["state"], "verified");
    assert_eq!(out["credentials"][0]["loa_eidas"], Value::Null);
    assert_eq!(out["claims"].as_array().unwrap().len(), 1);
    assert_eq!(out["claims"][0]["class"], "vc_age_over_18");

    let eaa = support::pki("issuer.test");
    let r = rig(lists(&[(EAA_TYPE, &eaa.root)]), &[]).await;
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&eaa, false),
        "urn:eudi:pid:1",
        &["given_name", "family_name", "age_over_18"],
        &json!({}),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["state"], "verified");
    assert_eq!(
        out["credentials"][0]["issuer_standing"],
        "attestation-provider"
    );
    assert_eq!(out["credentials"][0]["loa_eidas"], Value::Null);
    assert!(
        classes(&r)
            .iter()
            .all(|(_, b)| !b.to_string().contains("identity_binding"))
    );
}

// IDP-21, Ek B 4982, 4833
#[tokio::test]
async fn an_extra_disclosure_is_refused() {
    let pki = pki("issuer.test");
    let r = rig(lists(&[(PID_TYPE, &pki.root)]), &[]).await;
    let (id, status, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &["given_name", "family_name", "age_over_18", "birthdate"],
        &json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["state"], "refused");
    assert_eq!(out["reason"], "dcql-extra-disclosure");
    assert_eq!(classes(&r).len(), 0);

    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &["given_name", "family_name"],
        &json!({}),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "dcql-claim-missing");
    assert_eq!(classes(&r).len(), 0);
}

// IDP-21, Ek B 4834
#[tokio::test]
async fn an_issuer_outside_the_lotl_is_refused() {
    let listed = pki("issuer.test");
    let other = pki("issuer.test");
    let r = rig(lists(&[(PID_TYPE, &listed.root)]), &[]).await;
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&other, false),
        "urn:eudi:pid:1",
        &["given_name", "family_name", "age_over_18"],
        &json!({}),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "issuer-untrusted");
    assert_eq!(classes(&r).len(), 0);

    let mut stale: TrustedLists = lists(&[(PID_TYPE, &listed.root)]);
    stale.next_update_ms = now_ms() - 1;
    let r = rig(stale, &[]).await;
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&listed, false),
        "urn:eudi:pid:1",
        &["given_name", "family_name", "age_over_18"],
        &json!({}),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "trusted-list-unusable");

    let wrong_name = pki("other.test");
    let r = rig(lists(&[(PID_TYPE, &wrong_name.root)]), &[]).await;
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&wrong_name, false),
        "urn:eudi:pid:1",
        &["given_name", "family_name", "age_over_18"],
        &json!({}),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "issuer-binding");
}

fn status_list_jwt(pki: &Pki, uri: &str, bits: &[u8]) -> String {
    let lst = miniz_oxide::deflate::compress_to_vec_zlib(bits, 6);
    sign_jwt(
        &pki.signer,
        &json!({ "alg": "ES256", "typ": "statuslist+jwt", "x5c": [access_vc_verifier::domain::request::base64(&pki.leaf)] }),
        &json!({
            "sub": uri,
            "iat": now_ms() / 1000,
            "exp": now_ms() / 1000 + 3600,
            "status_list": { "bits": 1, "lst": b64url_encode(&lst) },
        }),
    )
}

// IDP-21, Ek B 4921
#[tokio::test]
async fn a_revoked_credential_is_not_ingested() {
    let pki = pki("issuer.test");
    let r = rig(lists(&[(PID_TYPE, &pki.root)]), &[]).await;
    let uri = "https://issuer.test/status/1";
    r.fetch.0.lock().unwrap().insert(
        uri.to_owned(),
        status_list_jwt(&pki, uri, &[0b0000_0100, 0]).into_bytes(),
    );
    let names = ["given_name", "family_name", "age_over_18"];
    let status = |idx: u64| json!({ "status": { "status_list": { "idx": idx, "uri": uri } } });
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &names,
        &status(2),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "status-revoked");
    assert_eq!(classes(&r).len(), 0);

    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &names,
        &status(1),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["state"], "verified", "{out}");

    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &names,
        &status(99),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "status-index");

    let gone =
        json!({ "status": { "status_list": { "idx": 1, "uri": "https://issuer.test/status/9" } } });
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &names,
        &gone,
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "fetch-failed");
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    out
}

// IDP-21, Ek B 4921, 4828
#[tokio::test]
async fn a_bitstring_status_list_revokes() {
    let pki = pki("issuer.test");
    let r = rig(lists(&[(PID_TYPE, &pki.root)]), &[]).await;
    let uri = "https://issuer.test/bsl/1";
    let di = "https://issuer.test/bsl/di";
    let list = |proof: bool, at: &str| {
        let mut vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": at,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": ISS,
            "credentialSubject": {
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": format!("u{}", b64url_encode(&gzip(&[0b0100_0000, 0]))),
            },
        });
        if proof {
            vc["proof"] = json!({ "type": "DataIntegrityProof" });
        }
        sign_jwt(
            &pki.signer,
            &json!({ "alg": "ES256", "typ": "vc+jwt", "x5c": [access_vc_verifier::domain::request::base64(&pki.leaf)] }),
            &vc,
        )
    };
    r.fetch
        .0
        .lock()
        .unwrap()
        .insert(uri.to_owned(), list(false, uri).into_bytes());
    r.fetch
        .0
        .lock()
        .unwrap()
        .insert(di.to_owned(), list(true, di).into_bytes());
    let entry = |idx: &str, at: &str| {
        json!({ "credentialStatus": {
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": idx,
            "statusListCredential": at,
        }})
    };
    let names = ["given_name", "family_name", "age_over_18"];
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &names,
        &entry("1", uri),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "status-revoked");
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &names,
        &entry("0", uri),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["state"], "verified", "{out}");
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&pki, false),
        "urn:eudi:pid:1",
        &names,
        &entry("0", di),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "status-list");
}

fn mdoc_query() -> Value {
    json!({ "credentials": [{
        "id": "mdl",
        "format": "mso_mdoc",
        "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
        "claims": [
            { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
            { "path": ["eu.europa.ec.eudi.pid.1", "age_over_18"] },
        ],
    }]})
}

async fn answer_mdoc(r: &Rig, pki: &Pki, items: &[(&str, Cbor)], tamper: bool) -> String {
    let device = holder();
    let (id, object) = open(&r.router, &mdoc_query(), None).await;
    let t = Transcript {
        client_id: object["client_id"].as_str().unwrap(),
        nonce: object["nonce"].as_str().unwrap(),
        thumb: thumb(&object),
        response_uri: object["response_uri"].as_str().unwrap(),
    };
    let doc = mdoc(
        pki,
        &device,
        "eu.europa.ec.eudi.pid.1",
        "eu.europa.ec.eudi.pid.1",
        items,
        &t,
        tamper,
    );
    let (status, _) = respond(&r.router, &id, &object, &json!({ "mdl": [doc] })).await;
    assert_eq!(status, 200);
    id
}

// IDP-21, Ek B 4832, 4835
#[tokio::test]
async fn an_mdoc_pid_is_verified() {
    let pki = pki("issuer.test");
    let r = rig(lists(&[(PID_TYPE, &pki.root)]), &[]).await;
    let items = [
        ("family_name", Cbor::text("Lovelace")),
        ("age_over_18", Cbor::Bool(true)),
    ];
    let id = answer_mdoc(&r, &pki, &items, false).await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["state"], "verified", "{out}");
    assert_eq!(out["credentials"][0]["format"], "mso_mdoc");
    assert_eq!(out["credentials"][0]["loa_eidas"], 3);

    let id = answer_mdoc(&r, &pki, &items, true).await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "mdoc-digest");

    let extra = [
        ("family_name", Cbor::text("Lovelace")),
        ("age_over_18", Cbor::Bool(true)),
        ("birth_date", Cbor::text("1815-12-10")),
    ];
    let id = answer_mdoc(&r, &pki, &extra, false).await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["reason"], "dcql-extra-disclosure");
}

// IDP-21, Ek B 4837
#[tokio::test]
async fn did_web_and_did_jwk_issuers_resolve() {
    let key = holder();
    let jwk = jwk_of(&key);
    let did_jwk = format!("did:jwk:{}", b64url_encode(jwk.to_string().as_bytes()));
    let did_web = "did:web:issuer.test:people";
    let r = rig(lists(&[]), &[&did_jwk, did_web, "did:key:z6Mk"]).await;
    r.fetch.0.lock().unwrap().insert(
        String::from("https://issuer.test/people/did.json"),
        json!({
            "id": did_web,
            "verificationMethod": [{ "id": format!("{did_web}#k1"), "type": "JsonWebKey", "controller": did_web, "publicKeyJwk": jwk }],
            "assertionMethod": [format!("{did_web}#k1")],
        })
        .to_string()
        .into_bytes(),
    );
    let mut q = pid_query();
    q["credentials"][0]["meta"]["vct_values"] = json!(["urn:example:person"]);
    for (iss, kid, expect) in [
        (did_jwk.as_str(), format!("{did_jwk}#0"), "verified"),
        (did_web, format!("{did_web}#k1"), "verified"),
        (did_web, format!("{did_web}#k2"), "refused"),
        ("did:key:z6Mk", String::from("did:key:z6Mk#z6Mk"), "refused"),
    ] {
        let h = holder();
        let (id, object) = open(&r.router, &q, None).await;
        let c = sd_jwt_vc(
            &IssuerKey::Kid(&key, &kid),
            iss,
            "urn:example:person",
            &h,
            &pid_claims(),
            &json!({}),
        );
        let p = present(
            &c,
            &["given_name", "family_name", "age_over_18"],
            &h,
            object["client_id"].as_str().unwrap(),
            object["nonce"].as_str().unwrap(),
        );
        respond(&r.router, &id, &object, &json!({ "pid": [p] })).await;
        let (_, out) = result(&r.router, &id, None).await;
        assert_eq!(out["state"], expect, "{iss} {kid} {out}");
        if expect == "verified" {
            assert_eq!(
                out["credentials"][0]["issuer_standing"],
                "configured-issuer"
            );
            assert_eq!(out["credentials"][0]["loa_eidas"], Value::Null);
        }
    }
    let (_, out) = {
        let h = holder();
        let (id, object) = open(&r.router, &q, None).await;
        let c = sd_jwt_vc(
            &IssuerKey::Kid(&key, "did:key:z6Mk#z6Mk"),
            "did:key:z6Mk",
            "urn:example:person",
            &h,
            &pid_claims(),
            &json!({}),
        );
        let p = present(
            &c,
            &["given_name", "family_name", "age_over_18"],
            &h,
            object["client_id"].as_str().unwrap(),
            object["nonce"].as_str().unwrap(),
        );
        respond(&r.router, &id, &object, &json!({ "pid": [p] })).await;
        result(&r.router, &id, None).await
    };
    assert_eq!(out["reason"], "did-method-unsupported");
}

// IDP-21, Ek B 4833
#[tokio::test]
async fn same_device_and_cross_device_modes() {
    let pki = pki("issuer.test");
    let r = rig(lists(&[(PID_TYPE, &pki.root)]), &[]).await;
    let (id, object) = open(&r.router, &pid_query(), Some("https://rp.test/back")).await;
    assert!(
        object["client_id"]
            .as_str()
            .unwrap()
            .starts_with("x509_hash:")
    );
    assert_eq!(object["response_mode"], "direct_post.jwt");
    assert_eq!(object["response_type"], "vp_token");
    assert_eq!(object["dcql_query"], pid_query());
    let (_, pending) = result(&r.router, &id, None).await;
    assert_eq!(pending["state"], "pending");
    let h = holder();
    let c = sd_jwt_vc(
        &IssuerKey::X5c(&pki, true),
        ISS,
        "urn:eudi:pid:1",
        &h,
        &pid_claims(),
        &json!({}),
    );
    let p = present(
        &c,
        &["given_name", "family_name", "age_over_18"],
        &h,
        object["client_id"].as_str().unwrap(),
        object["nonce"].as_str().unwrap(),
    );
    let (status, back) = respond(&r.router, &id, &object, &json!({ "pid": [p.clone()] })).await;
    assert_eq!(status, 200);
    let redirect = back["redirect_uri"].as_str().unwrap();
    let code = redirect
        .strip_prefix("https://rp.test/back#response_code=")
        .unwrap();
    let (s, _) = result(&r.router, &id, None).await;
    assert_eq!(s, 404);
    let (s, out) = result(&r.router, &id, Some(code)).await;
    assert_eq!(s, 200);
    assert_eq!(out["state"], "verified", "{out}");
    let (again, _) = respond(&r.router, &id, &object, &json!({ "pid": [p] })).await;
    assert_eq!(again, 409);

    let (s, b) = call(
        &r.router,
        Request::post("/vc-verifier/v1/presentations")
            .header(header::AUTHORIZATION, "Bearer someone-else")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(s, 401, "{}", String::from_utf8_lossy(&b));
    let (s, _) = call(
        &r.router,
        Request::get("/vc-verifier/v1/trusted-lists")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, 200);
}

// IDP-21, Ek B 4982, 4828
#[tokio::test]
async fn dcql_outside_the_profile_is_refused() {
    let r = rig(lists(&[]), &[]).await;
    for (q, code) in [
        (
            json!({ "credentials": [{ "id": "a", "format": "ldp_vc", "meta": {}, "claims": [{ "path": ["x"] }] }] }),
            "dcql-unsupported",
        ),
        (
            json!({ "credentials": [{ "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["t"] } }] }),
            "dcql-no-claims",
        ),
        (
            json!({ "credentials": [{ "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["t"] }, "claims": [{ "path": ["x"], "values": [1] }] }] }),
            "dcql-unsupported",
        ),
        (
            json!({ "credentials": [], "credential_sets": [] }),
            "dcql-unsupported",
        ),
    ] {
        let body = json!({
            "domain": format!("sha-256:{}", b64url_encode(&DOMAIN)),
            "subject": b64url_encode(&SUBJECT),
            "dcql_query": q,
            "mode": "cross-device",
        });
        let (s, b) = call(
            &r.router,
            Request::post("/vc-verifier/v1/presentations")
                .header(header::AUTHORIZATION, format!("Bearer {CALLER}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(s, 400);
        assert_eq!(json_of(&b)["code"], code);
    }
}

fn summary(tsl_type: &str, next: &str, pointers: &[&str], services: &[(&str, &[u8])]) -> Vec<u8> {
    use suiss_crypto::dcbor::{self, Limits, Value};
    let v = Value::Map(vec![
        (
            Value::text("pointers"),
            Value::Array(
                pointers
                    .iter()
                    .map(|l| {
                        Value::Map(vec![
                            (Value::text("location"), Value::text(l)),
                            (Value::text("certificates"), Value::Array(vec![])),
                        ])
                    })
                    .collect(),
            ),
        ),
        (Value::text("sequence"), Value::Unsigned(9)),
        (Value::text("tsl_type"), Value::text(tsl_type)),
        (Value::text("next_update"), Value::text(next)),
        (
            Value::text("services"),
            Value::Array(
                services
                    .iter()
                    .map(|(t, c)| {
                        Value::Map(vec![
                            (Value::text("provider"), Value::text("P")),
                            (Value::text("service_type"), Value::text(t)),
                            (Value::text("status"), Value::text(GRANTED[0])),
                            (
                                Value::text("certificates"),
                                Value::Array(vec![Value::Bytes(c.to_vec())]),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (Value::text("signer"), Value::Array(vec![])),
    ]);
    dcbor::encode(&v, Limits::CEILING).unwrap()
}

// IDP-21, Ek B 4834
#[tokio::test]
async fn pinned_trusted_list_snapshots_from_the_parser_worker_are_used() {
    use access_vc_verifier::domain::lists::{Document, LOTL_TYPE, ListError, assemble};
    let issuer = pki("issuer.test");
    let lotl = Document {
        digest: suiss_crypto::digest::sha256(b"lotl-document"),
        location: String::from("https://ec.example.eu/lotl.xml"),
        summary: summary(
            LOTL_TYPE,
            "2099-01-01T00:00:00Z",
            &["https://tl.example.eu/xx.xml"],
            &[],
        ),
    };
    let national = Document {
        digest: suiss_crypto::digest::sha256(b"xx-document"),
        location: String::from("https://tl.example.eu/xx.xml"),
        summary: summary(
            "national",
            "2098-01-01T00:00:00Z",
            &[],
            &[(PID_TYPE, &issuer.root)],
        ),
    };
    let pins = [lotl.digest, national.digest];
    let lists = assemble(&lotl, std::slice::from_ref(&national), &pins).unwrap();
    assert!(lists.pinned && !lists.signature_verified);
    assert_eq!(lists.sequence, 9);
    assert_eq!(
        assemble(&lotl, std::slice::from_ref(&national), &pins[..1]),
        Err(ListError::Unpinned)
    );
    let stray = Document {
        location: String::from("https://elsewhere.example/tl.xml"),
        ..national.clone()
    };
    assert_eq!(assemble(&lotl, &[stray], &pins), Err(ListError::Unlisted));
    let r = rig(lists, &[]).await;
    let (id, _, _) = answer_sd_jwt(
        &r,
        &pid_query(),
        &IssuerKey::X5c(&issuer, false),
        "urn:eudi:pid:1",
        &["given_name", "family_name", "age_over_18"],
        &json!({}),
    )
    .await;
    let (_, out) = result(&r.router, &id, None).await;
    assert_eq!(out["state"], "verified", "{out}");
    assert_eq!(out["credentials"][0]["loa_eidas"], 3);
}
