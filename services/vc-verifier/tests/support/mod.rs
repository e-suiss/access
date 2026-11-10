//! Test issuers, wallets and ports for the verifier: certificates, keys, credentials and
//! responses are made at run time; nothing secret is committed.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::unused_async_trait_impl,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    unreachable_pub,
    reason = "test support"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use access_kernel::json::b64url_encode;
use access_kernel::model::Id;
use access_kernel::verify::cose::PublicKey;
use access_vc_verifier::app::{Config, Verifier};
use access_vc_verifier::domain::cbor::{self, Cbor};
use access_vc_verifier::domain::claims::Reporter;
use access_vc_verifier::domain::jwe;
use access_vc_verifier::domain::mdoc;
use access_vc_verifier::domain::request::base64;
use access_vc_verifier::domain::sd_jwt_vc::digest_of;
use access_vc_verifier::domain::trust::{GRANTED, Service, TrustedLists};
use access_vc_verifier::ports::{Access, Answer, Clock, Fault, Fetch, Random, Response};
use access_vc_verifier::router;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, header};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer, SoftSigner};
use tower::ServiceExt as _;

pub const PID_TYPE: &str = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
pub const EAA_TYPE: &str = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q";
pub const CALLER: &str = "caller-key-made-for-this-test";
pub const ORIGIN: &str = "https://verifier.test";
pub const DOMAIN: [u8; 32] = [0x11; 32];
pub const SUBJECT: [u8; 16] = [0x22; 16];
pub const OPERATOR: Id = Id([0x0a; 16]);
pub const INSTANCE: Id = Id([0x0b; 16]);

pub fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A certificate authority and one issuer certificate under it, with the issuer's signer.
pub struct Pki {
    pub root: Vec<u8>,
    pub leaf: Vec<u8>,
    pub signer: SoftSigner,
}

pub fn pki(san: &str) -> Pki {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::new(vec![san.to_owned()]).unwrap();
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = leaf_params.signed_by(&leaf_key, &root).unwrap();
    let signer = SoftSigner::p256_from_pkcs8(&Secret::new(leaf_key.serialize_der())).unwrap();
    Pki {
        root: root.der().to_vec(),
        leaf: leaf.der().to_vec(),
        signer,
    }
}

pub fn lists(services: &[(&str, &[u8])]) -> TrustedLists {
    TrustedLists {
        sequence: 7,
        next_update_ms: now_ms() + 86_400_000,
        digests: vec![vec![1; 32]],
        signature_verified: true,
        services: services
            .iter()
            .map(|(t, der)| Service {
                provider: String::from("Test Provider"),
                service_type: (*t).to_owned(),
                status: GRANTED[0].to_owned(),
                certificates: vec![der.to_vec()],
            })
            .collect(),
    }
}

pub fn sign_jwt(signer: &dyn Signer, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(payload.to_string().as_bytes())
    );
    let sig = signer.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(&sig))
}

pub fn jwk_of(signer: &dyn Signer) -> Value {
    let PublicKey::P256(sec1) = signer.public_key() else {
        panic!("p256")
    };
    json!({
        "kty": "EC", "crv": "P-256",
        "x": b64url_encode(&sec1[1..33]),
        "y": b64url_encode(&sec1[33..65]),
    })
}

pub fn disclosure(name: &str, value: &Value) -> String {
    let salt = b64url_encode(&access_crypto_salt());
    b64url_encode(json!([salt, name, value]).to_string().as_bytes())
}

fn access_crypto_salt() -> [u8; 16] {
    let mut s = [0u8; 16];
    aws_lc_rs::rand::fill(&mut s).unwrap();
    s
}

/// An SD-JWT VC: the issuer-signed JWT and one disclosure per selectively disclosable claim.
pub struct Credential {
    pub jwt: String,
    pub disclosures: BTreeMap<String, String>,
}

pub enum IssuerKey<'a> {
    X5c(&'a Pki, bool),
    Kid(&'a dyn Signer, &'a str),
}

pub fn sd_jwt_vc(
    key: &IssuerKey<'_>,
    iss: &str,
    vct: &str,
    holder: &dyn Signer,
    claims: &[(&str, Value)],
    extra: &Value,
) -> Credential {
    let mut disclosures = BTreeMap::new();
    let mut sd = Vec::new();
    for (name, value) in claims {
        let d = disclosure(name, value);
        sd.push(Value::from(digest_of(&d)));
        disclosures.insert((*name).to_owned(), d);
    }
    sd.push(Value::from(b64url_encode(&access_crypto_salt())));
    let now = now_ms() / 1000;
    let mut payload = json!({
        "iss": iss,
        "vct": vct,
        "iat": now,
        "exp": now + 3600,
        "cnf": { "jwk": jwk_of(holder) },
        "_sd": sd,
        "_sd_alg": "sha-256",
    });
    if let (Some(p), Some(e)) = (payload.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    let (signer, header): (&dyn Signer, Value) = match key {
        IssuerKey::X5c(pki, with_root) => {
            let mut chain = vec![base64(&pki.leaf)];
            if *with_root {
                chain.push(base64(&pki.root));
            }
            (
                &pki.signer,
                json!({ "alg": "ES256", "typ": "dc+sd-jwt", "x5c": chain }),
            )
        }
        IssuerKey::Kid(s, kid) => (
            *s,
            json!({ "alg": "ES256", "typ": "dc+sd-jwt", "kid": kid }),
        ),
    };
    Credential {
        jwt: sign_jwt(signer, &header, &payload),
        disclosures,
    }
}

pub fn present(
    c: &Credential,
    names: &[&str],
    holder: &dyn Signer,
    aud: &str,
    nonce: &str,
) -> String {
    let mut prefix = format!("{}~", c.jwt);
    for n in names {
        prefix.push_str(&c.disclosures[*n]);
        prefix.push('~');
    }
    let kb = sign_jwt(
        holder,
        &json!({ "alg": "ES256", "typ": "kb+jwt" }),
        &json!({
            "aud": aud,
            "nonce": nonce,
            "iat": now_ms() / 1000,
            "sd_hash": digest_of(&prefix),
        }),
    );
    format!("{prefix}{kb}")
}

fn enc(v: &Cbor) -> Vec<u8> {
    cbor::encode(v)
}

fn tag24(bytes: Vec<u8>) -> Cbor {
    Cbor::Tag(24, Box::new(Cbor::Bytes(bytes)))
}

fn tdate(ms: u64) -> Cbor {
    let secs = ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap();
    let rem = secs % 86_400;
    let (y, m, d) = civil(days);
    Cbor::Tag(
        0,
        Box::new(Cbor::text(&format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        ))),
    )
}

fn civil(z: i64) -> (i64, u64, u64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u64::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap();
    let m = u64::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap();
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn cose_key(signer: &dyn Signer) -> Cbor {
    let PublicKey::P256(sec1) = signer.public_key() else {
        panic!("p256")
    };
    Cbor::Map(vec![
        (Cbor::Uint(1), Cbor::Uint(2)),
        (Cbor::Nint(0), Cbor::Uint(1)),
        (Cbor::Nint(1), Cbor::Bytes(sec1[1..33].to_vec())),
        (Cbor::Nint(2), Cbor::Bytes(sec1[33..65].to_vec())),
    ])
}

fn sign1(signer: &dyn Signer, unprotected: Cbor, payload: Option<&[u8]>, detached: &[u8]) -> Cbor {
    let protected = enc(&Cbor::Map(vec![(Cbor::Uint(1), Cbor::Nint(6))]));
    let tbs = suiss_crypto::cose::to_be_signed(&protected, payload.unwrap_or(detached)).unwrap();
    let sig = signer.sign(&tbs).unwrap();
    Cbor::Array(vec![
        Cbor::Bytes(protected),
        unprotected,
        payload.map_or(Cbor::Null, |p| Cbor::Bytes(p.to_vec())),
        Cbor::Bytes(sig),
    ])
}

/// What the wallet binds an mdoc presentation to.
pub struct Transcript<'a> {
    pub client_id: &'a str,
    pub nonce: &'a str,
    pub thumb: [u8; 32],
    pub response_uri: &'a str,
}

/// An mdoc `DeviceResponse`, base64url; `tamper` changes one disclosed value after signing.
pub fn mdoc(
    pki: &Pki,
    device: &dyn Signer,
    doctype: &str,
    ns: &str,
    items: &[(&str, Cbor)],
    t: &Transcript<'_>,
    tamper: bool,
) -> String {
    let mut digests = Vec::new();
    let mut signed_items = Vec::new();
    for (i, (name, value)) in items.iter().enumerate() {
        let item = enc(&Cbor::Map(vec![
            (
                Cbor::text("random"),
                Cbor::Bytes(access_crypto_salt().to_vec()),
            ),
            (
                Cbor::text("digestID"),
                Cbor::Uint(u64::try_from(i).unwrap()),
            ),
            (Cbor::text("elementValue"), value.clone()),
            (Cbor::text("elementIdentifier"), Cbor::text(name)),
        ]));
        let wrapped = enc(&tag24(item.clone()));
        digests.push((
            Cbor::Uint(u64::try_from(i).unwrap()),
            Cbor::Bytes(suiss_crypto::digest::sha256(&wrapped).to_vec()),
        ));
        let shown = if tamper && i == 0 {
            enc(&Cbor::Map(vec![
                (
                    Cbor::text("random"),
                    Cbor::Bytes(access_crypto_salt().to_vec()),
                ),
                (Cbor::text("digestID"), Cbor::Uint(0)),
                (Cbor::text("elementValue"), Cbor::Bool(true)),
                (Cbor::text("elementIdentifier"), Cbor::text(name)),
            ]))
        } else {
            item
        };
        signed_items.push(tag24(shown));
    }
    let now = now_ms();
    let mso = enc(&Cbor::Map(vec![
        (Cbor::text("docType"), Cbor::text(doctype)),
        (Cbor::text("version"), Cbor::text("1.0")),
        (
            Cbor::text("validityInfo"),
            Cbor::Map(vec![
                (Cbor::text("signed"), tdate(now - 1000)),
                (Cbor::text("validFrom"), tdate(now - 1000)),
                (Cbor::text("validUntil"), tdate(now + 86_400_000)),
            ]),
        ),
        (
            Cbor::text("valueDigests"),
            Cbor::Map(vec![(Cbor::text(ns), Cbor::Map(digests))]),
        ),
        (
            Cbor::text("deviceKeyInfo"),
            Cbor::Map(vec![(Cbor::text("deviceKey"), cose_key(device))]),
        ),
        (Cbor::text("digestAlgorithm"), Cbor::text("SHA-256")),
    ]));
    let mso_payload = enc(&tag24(mso));
    let issuer_auth = sign1(
        &pki.signer,
        Cbor::Map(vec![(Cbor::Uint(33), Cbor::Bytes(pki.leaf.clone()))]),
        Some(&mso_payload),
        &[],
    );
    let device_ns = enc(&tag24(enc(&Cbor::Map(vec![]))));
    let transcript = mdoc::session_transcript(t.client_id, t.nonce, &t.thumb, t.response_uri);
    let auth = mdoc::device_authentication(&transcript, doctype, &device_ns).unwrap();
    let device_sig = sign1(device, Cbor::Map(vec![]), None, &auth);
    let response = Cbor::Map(vec![
        (Cbor::text("status"), Cbor::Uint(0)),
        (Cbor::text("version"), Cbor::text("1.0")),
        (
            Cbor::text("documents"),
            Cbor::Array(vec![Cbor::Map(vec![
                (Cbor::text("docType"), Cbor::text(doctype)),
                (
                    Cbor::text("deviceSigned"),
                    Cbor::Map(vec![
                        (Cbor::text("nameSpaces"), tag24(enc(&Cbor::Map(vec![])))),
                        (
                            Cbor::text("deviceAuth"),
                            Cbor::Map(vec![(Cbor::text("deviceSignature"), device_sig)]),
                        ),
                    ]),
                ),
                (
                    Cbor::text("issuerSigned"),
                    Cbor::Map(vec![
                        (Cbor::text("issuerAuth"), issuer_auth),
                        (
                            Cbor::text("nameSpaces"),
                            Cbor::Map(vec![(Cbor::text(ns), Cbor::Array(signed_items))]),
                        ),
                    ]),
                ),
            ])]),
        ),
    ]);
    b64url_encode(&enc(&response))
}

#[derive(Clone, Default)]
pub struct FakeAccess(pub Arc<Mutex<Vec<(String, Value)>>>);

impl Access for FakeAccess {
    async fn ingest(&self, key: String, body: Vec<u8>) -> Answer {
        let v: Value = serde_json::from_slice(&body).unwrap();
        self.0.lock().unwrap().push((key.clone(), v));
        Answer::Response(Response::new(
            200,
            json!({ "claim": key, "position": "1", "disposition": "admit", "replayed": false })
                .to_string()
                .into_bytes(),
        ))
    }
}

#[derive(Clone, Default)]
pub struct FakeFetch(pub Arc<Mutex<BTreeMap<String, Vec<u8>>>>);

impl Fetch for FakeFetch {
    async fn get(&self, url: String, _accept: &'static str) -> Answer {
        self.0
            .lock()
            .unwrap()
            .get(&url)
            .map_or(Answer::Unanswered(Fault::Unreachable), |b| {
                Answer::Response(Response::new(200, b.clone()))
            })
    }
}

pub struct Wall;

impl Clock for Wall {
    fn now(&self) -> Option<u64> {
        Some(now_ms())
    }
}

pub struct Os;

impl Random for Os {
    fn bytes(&self) -> Option<[u8; 16]> {
        Some(access_crypto_salt())
    }
}

pub type V = Verifier<FakeAccess, FakeFetch, Wall, Os, SoftSigner>;

pub struct Rig {
    pub verifier: Arc<V>,
    pub router: Router,
    pub access: FakeAccess,
    pub fetch: FakeFetch,
}

pub async fn rig(lists: TrustedLists, issuers: &[&str]) -> Rig {
    let (store, _pool) = access_vc_verifier::testing::store().await.unwrap();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = CertificateParams::new(vec![String::from("verifier.test")])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let signer = SoftSigner::p256_from_pkcs8(&Secret::new(key.serialize_der())).unwrap();
    let mut secret = [0u8; 32];
    aws_lc_rs::rand::fill(&mut secret).unwrap();
    let secret = Secret::new(secret);
    let access = FakeAccess::default();
    let fetch = FakeFetch::default();
    let verifier = Arc::new(Verifier::new(
        store,
        (access.clone(), fetch.clone()),
        (Wall, Os, signer),
        Config {
            origin: String::from(ORIGIN),
            chain: vec![cert.der().to_vec()],
            response_secret: secret,
            reporter: Reporter {
                operator: OPERATOR,
                instance: INSTANCE,
            },
            callers: vec![suiss_crypto::digest::sha256(CALLER.as_bytes())],
            issuers: issuers.iter().map(|s| (*s).to_owned()).collect(),
        },
    ));
    verifier.install_lists(lists).await.unwrap();
    Rig {
        router: router(Arc::clone(&verifier)),
        verifier,
        access,
        fetch,
    }
}

pub async fn call(router: &Router, req: Request<Body>) -> (u16, Vec<u8>) {
    let r = router.clone().oneshot(req).await.unwrap();
    let status = r.status().as_u16();
    (
        status,
        to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec(),
    )
}

pub fn json_of(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap()
}

/// Opens a request and fetches its request object; answers the request id and the object's
/// payload.
pub async fn open(router: &Router, query: &Value, return_uri: Option<&str>) -> (String, Value) {
    let mut body = json!({
        "domain": format!("sha-256:{}", b64url_encode(&DOMAIN)),
        "subject": b64url_encode(&SUBJECT),
        "dcql_query": query,
        "mode": if return_uri.is_some() { "same-device" } else { "cross-device" },
    });
    if let Some(u) = return_uri {
        body["return_uri"] = Value::from(u);
    }
    let (status, b) = call(
        router,
        Request::post("/vc-verifier/v1/presentations")
            .header(header::AUTHORIZATION, format!("Bearer {CALLER}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&b));
    let id = json_of(&b)["request"].as_str().unwrap().to_owned();
    let (status, jwt) = call(
        router,
        Request::get(format!("/vc-verifier/v1/requests/{id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    let jwt = String::from_utf8(jwt).unwrap();
    let payload = jwt.split('.').nth(1).unwrap();
    let payload = access_kernel::json::b64url_decode(payload).unwrap();
    (id, json_of(&payload))
}

/// The response key's thumbprint as the request object publishes it.
pub fn thumb(object: &Value) -> [u8; 32] {
    let k = &object["client_metadata"]["jwks"]["keys"][0];
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        k["x"].as_str().unwrap(),
        k["y"].as_str().unwrap()
    );
    suiss_crypto::digest::sha256(canonical.as_bytes())
}

/// Encrypts `vp_token` to the request's key and posts it as the wallet does.
pub async fn respond(router: &Router, id: &str, object: &Value, vp_token: &Value) -> (u16, Value) {
    let k = &object["client_metadata"]["jwks"]["keys"][0];
    let x = access_kernel::json::b64url_decode(k["x"].as_str().unwrap()).unwrap();
    let y = access_kernel::json::b64url_decode(k["y"].as_str().unwrap()).unwrap();
    let point = [&[0x04][..], &x, &y].concat();
    let params = json!({ "vp_token": vp_token, "state": object["state"] });
    let jwe = jwe::encrypt(
        params.to_string().as_bytes(),
        &point,
        k["kid"].as_str().unwrap(),
        suiss_crypto::ecdh_es::Enc::A128Gcm,
    )
    .unwrap();
    let (status, b) = call(
        router,
        Request::post(format!("/vc-verifier/v1/responses/{id}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("response={jwe}")))
            .unwrap(),
    )
    .await;
    (
        status,
        if b.is_empty() {
            Value::Null
        } else {
            json_of(&b)
        },
    )
}

pub async fn result(router: &Router, id: &str, code: Option<&str>) -> (u16, Value) {
    let uri = code.map_or_else(
        || format!("/vc-verifier/v1/presentations/{id}"),
        |c| format!("/vc-verifier/v1/presentations/{id}?response_code={c}"),
    );
    let (s, b) = call(
        router,
        Request::get(uri)
            .header(header::AUTHORIZATION, format!("Bearer {CALLER}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    (s, json_of(&b))
}

pub fn pid_query() -> Value {
    json!({ "credentials": [{
        "id": "pid",
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:1"] },
        "claims": [
            { "path": ["given_name"] },
            { "path": ["family_name"] },
            { "path": ["age_over_18"] },
        ],
    }]})
}
