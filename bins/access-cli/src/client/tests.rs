#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::arithmetic_side_effects,
    clippy::unused_async_trait_impl,
    reason = "test code"
)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{self, Algorithm, KeySet};
use access_sdk::auth::dpop::ProofKey as _;
use serde_json::{Value, json};
use suiss_crypto::signer::SoftSigner;

use super::*;
use crate::commands::apply::reconcile;
use crate::http::{HttpError, Request, Response, Transport};

const API: &str = "https://mgmt.example:9443";
const ISSUER: &str = "https://login.example/realms/acme";
const DOMAIN: [u8; 32] = [7; 32];

struct Fixed;

impl RandomSource for Fixed {
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        out.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = u8::try_from(i % 251).unwrap_or(0));
        Ok(())
    }
}

impl Env for Fixed {
    fn now_ms(&self) -> u64 {
        1_800_000_000_000
    }
    fn random(&self) -> &dyn RandomSource {
        self
    }
}

fn envelope() -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: ActionRef {
            namespace: "idp.realm".into(),
            name: "branding".into(),
            major: 1,
            schema: Digest([3; 32]),
        },
        resources: vec![ResourceRef {
            namespace: "idp.realm".into(),
            path: vec!["acme".into()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 1_800_000_000_000,
            until: 1_800_000_600_000,
        },
    }
}

/// A scripted management API and token endpoint.
#[derive(Default)]
struct Fake {
    seen: RefCell<Vec<Request>>,
    token_type: RefCell<Option<&'static str>>,
    expires_in: Cell<u64>,
    tamper_digest: Cell<bool>,
    tamper_body: Cell<bool>,
    settings: RefCell<Value>,
    writes: Cell<u32>,
    no_domain: Cell<bool>,
    want_nonce: Cell<bool>,
}

fn reply(status: u16, body: &Value, headers: &[(&str, &str)]) -> Response {
    Response {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
        body: body.to_string().into_bytes(),
    }
}

impl Fake {
    fn new() -> Self {
        let f = Self::default();
        f.expires_in.set(600);
        *f.settings.borrow_mut() =
            json!({"branding": {"display_name": "Acme"}, "rp_id": "acme.example"});
        f
    }

    fn answer(&self, r: &Request) -> Response {
        let path = r.url.split_once("://").map_or("", |(_, rest)| {
            rest.find('/').map_or("", |i| rest.get(i..).unwrap_or(""))
        });
        let path = path.split('?').next().unwrap_or("");
        let read = r.header("authorization").is_some();
        if r.url.starts_with(ISSUER) {
            if path.ends_with("/.well-known/openid-configuration") {
                let mut meta = json!({"issuer": ISSUER, "authorization_endpoint": format!("{ISSUER}/authorize"),
                    "token_endpoint": format!("{ISSUER}/token"), "jwks_uri": format!("{ISSUER}/jwks"),
                    "code_challenge_methods_supported": ["S256"]});
                if !self.no_domain.get() {
                    meta["suiss_domain_metadata"] = json!(format!(
                        "https://api.example/.well-known/access-domain-metadata/sha-256:{}",
                        b64url_encode(&DOMAIN)
                    ));
                }
                return reply(200, &meta, &[]);
            }
            assert!(
                r.header("dpop").is_some(),
                "the token request is DPoP-bound"
            );
            assert!(
                r.header("authorization").is_none(),
                "the exchange takes no client authentication"
            );
            let form = form_of(r);
            assert_eq!(form["grant_type"], TOKEN_EXCHANGE);
            assert!(!form.contains_key("client_assertion") && !form.contains_key("resource"));
            if self.want_nonce.get() && !proof_has_nonce(r.header("dpop").unwrap()) {
                return reply(
                    400,
                    &json!({"error": "use_dpop_nonce"}),
                    &[("dpop-nonce", "n-1")],
                );
            }
            let t = self.token_type.borrow().unwrap_or("DPoP");
            return reply(
                200,
                &json!({"access_token": "rt-1", "token_type": t, "expires_in": self.expires_in.get()}),
                &[],
            );
        }
        match (r.method, path) {
            ("GET", "/admin/v1/realms/acme") => {
                assert!(read);
                reply(200, &json!({"domain": b64url_encode(&DOMAIN)}), &[])
            }
            ("GET", p)
                if p.ends_with("/clients")
                    || p.ends_with("/groups")
                    || p.ends_with("/upstream-idps") =>
            {
                reply(200, &json!({"items": []}), &[])
            }
            ("GET", "/admin/v1/realms/acme/settings") => {
                reply(200, &self.settings.borrow(), &[("etag", "\"s-1\"")])
            }
            ("POST", "/admin/v1/realms/acme/intents") => {
                assert!(read, "drafting is a read with the token");
                let asked: Value = serde_json::from_slice(&r.body.as_ref().unwrap().1).unwrap();
                let mut body = asked["body"].as_object().cloned().unwrap_or_default();
                body.insert(
                    "validity".into(),
                    json!({"not_before": "a", "not_after": "b"}),
                );
                if self.tamper_body.get() {
                    body.insert("display_name".into(), json!("Evil"));
                }
                let bytes = envelope().to_bytes().unwrap();
                let mut digest = intent_digest(&envelope()).unwrap();
                if self.tamper_digest.get() {
                    digest = Digest([9; 32]);
                }
                reply(
                    200,
                    &json!({"operation": asked["operation"], "key": asked["key"], "body": body,
                        "domain": b64url_encode(&DOMAIN), "pep": "access-identity",
                        "intent": b64url_encode(&bytes), "intent_digest": b64url_encode(&digest.0)}),
                    &[],
                )
            }
            (_, p) if p.starts_with("/admin/v1/realms/acme/") => {
                assert!(!read, "a write carries no token (TN-110, TN-130)");
                self.writes.set(self.writes.get() + 1);
                reply(200, &json!({"exercise_id": "ex-1", "position": "42"}), &[])
            }
            _ => reply(404, &json!({"code": "not-found"}), &[]),
        }
    }
}

impl Transport for Fake {
    async fn send(&self, request: Request) -> Result<Response, HttpError> {
        let r = self.answer(&request);
        self.seen.borrow_mut().push(request);
        Ok(r)
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn form_of(r: &Request) -> BTreeMap<String, String> {
    let text = String::from_utf8(r.body.clone().unwrap().1).unwrap();
    let mut out = BTreeMap::new();
    for pair in text.split('&') {
        let (k, v) = pair.split_once('=').unwrap();
        assert!(
            out.insert(pct_decode(k), pct_decode(v)).is_none(),
            "{k} appears once"
        );
    }
    out
}

fn proof_claims(proof: &str) -> Value {
    serde_json::from_slice(&b64url_decode(proof.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

fn proof_has_nonce(proof: &str) -> bool {
    proof_claims(proof).get("nonce").is_some()
}

fn key() -> InstanceKey {
    let (signer, _) = SoftSigner::generate_p256().unwrap();
    InstanceKey::from_signer(Box::new(signer))
}

fn target() -> Target {
    Target {
        api: API.into(),
        realm: "acme".into(),
        issuer: ISSUER.into(),
        basis: ExerciseBasis::Public(Id([5; 16])),
    }
}

fn branding() -> &'static Operation {
    api::contract().operation("putBranding").unwrap()
}

fn body() -> Map<String, Value> {
    json!({"display_name": "Acme 2"})
        .as_object()
        .cloned()
        .unwrap()
}

// TN-110, TN-126, PI-7
#[tokio::test(flavor = "current_thread")]
async fn a_write_signs_the_drafted_intent_and_sends_the_nonce_as_idempotency_key() {
    let fake = Fake::new();
    let k = key();
    let t = target();
    let c = Client::new(&fake, &k, &t, &Fixed);
    let w = c
        .write(branding(), None, &body(), Some("\"s-1\""))
        .await
        .unwrap();
    assert_eq!(
        (w.exercise_id.as_str(), w.position.as_str()),
        ("ex-1", "42")
    );
    let seen = fake.seen.borrow();
    let write = seen.last().unwrap();
    assert_eq!(write.method, "PUT");
    assert!(
        write
            .url
            .ends_with("/admin/v1/realms/acme/settings/branding")
    );
    assert_eq!(write.header("if-match"), Some("\"s-1\""));
    let ais = b64url_decode(write.header("x-access-ais").unwrap()).unwrap();
    let mut keys = KeySet::default();
    keys.insert(*k.kid(), k.public_key().clone()).unwrap();
    keys.allowed
        .extend([Algorithm::Esp256, Algorithm::Es256, Algorithm::Ed25519]);
    let v = cose::verify_sign1(&PureBackend, &ais, &keys, CONTENT_TYPE).unwrap();
    let s = Statement::from_bytes(&v.payload).unwrap();
    assert_eq!(s.intent, intent_digest(&envelope()).unwrap());
    assert_eq!(s.domain, Digest(DOMAIN));
    assert_eq!(s.pep, "access-identity");
    assert_eq!(s.basis, ExerciseBasis::Public(Id([5; 16])));
    assert_eq!(
        write.header("idempotency-key"),
        Some(b64url_encode(&s.nonce).as_str())
    );
    let sent: Value = serde_json::from_slice(&write.body.as_ref().unwrap().1).unwrap();
    assert_eq!(sent["display_name"], "Acme 2");
    assert!(sent.get("validity").is_some());
    for r in seen.iter().filter(|r| r.header("authorization").is_some()) {
        assert!(r.header("authorization").unwrap().starts_with("DPoP "));
        assert!(r.header("dpop").is_some());
    }
}

// TN-110
#[tokio::test(flavor = "current_thread")]
async fn a_draft_whose_digest_or_body_differs_is_refused_and_nothing_is_written() {
    for tamper in [0, 1] {
        let fake = Fake::new();
        if tamper == 0 {
            fake.tamper_digest.set(true);
        } else {
            fake.tamper_body.set(true);
        }
        let k = key();
        let t = target();
        let c = Client::new(&fake, &k, &t, &Fixed);
        let e = c.write(branding(), None, &body(), None).await.unwrap_err();
        assert!(matches!(e, ClientError::Draft(_)), "{e:?}");
        assert_eq!(fake.writes.get(), 0);
    }
}

// TN-130, TN-27
#[tokio::test(flavor = "current_thread")]
async fn a_bearer_or_long_lived_read_token_is_refused() {
    let fake = Fake::new();
    *fake.token_type.borrow_mut() = Some("Bearer");
    let k = key();
    let t = target();
    let c = Client::new(&fake, &k, &t, &Fixed);
    assert!(matches!(
        c.get("/admin/v1/realms/acme/settings").await.unwrap_err(),
        ClientError::TokenShape(_)
    ));
    let fake = Fake::new();
    fake.expires_in.set(2 * 60 * 60);
    let c = Client::new(&fake, &k, &t, &Fixed);
    assert!(matches!(
        c.get("/admin/v1/realms/acme/settings").await.unwrap_err(),
        ClientError::TokenShape(_)
    ));
}

fn token_requests(fake: &Fake) -> Vec<Request> {
    fake.seen
        .borrow()
        .iter()
        .filter(|r| r.url == format!("{ISSUER}/token"))
        .cloned()
        .collect()
}

// TN-130, TN-27, OP-151 m.18 (b)
#[tokio::test(flavor = "current_thread")]
async fn tn_130_the_read_token_is_exchanged_for_the_instances_own_check_statement() {
    let fake = Fake::new();
    let k = key();
    let t = target();
    let c = Client::new(&fake, &k, &t, &Fixed);
    c.get("/admin/v1/realms/acme/settings").await.unwrap();
    let requests = token_requests(&fake);
    let [request] = requests.as_slice() else {
        panic!("one token request");
    };
    let form = form_of(request);
    let names: Vec<&str> = form.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "audience",
            "grant_type",
            "requested_token_type",
            "scope",
            "subject_token",
            "subject_token_type"
        ]
    );
    assert_eq!(form["grant_type"], TOKEN_EXCHANGE);
    assert_eq!(form["subject_token_type"], AIS_TOKEN_TYPE);
    assert_eq!(form["requested_token_type"], ACCESS_TOKEN_TYPE);
    assert_eq!(form["audience"], "access-admin:realm:acme");
    assert_eq!(form["scope"], REALM_READ);
    assert!(request.header("authorization").is_none());

    let ais = b64url_decode(&form["subject_token"]).unwrap();
    let mut keys = KeySet::default();
    keys.insert(*k.kid(), k.public_key().clone()).unwrap();
    keys.allowed
        .extend([Algorithm::Esp256, Algorithm::Es256, Algorithm::Ed25519]);
    let v = cose::verify_sign1(&PureBackend, &ais, &keys, CONTENT_TYPE).unwrap();
    let s = Statement::from_bytes(&v.payload).unwrap();
    assert_eq!(s.mode, Mode::Check);
    assert_eq!(s.domain, Digest(DOMAIN));
    assert_eq!(
        s.intent,
        exchange_intent("access-admin:realm:acme", REALM_READ)
    );
    assert_eq!(s.nonce.len(), 32);
    assert_eq!(s.iat, Fixed.now_ms());

    let allowed = [Algorithm::Es256].into_iter().collect();
    let proof = access_kernel::verify::dpop::verify_proof(
        &access_crypto::AwsLcBackend,
        request.header("dpop").unwrap(),
        &access_kernel::verify::dpop::ProofRules {
            method: "POST",
            uri: &format!("{ISSUER}/token"),
            allowed: &allowed,
            now: Fixed.now_ms(),
            lifetime_ms: 60_000,
            skew_ms: 5_000,
            access_token: None,
            bound_jkt: None,
        },
    )
    .unwrap();
    assert_eq!(&proof.jkt, k.kid(), "the DPoP key is the Instance key");
}

// OP-151 m.18 (b), (c)
#[tokio::test(flavor = "current_thread")]
async fn the_exchange_retries_once_with_the_token_endpoints_dpop_nonce() {
    let fake = Fake::new();
    fake.want_nonce.set(true);
    let k = key();
    let t = target();
    let c = Client::new(&fake, &k, &t, &Fixed);
    c.get("/admin/v1/realms/acme/settings").await.unwrap();
    let requests = token_requests(&fake);
    assert_eq!(requests.len(), 2);
    let retry = proof_claims(requests[1].header("dpop").unwrap());
    assert_eq!(retry["nonce"], "n-1");
}

// MD-8, OP-151 m.18 (b)
#[tokio::test(flavor = "current_thread")]
async fn no_governing_domain_in_the_metadata_means_no_token() {
    let fake = Fake::new();
    fake.no_domain.set(true);
    let k = key();
    let t = target();
    let c = Client::new(&fake, &k, &t, &Fixed);
    assert!(matches!(
        c.get("/admin/v1/realms/acme/settings").await.unwrap_err(),
        ClientError::Unexpected("governing domain")
    ));
    assert_eq!(token_requests(&fake).len(), 0);
}

// OP-151 m.18 (b)
#[test]
fn the_exchange_matches_the_identity_planes_contract() {
    use access_identity_oauth::domain::management as server;
    for (audience, scope) in [
        ("access-admin:realm:acme", REALM_READ),
        (server::PLATFORM_AUDIENCE, server::PLATFORM_READ),
    ] {
        assert_eq!(
            exchange_intent(audience, scope),
            server::exchange_intent(audience, scope)
        );
    }
    assert_eq!(TOKEN_EXCHANGE, server::TOKEN_EXCHANGE);
    assert_eq!(AIS_TOKEN_TYPE, server::AIS_TOKEN_TYPE);
    assert_eq!(ACCESS_TOKEN_TYPE, server::ACCESS_TOKEN_TYPE);
    assert_eq!(EXCHANGE_CONTEXT, server::EXCHANGE_CONTEXT);
    assert_eq!(REALM_READ, server::REALM_READ);
}

// §9.15.1 k.2
#[test]
fn the_governing_domain_is_read_from_the_domain_metadata_address() {
    let id = b64url_encode(&DOMAIN);
    let path = "/.well-known/access-domain-metadata/sha-256:";
    let doc = json!({ "suiss_domain_metadata": format!("https://api.example{path}{id}") });
    assert_eq!(governing_domain(&doc), Some(Digest(DOMAIN)));
    for bad in [
        json!({}),
        json!({ "suiss_domain_metadata": format!("http://api.example{path}{id}") }),
        json!({ "suiss_domain_metadata": format!("https://api.example{path}AAAA") }),
        json!({ "suiss_domain_metadata": format!("https://api.example/other/sha-256:{id}") }),
    ] {
        assert_eq!(governing_domain(&bad), None, "{bad}");
    }
}

// TN-122
#[tokio::test(flavor = "current_thread")]
async fn the_reconciler_applies_one_exercise_per_change_and_proposes_reserved_ones() {
    let fake = Fake::new();
    let k = key();
    let t = target();
    let c = Client::new(&fake, &k, &t, &Fixed);
    let doc = json!({"realm": "acme", "settings": {"branding": {"display_name": "Acme 2"}, "rp_id": "login.acme.example"}});
    let o = Box::pin(reconcile(&c, "acme", &doc, false, None))
        .await
        .unwrap();
    assert_eq!(o.applied.len(), 1, "{}", o.plan);
    assert_eq!(o.applied[0].1, "ex-1");
    assert_eq!(o.proposals.len(), 1);
    assert_eq!(o.proposals[0]["operation"], "putRpId");
    assert_eq!(fake.writes.get(), 1);
    let drafted: Vec<Value> = fake
        .seen
        .borrow()
        .iter()
        .filter(|r| r.url.ends_with("/intents"))
        .map(|r| serde_json::from_slice(&r.body.as_ref().unwrap().1).unwrap())
        .collect();
    assert_eq!(drafted.len(), 1, "a reserved change is not even drafted");
    assert_eq!(drafted[0]["operation"], "putBranding");
}

// TN-124
#[tokio::test(flavor = "current_thread")]
async fn a_plan_with_a_conflict_applies_nothing() {
    let fake = Fake::new();
    let k = key();
    let t = target();
    let c = Client::new(&fake, &k, &t, &Fixed);
    let doc = json!({"realm": "acme", "clients": [{"client_id": "gone"}], "settings": {"branding": {"display_name": "Acme 2"}}});
    let o = Box::pin(reconcile(&c, "acme", &doc, false, None))
        .await
        .unwrap();
    assert_eq!(o.conflicts, 1);
    assert_eq!(o.applied.len(), 0);
    assert_eq!(fake.writes.get(), 0);
}

#[test]
fn the_next_link_is_read() {
    assert_eq!(
        next_link("</admin/v1/realms/acme/clients?page%5Bafter%5D=x>; rel=\"next\""),
        Some("/admin/v1/realms/acme/clients?page%5Bafter%5D=x".into())
    );
    assert_eq!(next_link("<x>; rel=\"prev\""), None);
}
