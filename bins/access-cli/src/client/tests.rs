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
                return reply(
                    200,
                    &json!({"issuer": ISSUER, "authorization_endpoint": format!("{ISSUER}/authorize"),
                        "token_endpoint": format!("{ISSUER}/token"), "jwks_uri": format!("{ISSUER}/jwks"),
                        "code_challenge_methods_supported": ["S256"]}),
                    &[],
                );
            }
            assert!(
                r.header("dpop").is_some(),
                "the token request is DPoP-bound"
            );
            let form = String::from_utf8(r.body.clone().unwrap().1).unwrap();
            assert!(form.contains("grant_type=client_credentials"));
            assert!(form.contains("client_assertion_type="));
            assert!(form.contains("resource=access-admin%3Arealm%3Aacme"));
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

fn key() -> InstanceKey {
    let (signer, _) = SoftSigner::generate_p256().unwrap();
    InstanceKey::from_signer(Box::new(signer))
}

fn target() -> Target {
    Target {
        api: API.into(),
        realm: "acme".into(),
        issuer: ISSUER.into(),
        client_id: "reconciler".into(),
        basis: Some(ExerciseBasis::Public(Id([5; 16]))),
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

// TN-110, TN-126, PI-7: a write is the AIS over the drafted digest, keyed by its nonce
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
    // every read carried a DPoP proof with the token
    for r in seen.iter().filter(|r| r.header("authorization").is_some()) {
        assert!(r.header("authorization").unwrap().starts_with("DPoP "));
        assert!(r.header("dpop").is_some());
    }
}

// TN-110: the client signs only what it computed; a draft that lies is refused before signing
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

// TN-130, TN-27: the read token must be DPoP-bound and live at most 60 minutes
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

// The AIS declares the caller's basis; without one nothing is drafted or written
#[tokio::test(flavor = "current_thread")]
async fn a_write_without_a_basis_is_refused() {
    let fake = Fake::new();
    let k = key();
    let t = Target {
        basis: None,
        ..target()
    };
    let c = Client::new(&fake, &k, &t, &Fixed);
    assert!(matches!(
        c.write(branding(), None, &body(), None).await.unwrap_err(),
        ClientError::Draft(_)
    ));
    assert!(fake.seen.borrow().is_empty());
}

// TN-122: the reconciler applies a CT2 change as one Exercise and only proposes the reserved one
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

// TN-124, fail closed: a plan with a conflict applies nothing
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
