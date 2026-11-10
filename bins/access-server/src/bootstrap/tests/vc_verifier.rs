//! The VC verifier against the real server path (OP-155 m.3 (p), OP-153 m.3 (gg)): a verifier
//! registered as an Instance of its own operator Party, a test PID provider under its trusted
//! list, and a wallet answering over `direct_post.jwt`. The verifier reaches Access only through
//! Claim Ingest on the public routes, on the real sequencer and `SoftHSM`; its requests are in its
//! own database.

use std::collections::BTreeMap;

use access_http::adp::adapters::Pep as PepId;
use access_internal_api::instances::{
    PlatformProduct, Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis,
    register_nonce, self_signed_intent,
};
use access_vc_verifier::app::{Config, Open, Verifier};
use access_vc_verifier::domain::claims::Reporter;
use access_vc_verifier::domain::request::Mode as Device;
use access_vc_verifier::domain::trust::{GRANTED, Service, TrustedLists};
use access_vc_verifier::ports::{Access, Answer, Fault, Fetch, Response};
use access_vc_verifier::testing::wallet::{IssuerKey, Pki, payload_of, pki, present, sd_jwt_vc};
use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequestOf, header};
use serde_json::{Value as Json, json};
use suiss_crypto::dcbor::Value;
use suiss_crypto::signer::SoftSigner;
use tower::ServiceExt as _;

use super::vault::Lab;
use super::*;

/// The verifier's operator Party: its Claims' issuer.
const OPERATOR: Id = Id([0x0c; 16]);

/// The verifier's client certificate thumbprint as the TLS layer would name it.
const VERIFIER_PEP: &str = "dmMtdmVyaWZpZXItY2VydGlmaWNhdGUtdGh1bWJwcmludA";

const ISS: &str = "https://issuer.test";

#[derive(Clone)]
struct Ingest(axum::Router);

impl Access for Ingest {
    async fn ingest(&self, key: String, body: Vec<u8>) -> Answer {
        let mut req = HttpRequestOf::post("/access/v1/claims:ingest")
            .header(header::HOST, "access.test")
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", key)
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut()
            .insert(PepId(String::from(VERIFIER_PEP)));
        let r = self.0.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let body = to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec();
        Answer::Response(Response::new(status, body))
    }
}

struct NoFetch;

impl Fetch for NoFetch {
    async fn get(&self, _url: String, _accept: &'static str) -> Answer {
        std::future::ready(Answer::Unanswered(Fault::Unreachable)).await
    }
}

struct Wall;

impl access_vc_verifier::ports::Clock for Wall {
    fn now(&self) -> Option<u64> {
        Some(now_ms())
    }
}

struct Os;

impl access_vc_verifier::ports::Random for Os {
    fn bytes(&self) -> Option<[u8; 16]> {
        access_crypto::random::bytes().ok()
    }
}

type V = Verifier<Ingest, NoFetch, Wall, Os, SoftSigner>;

fn self_signed(domain: Digest, key: &SoftSigner, nonce: &[u8], payload: &Payload) -> SelfSigned {
    let now = now_ms();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(payload, OPERATOR, validity).unwrap();
    let statement = Statement {
        domain,
        nonce: nonce.to_vec(),
        intent: intent_digest(&intent).unwrap(),
        mode: Mode::Commit,
        pep: String::from(access_internal_api::instances::IDENTITY_PEP),
        capacity: Capacity::Own,
        basis: bootstrap_basis(&domain),
        iat: now,
        exercise: None,
    };
    SelfSigned {
        nonce: nonce.to_vec(),
        validity,
        ais: sign_sign1(
            key,
            thumbprint(&key.public_key()),
            access_kernel::ais::CONTENT_TYPE,
            &statement.to_bytes().unwrap(),
        )
        .unwrap(),
    }
}

/// Registers the verifier's Instance key under its operator Party (AG-40 pattern).
async fn register(lab: &Lab, key: &SoftSigner) -> Id {
    let mut registration = Registration {
        tenant: *lab.route.tenant.as_bytes(),
        domain: lab.domain,
        registrant: Registrant::Service {
            product: PlatformProduct::parse("vc-verifier").unwrap(),
            client: String::from("vc-verifier"),
        },
        party: OPERATOR,
        key: key.public_key(),
        register: None,
        create: SelfSigned {
            nonce: Vec::new(),
            validity: Window { from: 0, until: 0 },
            ais: Vec::new(),
        },
        pep: String::from(access_internal_api::instances::IDENTITY_PEP),
        context: None,
    };
    let challenge = access_crypto::random::bytes::<32>().unwrap().to_vec();
    registration.register = Some(self_signed(
        lab.domain,
        key,
        &register_nonce(&challenge),
        &registration.register_payload(),
    ));
    registration.create = self_signed(lab.domain, key, &challenge, &registration.create_payload());
    match lab.w.plane.register(registration).await.unwrap() {
        RegistrationVerdict::Registered(r) => r.instance,
        other @ RegistrationVerdict::Refused { .. } => panic!("{other:?}"),
    }
}

fn issuer_gate(issuer: Id, use_: &str, classes: &[&str]) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text(use_)),
        (
            Value::text("classes"),
            Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
        ),
        (
            Value::text("subject"),
            access_kernel::model::SubjectSelector::Public.to_value(),
        ),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

/// The domain root's `acceptance_establish` of `content` on the meta anchor: the existing CT3
/// path (OP-155 m.3), time-locked before it takes effect.
async fn establish(lab: &Lab, content: Value) -> Verdict {
    let w = &lab.w;
    let domain = lab.domain;
    let root = root_key(&w.keys).unwrap();
    let payload = Payload::AcceptanceEstablish(content);
    let now = server_time(&w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, root_party(&root.public_key()), validity).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&domain));
    let ais = sign(
        &root,
        &Statement {
            domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(access_internal_api::instances::IDENTITY_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now,
            exercise: None,
        },
    )
    .unwrap();
    MetaExercises::lead(&w.plane, domain).await.unwrap();
    MetaExercises::meta(
        &w.plane,
        Request {
            domain,
            mode: Mode::Commit,
            nonce,
            intent,
            payload: Some(payload),
            basis,
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        },
        ais,
        String::from(access_internal_api::instances::IDENTITY_PEP),
    )
    .await
    .unwrap()
}

async fn verifier(lab: &Lab, issuer: &Pki) -> V {
    let (key, _) = SoftSigner::generate_ed25519().unwrap();
    let instance = register(lab, &key).await;
    let today = server_time(&lab.w.db.app).await.unwrap() / 86_400_000;
    for day in [today - 1, today, today + 1] {
        access_store::claims::open_claim_ingest_day(&lab.w.db.archive, u32::try_from(day).unwrap())
            .await
            .unwrap();
    }
    let (store, _) = access_vc_verifier::testing::store().await.unwrap();
    let request_key = pki("verifier.test");
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&access_crypto::random::bytes::<32>().unwrap());
    let v = Verifier::new(
        store,
        (
            Ingest(crate::ingest::routes(
                lab.w.domains.clone(),
                lab.w.db.app.clone(),
            )),
            NoFetch,
        ),
        (Wall, Os, key),
        Config {
            origin: String::from("https://verifier.test"),
            chain: vec![request_key.leaf.clone()],
            request_signer: Box::new(request_key.signer),
            response_secret: suiss_crypto::secret::Secret::new(secret),
            reporter: Reporter {
                operator: OPERATOR,
                instance,
            },
            callers: vec![suiss_crypto::digest::sha256(b"identity-plane")],
            issuers: Vec::new(),
        },
    );
    v.install_lists(TrustedLists {
        sequence: 1,
        next_update_ms: now_ms() + 86_400_000,
        digests: vec![vec![0x5a; 32]],
        signature_verified: true,
        pinned: false,
        services: vec![Service {
            provider: String::from("Test PID Provider"),
            service_type: String::from("http://uri.etsi.org/19602/SvcType/PID/Issuance"),
            status: GRANTED[0].to_owned(),
            certificates: vec![issuer.root.clone()],
        }],
    })
    .await
    .unwrap();
    v
}

/// One PID presentation for `subject`, end to end; answers the outcome the caller reads.
async fn present_pid(v: &V, lab: &Lab, issuer: &Pki) -> Json {
    let opened = v
        .open(
            "identity-plane",
            Open {
                domain: lab.domain.0,
                subject: lab.party.0,
                query: json!({ "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["urn:eudi:pid:1"] },
                    "claims": [{ "path": ["family_name"] }, { "path": ["age_over_18"] }],
                }]}),
                mode: Device::CrossDevice,
                return_uri: None,
            },
        )
        .await
        .unwrap();
    let object = payload_of(&v.request_object(&opened.request).await.unwrap());
    let holder = SoftSigner::generate_p256().unwrap().0;
    let c = sd_jwt_vc(
        &IssuerKey::X5c(issuer, false),
        ISS,
        "urn:eudi:pid:1",
        &holder,
        &[
            ("family_name", json!("Lovelace")),
            ("age_over_18", json!(true)),
        ],
        &json!({}),
    );
    let p = present(
        &c,
        &["family_name", "age_over_18"],
        &holder,
        object["client_id"].as_str().unwrap(),
        object["nonce"].as_str().unwrap(),
    );
    let response =
        access_vc_verifier::testing::wallet::seal_response(&object, &json!({ "pid": [p] }));
    v.respond(&opened.request, &response).await.unwrap();
    v.result("identity-plane", &opened.request, None)
        .await
        .unwrap()
}

fn dispositions(out: &Json) -> BTreeMap<String, String> {
    out["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["class"].as_str().unwrap().to_owned(),
                c["disposition"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// IDI-9, PI-3, AP-7, IDP-21, OP-155 m.3 (p), OP-153 m.3 (gg), Ek B 4831, 4835, 4838, 5055
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_presentation_without_an_acceptance_yields_no_selection() {
    let lab = Lab::open("vc-verifier-acceptance").await;
    let issuer = pki("issuer.test");
    let v = verifier(&lab, &issuer).await;
    let out = present_pid(&v, &lab, &issuer).await;
    assert_eq!(out["state"], "verified", "{out}");
    assert_eq!(out["credentials"][0]["loa_eidas"], 3);
    let before = dispositions(&out);
    assert_eq!(
        before.get("identity_binding_person").map(String::as_str),
        Some("quarantine:source-not-accepted"),
        "{out}"
    );
    assert_eq!(
        before.get("vc_age_over_18").map(String::as_str),
        Some("quarantine:source-not-accepted"),
        "{out}"
    );
    let verdict = establish(
        &lab,
        issuer_gate(
            OPERATOR,
            access_kernel::claim::ACTOR_BINDING,
            &["identity_binding_person"],
        ),
    )
    .await;
    let pending = matches!(
        &verdict,
        Verdict::NotAllowed { decision, .. }
            if decision.blockers.iter().any(|b| b.subcode.as_deref() == Some("time-lock"))
    );
    assert!(pending, "{verdict:?}");
    let out = present_pid(&v, &lab, &issuer).await;
    assert_eq!(
        dispositions(&out)
            .get("identity_binding_person")
            .map(String::as_str),
        Some("quarantine:source-not-accepted"),
        "{out}"
    );
}
