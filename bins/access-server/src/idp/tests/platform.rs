//! The platform product API end to end (OP-149 m.4, m.16 (a), m.17 (e), (g)): a platform client
//! authenticates with `private_key_jwt`, pairs with tenants by signing its own Exercises, and
//! manages its event streams, over HTTP against the real authority plane.

use std::sync::Arc;

use access_identity_admin::app::platform::{PAIRING_TTL_MS, PlatformApi};
use access_identity_events::app::Db;
use access_identity_events::app::streams::Streams;
use access_identity_events::ports::TenantIds as _;
use access_identity_oauth::adapters::PgDirectory;
use access_identity_oauth::adapters::oauth::OsRandom;
use access_identity_oauth::ports::dpop::{Clock as OAuthClock, ClockUnavailable};
use access_identity_oauth::ports::oauth::ClientKeys;
use access_internal_api::instances::{bootstrap_basis, self_signed_intent};
use access_kernel::json::{b64url_decode, b64url_encode};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use serde_json::{Value as Json, json};
use tower::ServiceExt as _;

use super::*;

const PEP_NAME: &str = "access-identity";
const SERVICE_SEED: u8 = 41;

/// The identity plane's clock at `NOW`, the authority plane's time in these tests.
pub(super) struct AtNow;

impl OAuthClock for AtNow {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        Ok(NOW)
    }
}

/// Fetches nothing: the test's platform client registered one key inline.
pub(super) struct NoJwks;

impl ClientKeys for NoJwks {
    fn fetch(
        &self,
        _: &str,
    ) -> impl std::future::Future<
        Output = Result<Vec<u8>, access_identity_oauth::ports::Unavailable>,
    > + Send {
        std::future::ready(Err(access_identity_oauth::ports::Unavailable))
    }
}

pub(super) type Api = PlatformApi<PgDirectory, NoJwks, TestPlane, NoSeal, OsRandom, AtNow>;

pub(super) struct Product {
    app: axum::Router,
    /// The platform API behind `app`, the product routes' assertion verifier (OP-149 m.37).
    pub(super) api: Arc<Api>,
    key: EcdsaKeyPair,
    pub(super) client: String,
    /// The seed of the Ed25519 service key its pairing Exercises are signed with.
    seed: u8,
    ids: Arc<IdKey>,
    jti: std::sync::atomic::AtomicU64,
}

pub(super) const ISSUER: &str = "https://platform.id.test";

impl Product {
    /// A fresh `private_key_jwt` assertion for the platform realm (RFC 7523).
    pub(super) fn assertion(&self, aud: &str) -> String {
        let n = self.jti.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let payload = json!({
            "iss": self.client,
            "sub": self.client,
            "aud": aud,
            "iat": NOW / 1000,
            "exp": NOW / 1000 + 60,
            "jti": format!("jti-{n}"),
        })
        .to_string();
        let input = format!(
            "{}.{}",
            b64url_encode(header.as_bytes()),
            b64url_encode(payload.as_bytes())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", b64url_encode(sig.as_ref()))
    }

    async fn call_as(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&Json>,
    ) -> (StatusCode, Json) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(b) = bearer {
            req = req.header("authorization", format!("Bearer {b}"));
        }
        let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
        let resp = self
            .app
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        assert_eq!(resp.headers()["cache-control"], "no-store");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = if bytes.is_empty() {
            Json::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, v)
    }

    async fn call(&self, method: &str, path: &str, body: Option<&Json>) -> (StatusCode, Json) {
        let a = self.assertion(ISSUER);
        self.call_as(method, path, Some(&a), body).await
    }

    fn tenant(&self, t: TenantId) -> String {
        self.ids.external(t.as_bytes()).unwrap()
    }

    /// What the service key `SERVICE_SEED` signs for one unpaired target of a challenge answer.
    fn signed(target: &Json) -> Json {
        Self::signed_with(SERVICE_SEED, target)
    }

    /// What the service key `seed` signs for one unpaired target of a challenge answer.
    fn signed_with(seed: u8, target: &Json) -> Json {
        let d = |k: &str| b64url_decode(target[k].as_str().unwrap()).unwrap();
        let domain = Digest(<[u8; 32]>::try_from(d("domain")).unwrap());
        let ais = |part: &Json| {
            let nonce = b64url_decode(part["nonce"].as_str().unwrap()).unwrap();
            let intent = Digest(
                <[u8; 32]>::try_from(b64url_decode(part["intent"].as_str().unwrap()).unwrap())
                    .unwrap(),
            );
            let s = Statement {
                domain,
                nonce,
                intent,
                mode: Mode::Commit,
                pep: String::from(target["pep"].as_str().unwrap()),
                capacity: Capacity::Own,
                basis: bootstrap_basis(&domain),
                iat: NOW,
                exercise: None,
            };
            b64url_encode(&sign(&s, seed))
        };
        let mut out = json!({
            "realm": target["realm"],
            "challenge": target["challenge"],
            "ais": ais(&target["instance_create"]),
        });
        if target.get("party_register").is_some() {
            out["register_ais"] = ais(&target["party_register"]).into();
        }
        out
    }

    /// Challenges and pairs every live realm of `tenant`.
    async fn pair(&self, tenant: &str) -> Json {
        let (s, v) = self
            .call(
                "POST",
                &format!("/access/v1/tenants/{tenant}/pairing/challenges"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let targets: Vec<Json> = v["targets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["status"] == "unpaired")
            .map(|t| Self::signed_with(self.seed, t))
            .collect();
        let (s, v) = self
            .call(
                "POST",
                &format!("/access/v1/tenants/{tenant}/pairing"),
                Some(&json!({ "targets": targets })),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v
    }
}

/// The committed contract (`sdks/openapi/access-v1.json`).
fn contract() -> Json {
    serde_json::from_str(include_str!("../../../../../sdks/openapi/access-v1.json")).unwrap()
}

/// `value` has the members schema `schema` requires and no other, down through objects and
/// arrays (OP-65: the live answer meets the committed contract).
fn meets(doc: &Json, schema: &Json, value: &Json, at: &str) {
    let schema = match schema.get("$ref").and_then(Json::as_str) {
        Some(r) => &doc["components"]["schemas"][r.trim_start_matches("#/components/schemas/")],
        None => schema,
    };
    if let Some(e) = schema.get("enum").and_then(Json::as_array) {
        assert!(e.contains(value), "{at}: {value}");
    }
    if let (Some(items), Some(list)) = (schema.get("items"), value.as_array()) {
        for (i, v) in list.iter().enumerate() {
            meets(doc, items, v, &format!("{at}[{i}]"));
        }
    }
    let (Some(props), Some(obj)) = (
        schema.get("properties").and_then(Json::as_object),
        value.as_object(),
    ) else {
        return;
    };
    for req in schema["required"].as_array().into_iter().flatten() {
        assert!(
            obj.contains_key(req.as_str().unwrap()),
            "{at}: missing {req}"
        );
    }
    for (k, v) in obj {
        let s = props
            .get(k)
            .unwrap_or_else(|| panic!("{at}: undeclared {k}"));
        meets(doc, s, v, &format!("{at}.{k}"));
    }
}

fn meets_schema(value: &Json, name: &str) {
    let doc = contract();
    meets(
        &doc,
        &json!({ "$ref": format!("#/components/schemas/{name}") }),
        value,
        name,
    );
}

/// The platform realm, the Work platform client with an ES256 client key, service key
/// `SERVICE_SEED` and an event receiver, and the platform API over the real authority plane.
async fn product(w: &World) -> (Product, TenantId, RealmId) {
    let (mut ps, pt, pr) = products(w, &[("work", SERVICE_SEED)]).await;
    (ps.remove(0), pt, pr)
}

/// The platform realm and one platform client per `(product name, service key seed)`, each with
/// its own ES256 client key and an event receiver, over the real authority plane.
pub(super) async fn products(w: &World, named: &[(&str, u8)]) -> (Vec<Product>, TenantId, RealmId) {
    let (pt, pr, pd) = w.realm("platform").await;
    onboard(&w.plane, pd, ROOT, ROOT_KEY).await;
    let platform = Admin {
        platform_tenant: Some(pt),
        ..w.admin()
    };
    let ids = Arc::new(IdKey::new(Secret::new([8; 32])));
    let api: Arc<Api> = Arc::new(PlatformApi {
        app: w.db.app.clone(),
        router: w.db.router.clone(),
        directory: PgDirectory::new(w.db.router.clone()),
        client_keys: NoJwks,
        instances: w.plane.clone(),
        streams: Streams::new(
            Db {
                app: w.db.app.clone(),
                reader: w.db.reader.clone(),
                ids: ids.clone(),
            },
            NoSeal,
            OsRandom,
        ),
        ids: ids.clone(),
        pep: String::from(PEP_NAME),
        clock: AtNow,
    });
    let app = access_http::platform::router(Arc::clone(&api), String::from("https://api.id.test"));
    let mut out = Vec::new();
    for (i, (name, seed)) in named.iter().enumerate() {
        let n = u8::try_from(i).unwrap();
        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let c = Client {
            auth: AuthMethod::PrivateKeyJwtKey {
                key: PublicKey::P256(key.public_key().as_ref().to_vec()),
            },
            ..platform_client(
                w.admin().new_client_id().await.unwrap(),
                PlatformProduct::parse(name).unwrap(),
                seed - 1,
            )
        };
        let p = proposal(
            (pt, pr),
            Change::ClientRegister(c.clone()),
            3 + n,
            idp_anchor(pd),
            1,
        );
        let prepared = platform.prepare(&p).await.unwrap();
        let ais = sign(
            &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
            ROOT_KEY,
        );
        written(&platform.apply(&p, ais).await.unwrap());
        out.push(Product {
            app: app.clone(),
            api: Arc::clone(&api),
            key,
            client: String::from(c.id.as_str()),
            seed: *seed,
            ids: ids.clone(),
            jti: std::sync::atomic::AtomicU64::new(0),
        });
    }
    (out, pt, pr)
}

// OP-149 m.4, m.16 (a), L0-META-7
#[tokio::test]
async fn a_platform_product_pairs_with_a_tenant_by_signing_its_own_exercises() {
    // TN-50, CR-24, OP-62
    let w = World::new().await;
    let (p, _, _) = product(&w).await;
    let (t2, r2, d2) = w.realm("acme").await;
    let tnt = p.tenant(t2);
    let challenges = format!("/access/v1/tenants/{tnt}/pairing/challenges");

    let (s, v) = p.call("POST", &challenges, None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    // OP-65
    meets_schema(&v, "PairingChallenges");
    assert_eq!(v["tenant"], tnt.as_str());
    let t = &v["targets"][0];
    assert_eq!(t["status"], "unpaired");
    assert_eq!(
        t["realm"],
        access_identity_events::domain::catalog::uuid(r2.as_bytes())
    );
    assert_eq!(t["domain"], b64url_encode(&d2.0));
    assert_eq!(t["pep"], PEP_NAME);
    assert_eq!(t["kid"], b64url_encode(&thumbprint(&public(SERVICE_SEED))));
    let ExerciseBasis::Public(grant) = bootstrap_basis(&d2) else {
        panic!("basis");
    };
    assert_eq!(t["basis"], b64url_encode(&grant.0));
    // OP-149 m.17b (e)
    let challenge = b64url_decode(t["challenge"].as_str().unwrap()).unwrap();
    assert_eq!(t["instance_create"]["nonce"], t["challenge"]);
    assert_eq!(
        t["party_register"]["nonce"],
        b64url_encode(&register_nonce(&challenge))
    );
    let party =
        Id(<[u8; 16]>::try_from(b64url_decode(t["party"].as_str().unwrap()).unwrap()).unwrap());
    let validity = Window {
        from: NOW,
        until: NOW + PAIRING_TTL_MS,
    };
    let create = Payload::InstanceCreate {
        party,
        key: public(SERVICE_SEED),
        mandate: None,
    };
    let register = Payload::PartyRegister {
        party,
        root: Root::Sole(party),
        actor_kind: ActorKind::System,
    };
    for (payload, member) in [(&create, "instance_create"), (&register, "party_register")] {
        let intent = intent_digest(&self_signed_intent(payload, party, validity).unwrap()).unwrap();
        assert_eq!(t[member]["intent"], b64url_encode(&intent.0));
    }
    let (_, again) = p.call("POST", &challenges, None).await;
    assert_eq!(again["targets"][0]["challenge"], t["challenge"]);

    let mut half = Product::signed(t);
    half.as_object_mut().unwrap().remove("register_ais");
    let pairing = format!("/access/v1/tenants/{tnt}/pairing");
    let (s, v) = p
        .call("POST", &pairing, Some(&json!({ "targets": [half] })))
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid-party"))
    );

    let body = json!({ "targets": [Product::signed(t)] });
    meets_schema(&body, "PairingRequest");
    let (s, v) = p.call("POST", &pairing, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    meets_schema(&v, "PairingResult");
    let paired = &v["targets"][0];
    assert_eq!(paired["status"], "paired", "{v}");
    assert_eq!(paired["party"], t["party"]);
    assert_eq!(paired["kid"], t["kid"]);
    let instance = meta::object_id(
        &meta::exercise_id(&d2, &challenge).unwrap(),
        kind::INSTANCE,
        0,
    );
    assert_eq!(paired["instance"], b64url_encode(&instance.0));
    // L0-META-7
    assert!(
        w.plane
            .actors
            .bound(&thumbprint(&public(SERVICE_SEED)))
            .is_none()
    );
    let stream = v["event_stream"].clone();
    assert!(stream.is_string(), "{v}");

    let (_, v) = p.call("POST", &pairing, Some(&body)).await;
    assert_eq!(v["targets"][0], *paired);
    assert_eq!(v["event_stream"], stream);
    let (_, v) = p.call("POST", &challenges, None).await;
    assert_eq!(v["targets"][0], *paired);
}

// OP-149 m.4, RFC 7523
#[tokio::test]
async fn the_platform_api_takes_a_fresh_client_assertion() {
    // §10.4.5, TN-30
    let w = World::new().await;
    let (p, _, _) = product(&w).await;
    let (t2, _, _) = w.realm("acme").await;
    let path = format!("/access/v1/tenants/{}/pairing/challenges", p.tenant(t2));
    let (s, v) = p.call_as("POST", &path, None, None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("client-unauthenticated"))
    );
    let other = p.assertion("https://acme.id.test");
    let (s, _) = p.call_as("POST", &path, Some(&other), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let once = p.assertion(ISSUER);
    let (s, _) = p.call_as("POST", &path, Some(&once), None).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = p.call_as("POST", &path, Some(&once), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a replayed jti");
    let (s, v) = p
        .call(
            "POST",
            "/access/v1/tenants/tnt_0123456789abcdefghjkmnpqrs/pairing/challenges",
            None,
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("tenant-unknown"))
    );
    let (s, v) = p
        .call(
            "POST",
            &path,
            Some(&json!({ "realms": ["01010101-0101-0101-0101-010101010101"] })),
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("realm-unknown"))
    );
}

// OP-149 m.4, m.17 (e), (g)
// OP-73
#[tokio::test]
async fn pairing_opens_one_push_stream_the_client_manages() {
    // §8.1.1
    let w = World::new().await;
    let (p, _, _) = product(&w).await;
    let (t2, _, _) = w.realm("acme").await;
    let (t3, _, _) = w.realm("beta").await;
    let first = p.pair(&p.tenant(t2)).await;
    let second = p.pair(&p.tenant(t3)).await;
    assert_eq!(first["targets"][0]["status"], "paired");
    assert_eq!(second["targets"][0]["status"], "paired");
    assert_eq!(first["event_stream"], second["event_stream"]);

    let (s, v) = p.call("GET", "/access/v1/platform/streams", None).await;
    assert_eq!(s, StatusCode::OK);
    meets_schema(&v, "PlatformStreams");
    let streams = v["streams"].as_array().unwrap();
    assert_eq!(streams.len(), 1);
    let id = streams[0]["stream_id"].as_str().unwrap().to_owned();
    assert_eq!(first["event_stream"], id.as_str());
    assert_eq!(streams[0]["delivery"]["method"], "urn:ietf:rfc:8935");
    assert_eq!(
        streams[0]["delivery"]["endpoint_url"],
        "https://work.suiss.example/ssf"
    );
    assert_eq!(streams[0]["aud"], p.client.as_str());

    let push = json!({
        "delivery": {"method": "urn:ietf:rfc:8935", "endpoint_url": "https://work.suiss.example/ssf"},
        "aud": "work",
        "events_requested": ["urn:suiss:access:event:tenant.created"],
    });
    let (s, v) = p
        .call("POST", "/access/v1/platform/streams", Some(&push))
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("stream-exists"))
    );
    let poll = json!({
        "delivery": {"method": "urn:ietf:rfc:8936"},
        "aud": "work",
        "events_requested": ["urn:suiss:access:event:tenant.created"],
    });
    let (s, v) = p
        .call("POST", "/access/v1/platform/streams", Some(&poll))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert!(v["access_token"].is_string());
    let path = format!("/access/v1/platform/streams/{id}");
    let (s, v) = p.call("GET", &path, None).await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("enabled")));
    // SSF §8.1.2, OP-149 m.26 (c)
    let status = format!("{path}/status");
    let (s, v) = p.call("GET", &status, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    meets_schema(&v, "StreamStatus");
    assert_eq!(v, json!({ "stream_id": id, "status": "enabled" }));
    let (s, v) = p
        .call(
            "POST",
            &status,
            Some(&json!({ "stream_id": id, "status": "paused", "reason": "maintenance" })),
        )
        .await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("paused")));
    let (_, v) = p.call("GET", &path, None).await;
    assert_eq!(v["status"], "paused");
    for (body, want) in [
        (json!({ "stream_id": id, "status": "on" }), "status"),
        (
            json!({ "stream_id": "01010101-0101-4101-8101-010101010101", "status": "enabled" }),
            "stream_id",
        ),
    ] {
        let (s, v) = p.call("POST", &status, Some(&body)).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some(want)),
            "{body}"
        );
    }
    let (s, v) = p
        .call(
            "POST",
            &status,
            Some(&json!({ "stream_id": id, "status": "enabled" })),
        )
        .await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("enabled")));
    let (s, _) = p.call("DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, v) = p.call("GET", &path, None).await;
    assert_eq!(v["status"], "disabled");
    let (s, _) = p.call("DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = p.call("GET", &status, None).await;
    assert_eq!(
        (s, v["status"].as_str()),
        (StatusCode::OK, Some("disabled"))
    );
    let (s, _) = p
        .call(
            "POST",
            &status,
            Some(&json!({ "stream_id": id, "status": "enabled" })),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = p
        .call(
            "GET",
            "/access/v1/platform/streams/01010101-0101-4101-8101-010101010101",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (t4, _, _) = w.realm("gamma").await;
    let third = p.pair(&p.tenant(t4)).await;
    assert_ne!(third["event_stream"], first["event_stream"]);
}

// OP-150 m.3 (m), MUST-NEVER-13, XI-18, PI-13
#[tokio::test]
async fn a_third_party_product_holds_the_same_platform_role_as_work() {
    // OP-149 m.4, m.17 (e), m.19 (d), (e), (f), CT2, §9.13.2
    let w = World::new().await;
    let third = "acme-ledger";
    let (ps, pt, _) = products(&w, &[("work", SERVICE_SEED), (third, SERVICE_SEED + 2)]).await;
    let (t2, r2, d2) = w.realm("acme").await;
    let tnt = ps[0].tenant(t2);
    let challenges = format!("/access/v1/tenants/{tnt}/pairing/challenges");
    let ExerciseBasis::Public(grant) = bootstrap_basis(&d2) else {
        panic!("basis");
    };

    // CT2
    for name in ["work", third] {
        let c = platform_client(
            w.admin().new_client_id().await.unwrap(),
            PlatformProduct::parse(name).unwrap(),
            60,
        );
        let p = proposal((t2, r2), Change::ClientRegister(c), 9, idp_anchor(d2), 1);
        assert!(
            matches!(
                Admin {
                    platform_tenant: Some(pt),
                    ..w.admin()
                }
                .prepare(&p)
                .await,
                Err(AdminError::Invalid(Invalid::PlatformTenant))
            ),
            "{name}"
        );
    }

    let mut outcomes: Vec<Vec<(StatusCode, Option<String>)>> = Vec::new();
    let mut streams = Vec::new();
    for p in &ps {
        let mut seen = Vec::new();
        let mut note = |s: StatusCode, v: &Json| {
            seen.push((s, v["code"].as_str().map(String::from)));
        };
        let (s, v) = p.call_as("POST", &challenges, None, None).await;
        note(s, &v);
        let other = p.assertion("https://acme.id.test");
        let (s, v) = p.call_as("POST", &challenges, Some(&other), None).await;
        note(s, &v);
        let once = p.assertion(ISSUER);
        let (s, v) = p.call_as("POST", &challenges, Some(&once), None).await;
        note(s, &v);
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let t = &v["targets"][0];
        assert_eq!(t["status"], "unpaired");
        assert_eq!(t["domain"], b64url_encode(&d2.0));
        assert_eq!(t["pep"], PEP_NAME);
        assert_eq!(t["basis"], b64url_encode(&grant.0));
        assert_eq!(t["kid"], b64url_encode(&thumbprint(&public(p.seed))));
        let (s, v) = p.call_as("POST", &challenges, Some(&once), None).await;
        note(s, &v);
        let paired = p.pair(&tnt).await;
        assert_eq!(paired["targets"][0]["status"], "paired", "{paired}");
        assert_eq!(paired["targets"][0]["kid"], t["kid"]);
        let stream = paired["event_stream"].as_str().unwrap().to_owned();
        let (s, v) = p.call("GET", "/access/v1/platform/streams", None).await;
        note(s, &v);
        let listed = v["streams"].as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["aud"], p.client.as_str());
        let push = json!({
            "delivery": {"method": "urn:ietf:rfc:8935", "endpoint_url": "https://work.suiss.example/ssf"},
            "aud": p.client.as_str(),
            "events_requested": ["urn:suiss:access:event:party.disabled"],
        });
        let (s, v) = p
            .call("POST", "/access/v1/platform/streams", Some(&push))
            .await;
        note(s, &v);
        let (s, v) = p
            .call(
                "POST",
                "/access/v1/tenants/tnt_0123456789abcdefghjkmnpqrs/pairing/challenges",
                None,
            )
            .await;
        note(s, &v);
        let (s, v) = p
            .call(
                "DELETE",
                "/access/v1/platform/streams/01010101-0101-4101-8101-010101010101",
                None,
            )
            .await;
        note(s, &v);
        streams.push(stream);
        outcomes.push(seen);
    }
    assert_eq!(outcomes[0], outcomes[1]);
    assert_eq!(outcomes[0][0].1.as_deref(), Some("client-unauthenticated"));
    assert_eq!(outcomes[0][3].0, StatusCode::UNAUTHORIZED, "a replayed jti");
    assert_eq!(outcomes[0][5].1.as_deref(), Some("stream-exists"));
    assert_eq!(outcomes[0][6].1.as_deref(), Some("tenant-unknown"));
    assert_eq!(outcomes[0][7].0, StatusCode::NOT_FOUND);
    assert_ne!(streams[0], streams[1]);

    for (p, other) in [(&ps[0], &streams[1]), (&ps[1], &streams[0])] {
        let (s, _) = p
            .call("GET", &format!("/access/v1/platform/streams/{other}"), None)
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    // OP-149 m.17a
    let created = identity_events(&w.db, "event.api_client.", 2).await;
    let mut names: Vec<String> = created
        .iter()
        .map(|e| {
            access_identity_events::domain::catalog::IdentityEvent::from_outbox(&e.kind, &e.payload)
                .unwrap()
                .payload["platform_product"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    names.sort();
    assert_eq!(names, [third, "work"]);
}

// OP-149 m.37, m.19 (e), m.19 (g), m.5
#[tokio::test]
async fn a_paired_product_reads_its_tenant_with_its_assertion() {
    // MD-10, OP-141 m.22 (f)
    let w = World::new().await;
    let (p, _, _) = product(&w).await;
    let (t2, r2, _) = w.realm("acme").await;
    let tnt = p.tenant(t2);
    let paired = p.pair(&tnt).await;
    let party = paired["targets"][0]["party"].as_str().unwrap().to_owned();
    let products = access_http::product::adapters::router(access_http::product::app::Service::new(
        w.plane.domains.clone(),
        crate::product::PgTenants::new(w.db.router.clone(), p.ids.clone()),
        crate::product::PgSubjects {
            app: w.db.app.clone(),
            domains: w.plane.domains.clone(),
        },
        Arc::clone(&p.api),
        String::from("eu-central"),
        String::from("https://api.id.test"),
    ));
    let call = |bearer: Option<String>, method: &'static str, path: String, body: Option<Json>| {
        let products = products.clone();
        async move {
            let mut req = Request::builder().method(method).uri(path);
            if let Some(b) = bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            if body.is_some() {
                req = req.header("content-type", "application/json");
            }
            let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
            let resp = products.oneshot(req.body(body).unwrap()).await.unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let v: Json = if bytes.is_empty() {
                Json::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            (status, v)
        }
    };
    let snapshot = format!("/access/v1/tenants/{tnt}/snapshot");
    let (s, v) = call(None, "GET", snapshot.clone(), None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("pep-unauthenticated"))
    );
    let once = p.assertion(ISSUER);
    let (s, v) = call(Some(once.clone()), "GET", snapshot.clone(), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    meets_schema(&v, "TenantSnapshot");
    assert_eq!(v["tenant"], tnt.as_str());
    let realm = access_identity_events::domain::catalog::uuid(r2.as_bytes());
    assert_eq!(v["realms"][0]["id"], realm);
    let (s, v) = call(Some(once), "GET", snapshot.clone(), None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("client-unauthenticated")),
        "a replayed jti"
    );
    let resolve = format!("/access/v1/tenants/{tnt}/subjects:resolve");
    let ask = json!({ "realm": realm, "client_id": p.client, "parties": [party] });
    let (s, v) = call(
        Some(p.assertion(ISSUER)),
        "POST",
        resolve.clone(),
        Some(ask.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    meets_schema(&v, "Resolution");
    assert_eq!(v["resolved"][0]["party"], party);
    let sub = v["resolved"][0]["sub"].as_str().unwrap().to_owned();
    assert_eq!(sub.len(), 43);
    assert_eq!(v["unknown"], json!([]));
    let back = json!({ "realm": realm, "client_id": p.client, "subs": [sub] });
    let (s, v) = call(
        Some(p.assertion(ISSUER)),
        "POST",
        resolve.clone(),
        Some(back),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["resolved"][0]["party"], party, "assigned once");
    let mut other = ask;
    other["client_id"] = json!("cli_other");
    let (s, v) = call(Some(p.assertion(ISSUER)), "POST", resolve, Some(other)).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("client-mismatch"))
    );
    let agency = format!(
        "/access/v1/exercises/{}/agency?domain=sha-256:{}",
        b64url_encode(&[7; 32]),
        b64url_encode(&[8; 32])
    );
    let (s, v) = call(Some(p.assertion(ISSUER)), "GET", agency, None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("pep-unauthenticated"))
    );
}
