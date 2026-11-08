//! OP-149: the product client API over HTTP against fake ports, and the committed contract
//! (`sdks/openapi/access-v1.json` and its examples) against the code. Every example validates
//! against the document's schemas. `ACCESS_UPDATE_CONTRACTS=1` rewrites them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unused_async_trait_impl,
    clippy::too_many_lines,
    reason = "test code with fakes of async ports; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use access_authority_core::CoreError;
use access_authority_core::adapters::{ExerciseRecord, KeyAnswer, PartyAnswer};
use access_authority_core::app::{Compromise, Incoming, Response};
use access_authority_core::keys::{AsOf, KeyEntry, KeyState, Lookup, Point};
use access_authority_core::parties::{self, PartyEntry};
use access_http::adp::adapters::{Discovery as AdpDiscovery, Pep, router as adp_router};
use access_http::adp::app::Service as AdpService;
use access_http::adp::ports::Pdp;
use access_http::product::adapters::router;
use access_http::product::app::Service;
use access_http::product::ports::{
    AssertionRefused, ClientAssertions, Exercises, KeyDirectory, PlatformClient, Realm, Resolved,
    Sector, SubjectQuery, Subjects, Tenant, Tenants, Unavailable,
};
use access_http::product::schema::openapi;
use access_http::{Limits, harden};
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::domain::suiss::{self, Settings};
use access_kernel::combinator::{Decision, Mode, Outcome};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::ActorKind;
use access_kernel::model::Id;
use access_kernel::verify::cose::PublicKey;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const DOMAIN: Digest = Digest([1; 32]);
const ACTIVE: [u8; 32] = [0xa1; 32];
const ENDED: [u8; 32] = [0xa2; 32];
const COMPROMISED: [u8; 32] = [0xa3; 32];
/// Asked for signed, its answer waits for the domain's first operational key (SAI-46).
const PENDING: [u8; 32] = [0xa4; 32];
const SIGN1: [u8; 4] = [0xd2, 0x84, 0x40, 0xa0];
const EXCERPT: [u8; 2] = [0xd2, 0x84];
const T0: u64 = 1_793_786_400_000;
/// A live human Party of the domain.
const HUMAN: Id = Id([0xb1; 16]);
/// A system Party that departed.
const DEPARTED: Id = Id([0xb2; 16]);

fn party_entry(party: Id) -> Option<PartyEntry> {
    let since = Point { pos: 4, at: T0 };
    match party {
        HUMAN => Some(PartyEntry {
            party,
            actor_kind: ActorKind::Human,
            since,
            ended: None,
        }),
        DEPARTED => Some(PartyEntry {
            party,
            actor_kind: ActorKind::System,
            since,
            ended: Some(Point {
                pos: 8,
                at: T0.saturating_add(60_000),
            }),
        }),
        _ => None,
    }
}

fn entry(kid: [u8; 32]) -> Option<KeyEntry> {
    let since = Point { pos: 4, at: T0 };
    let ended = Point {
        pos: 8,
        at: T0.saturating_add(60_000),
    };
    let base = KeyEntry {
        kid,
        key: PublicKey::Ed25519([9; 32]),
        party: Id([2; 16]),
        actor_kind: ActorKind::Agent,
        instance: Id([3; 16]),
        since,
        ended: None,
        successor: None,
        state: KeyState::Active,
        compromise: None,
    };
    match kid {
        ACTIVE => Some(base),
        ENDED => Some(KeyEntry {
            ended: Some(ended),
            successor: Some(Id([5; 16])),
            state: KeyState::Ended,
            ..base
        }),
        COMPROMISED => Some(KeyEntry {
            state: KeyState::Compromised,
            compromise: Some(Compromise {
                from: T0.saturating_sub(3_600_000),
                claim: Id([7; 16]),
                declared: 9,
                declared_at: T0.saturating_add(120_000),
            }),
            ..base
        }),
        _ => None,
    }
}

/// Knows three keys and two Parties of one domain at position 9.
struct Ledger;

impl KeyDirectory for Ledger {
    async fn parties(
        &self,
        domain: Digest,
        parties: Vec<Id>,
        as_of: AsOf,
        sign: bool,
    ) -> Result<PartyAnswer, CoreError> {
        if domain != DOMAIN {
            return Err(CoreError::Unavailable("unknown-domain"));
        }
        if as_of == AsOf::Position(99) {
            return Err(CoreError::Unavailable("consistency"));
        }
        let (known, unknown): (Vec<_>, Vec<_>) =
            parties.iter().partition(|p| party_entry(**p).is_some());
        Ok(PartyAnswer {
            lookup: parties::Lookup {
                domain,
                pos: 9,
                iat: T0.saturating_add(180_000),
                parties: known.iter().filter_map(|p| party_entry(*p)).collect(),
                unknown,
            },
            consistency: "ct-9".to_owned(),
            signed: sign.then(|| (SIGN1.to_vec(), EXCERPT.to_vec())),
        })
    }

    async fn lookup(
        &self,
        domain: Digest,
        kids: Vec<[u8; 32]>,
        as_of: AsOf,
        sign: bool,
    ) -> Result<KeyAnswer, CoreError> {
        if domain != DOMAIN {
            return Err(CoreError::Unavailable("unknown-domain"));
        }
        if as_of == AsOf::Position(99) {
            return Err(CoreError::Unavailable("consistency"));
        }
        if sign && kids.contains(&PENDING) {
            return Err(CoreError::Unavailable("signer-no-key"));
        }
        let (keys, unknown): (Vec<_>, Vec<_>) = kids.iter().partition(|k| entry(**k).is_some());
        Ok(KeyAnswer {
            lookup: Lookup {
                domain,
                pos: 9,
                iat: T0.saturating_add(180_000),
                keys: keys.iter().filter_map(|k| entry(*k)).collect(),
                unknown,
            },
            consistency: "ct-9".to_owned(),
            signed: sign.then(|| (SIGN1.to_vec(), EXCERPT.to_vec())),
        })
    }
}

/// Two tenants; external ids are `tnt_` and the hex of the id.
struct Directory;

fn tenant(n: u8, status: &str) -> Tenant {
    Tenant {
        id: [n; 16],
        status: status.to_owned(),
        organizations: Vec::new(),
        realms: vec![Realm {
            id: [n.saturating_add(0xa0); 16],
            issuer: format!("https://shop{n}.id.example"),
            slug: format!("shop{n}"),
        }],
    }
}

impl Tenants for Directory {
    async fn tenant(&self, id: [u8; 16]) -> Result<Option<Tenant>, Unavailable> {
        Ok(match id[0] {
            1 => Some(tenant(1, "active")),
            2 => Some(tenant(2, "suspended")),
            _ => None,
        })
    }

    async fn after(
        &self,
        after: Option<[u8; 16]>,
        _limit: u32,
    ) -> Result<Vec<Tenant>, Unavailable> {
        Ok([tenant(1, "active"), tenant(2, "suspended")]
            .into_iter()
            .filter(|t| after.is_none_or(|a| t.id > a))
            .collect())
    }

    fn external(&self, id: [u8; 16]) -> Option<String> {
        Some(format!("tnt_{:02x}", id[0]))
    }

    fn internal(&self, text: &str) -> Option<[u8; 16]> {
        let n = u8::from_str_radix(text.strip_prefix("tnt_")?, 16).ok()?;
        Some([n; 16])
    }
}

/// One allowed Exercise with a signed receipt and one known only from state.
const SIGNED: [u8; 32] = [0xe1; 32];
const FROM_STATE: [u8; 32] = [0xe2; 32];
/// An allowed Exercise of an agent acting for Party 2 under Mandate 4.
const AGENT: [u8; 32] = [0xe3; 32];

fn agent_receipt() -> Vec<u8> {
    use access_kernel::codec::Canonical as _;
    use access_kernel::receipt::{AgencyLink, Receipt};
    Receipt {
        domain: DOMAIN,
        exercise: Digest(AGENT),
        record: 12,
        intent: Digest([0x1e; 32]),
        instance: Some(Id([3; 16])),
        ais: None,
        capacity: access_kernel::combinator::Capacity::For(Id([2; 16])),
        basis: access_kernel::meta::ExerciseBasis::Public(Id([5; 16])),
        audience: "pep.example".to_owned(),
        iat: T0,
        drawn: false,
        agency: vec![AgencyLink {
            mandate: Id([4; 16]),
            principal: Id([2; 16]),
            agent: Id([6; 16]),
        }],
    }
    .to_bytes()
    .unwrap()
}

impl Exercises for Ledger {
    async fn exercise(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> Result<Option<ExerciseRecord>, CoreError> {
        if domain != DOMAIN {
            return Ok(None);
        }
        let base = ExerciseRecord {
            exercise,
            position: 12,
            intent: Digest([0x1e; 32]),
            instance: Some(Id([3; 16])),
            receipt: None,
            signed_receipt: None,
        };
        Ok(match exercise.0 {
            SIGNED => Some(ExerciseRecord {
                receipt: Some(vec![0xa1, 0x61, 0x76, 0x01]),
                signed_receipt: Some((SIGN1.to_vec(), EXCERPT.to_vec())),
                ..base
            }),
            FROM_STATE => Some(base),
            AGENT => Some(ExerciseRecord {
                receipt: Some(agent_receipt()),
                signed_receipt: Some((SIGN1.to_vec(), EXCERPT.to_vec())),
                ..base
            }),
            _ => None,
        })
    }
}

/// One realm of tenant 1 with client `cli_relay`; Party 2 is subject `sub-2…` to it.
struct People;

const REALM: [u8; 16] = [0xa1; 16];

fn sub_of(party: u8) -> String {
    b64url_encode(&[party; 32])
}

impl Subjects for People {
    async fn resolve(
        &self,
        tenant: [u8; 16],
        realm: [u8; 16],
        sector: Sector<'_>,
        lookup: SubjectQuery,
    ) -> Result<Option<Resolved>, Unavailable> {
        let known_sector = match sector {
            Sector::RealmClient(client_id) => client_id == "cli_relay",
            // OP-149 m.37
            Sector::Platform(c) => *c == relay(),
        };
        if tenant != [1; 16] || realm != REALM || !known_sector {
            return Ok(None);
        }
        let known = [2_u8, 4];
        let mut clients = Vec::new();
        let pairs = match lookup {
            SubjectQuery::Parties(list) => list
                .into_iter()
                .filter(|p| known.contains(&p[0]) && p.iter().all(|b| *b == p[0]))
                .map(|p| (p, sub_of(p[0])))
                .collect(),
            SubjectQuery::Subs(list) => list
                .into_iter()
                .filter_map(|s| {
                    if s == sub_of(7) {
                        clients.push((String::from("cli_seven"), s));
                        return None;
                    }
                    known
                        .iter()
                        .find(|n| sub_of(**n) == s)
                        .map(|n| ([*n; 16], s))
                })
                .collect(),
        };
        Ok(Some(Resolved {
            pairs,
            clients,
            consistency: "ct-7".to_owned(),
        }))
    }
}

/// The platform realm's issuer, the audience a product's assertion names.
const PLATFORM_ISSUER: &str = "https://platform.id.example";
/// Where the routes are served; an assertion may name the endpoint called instead.
const API_BASE: &str = "https://access.example";

/// The one platform product client the verifier knows.
fn relay() -> PlatformClient {
    PlatformClient {
        tenant: [0xf0; 16],
        realm: [0xf1; 16],
        client_id: "cli_relay".to_owned(),
        product: "relay".to_owned(),
    }
}

/// Stands in for the platform API's RFC 7523 verification (OP-149 m.19 (e)) over assertions of
/// the form `<client_id>|<aud>|<jti>`: the client must be the platform product `cli_relay`, the
/// audience the platform realm's issuer or the endpoint called, and the `jti` unused before.
struct Gate(std::sync::Mutex<std::collections::BTreeSet<String>>);

impl ClientAssertions for Gate {
    async fn authenticate(
        &self,
        assertion: &str,
        endpoint: &str,
    ) -> Result<PlatformClient, AssertionRefused> {
        let mut parts = assertion.split('|');
        let (Some(client), Some(aud), Some(jti), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AssertionRefused::Unauthenticated);
        };
        if client != "cli_relay" || (aud != PLATFORM_ISSUER && aud != endpoint) {
            return Err(AssertionRefused::Unauthenticated);
        }
        if !self.0.lock().unwrap().insert(jti.to_owned()) {
            return Err(AssertionRefused::Unauthenticated);
        }
        Ok(relay())
    }
}

fn app(client: bool) -> Router {
    let limits = Limits::default();
    let routes = router(Service::new(
        Ledger,
        Directory,
        People,
        Gate(std::sync::Mutex::default()),
        "eu-central".to_owned(),
        API_BASE.to_owned(),
    ));
    let routes = if client {
        routes.layer(axum::Extension(Pep("product-client".to_owned())))
    } else {
        routes
    };
    harden(routes, limits)
}

/// `req` bearing `assertion` (OP-149 m.37).
fn bearing(mut req: Request<Body>, assertion: &str) -> Request<Body> {
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {assertion}").parse().unwrap(),
    );
    req
}

/// A fresh assertion of the platform product for the platform realm's issuer.
fn assertion(jti: &str) -> String {
    format!("cli_relay|{PLATFORM_ISSUER}|{jti}")
}

async fn call(app: Router, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn domain_text() -> String {
    format!("sha-256:{}", b64url_encode(&DOMAIN.0))
}

fn get_key(kid: [u8; 32], accept: Option<&str>, extra: &str) -> Request<Body> {
    let mut r = Request::get(format!(
        "/access/v1/keys/{}?domain={}{extra}",
        b64url_encode(&kid),
        domain_text()
    ));
    if let Some(a) = accept {
        r = r.header(header::ACCEPT, a);
    }
    r.body(Body::empty()).unwrap()
}

fn batch(kids: &[[u8; 32]], accept: &str) -> Request<Body> {
    let kids: Vec<String> = kids.iter().map(|k| b64url_encode(k)).collect();
    Request::post("/access/v1/keys:batchGet")
        .header(header::ACCEPT, accept)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "domain": domain_text(), "kids": kids }).to_string(),
        ))
        .unwrap()
}

fn get_party(party: Id, accept: Option<&str>, extra: &str) -> Request<Body> {
    let mut r = Request::get(format!(
        "/access/v1/parties/{}?domain={}{extra}",
        b64url_encode(&party.0),
        domain_text()
    ));
    if let Some(a) = accept {
        r = r.header(header::ACCEPT, a);
    }
    r.body(Body::empty()).unwrap()
}

fn party_batch(parties: &[Id], accept: &str) -> Request<Body> {
    let parties: Vec<String> = parties.iter().map(|p| b64url_encode(&p.0)).collect();
    Request::post("/access/v1/parties:batchGet")
        .header(header::ACCEPT, accept)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "domain": domain_text(), "parties": parties }).to_string(),
        ))
        .unwrap()
}

fn problem_type(body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(body).unwrap();
    v["type"].as_str().unwrap().to_owned()
}

fn resolve_request(body: &Value) -> Request<Body> {
    Request::post("/access/v1/tenants/tnt_01/subjects:resolve")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_exercise(id: [u8; 32]) -> Request<Body> {
    Request::get(format!(
        "/access/v1/exercises/{}?domain={}",
        b64url_encode(&id),
        domain_text()
    ))
    .body(Body::empty())
    .unwrap()
}

fn get_agency(id: [u8; 32]) -> Request<Body> {
    Request::get(format!(
        "/access/v1/exercises/{}/agency?domain={}",
        b64url_encode(&id),
        domain_text()
    ))
    .body(Body::empty())
    .unwrap()
}

fn parties_request() -> Value {
    json!({
        "realm": "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1",
        "client_id": "cli_relay",
        "parties": [b64url_encode(&[2; 16]), b64url_encode(&[3; 16])],
    })
}

// OP-149 A11
#[tokio::test]
async fn subjects_resolve_both_ways() {
    // MD-10, OP-141 m.22 (f)
    let (status, _, body) = call(app(true), resolve_request(&parties_request())).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["resolved"],
        json!([{ "party": b64url_encode(&[2; 16]), "sub": sub_of(2) }])
    );
    assert_eq!(v["unknown"], json!([b64url_encode(&[3; 16])]));
    assert_eq!(v["consistency_token"], "ct-7");
    // OP-149 m.34 (b)
    let back = json!({
        "realm": "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1",
        "client_id": "cli_relay",
        "subs": [sub_of(4), sub_of(9), sub_of(7)],
    });
    let (_, _, body) = call(app(true), resolve_request(&back)).await;
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["resolved"],
        json!([
            { "party": b64url_encode(&[4; 16]), "sub": sub_of(4) },
            { "client_id": "cli_seven", "sub": sub_of(7) },
        ])
    );
    assert_eq!(v["unknown"], json!([sub_of(9)]));
    let many: Vec<String> = (0..101_u8).map(|n| b64url_encode(&[n; 16])).collect();
    let mut bad = parties_request();
    for (change, code) in [
        (json!({ "parties": many }), "parties"),
        (json!({ "parties": [] }), "parties"),
        (json!({ "subs": [sub_of(4)] }), "parties-or-subs"),
        (
            json!({ "realm": "A1A1A1A1-A1A1-A1A1-A1A1-A1A1A1A1A1A1" }),
            "realm",
        ),
        (json!({ "x": 1 }), "unknown-member"),
    ] {
        let mut req = bad.clone();
        for (k, v) in change.as_object().unwrap() {
            req[k] = v.clone();
        }
        let (status, _, body) = call(app(true), resolve_request(&req)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{change}");
        assert_eq!(
            problem_type(&body),
            format!("urn:suiss:access:problem:{code}")
        );
    }
    let mut short = parties_request();
    short.as_object_mut().unwrap().remove("parties");
    short["subs"] = json!(["short"]);
    let (status, _, body) = call(app(true), resolve_request(&short)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_type(&body), "urn:suiss:access:problem:subs");
    bad["client_id"] = json!("cli_other");
    let (status, _, body) = call(app(true), resolve_request(&bad)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:client-unknown"
    );
}

// OP-149 m.9
#[tokio::test]
async fn an_exercise_is_read_by_its_id() {
    // §9.8, L2-RCP-2
    let (status, _, body) = call(app(true), get_exercise(SIGNED)).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "allowed");
    assert_eq!(v["position"], "12");
    assert_eq!(v["receipt"]["cose_sign1"], b64url_encode(&SIGN1));
    assert_eq!(v["receipt"]["key_excerpt"], b64url_encode(&EXCERPT));
    let (_, _, body) = call(app(true), get_exercise(FROM_STATE)).await;
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("receipt").is_none());
    assert_eq!(v["instance"], b64url_encode(&[3; 16]));
    let (status, _, body) = call(app(true), get_exercise([0xe9; 32])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:exercise-unknown"
    );
    let (status, _, _) = call(
        app(true),
        Request::get(format!("/access/v1/exercises/{}", b64url_encode(&SIGNED)))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// OP-149 m.11, L2-RCP-1
#[tokio::test]
async fn an_exercise_agency_chain_is_read_from_its_receipt() {
    // OP-149 m.11
    let (status, _, body) = call(app(true), get_agency(AGENT)).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["capacity"], json!({ "for": b64url_encode(&[2; 16]) }));
    assert_eq!(
        v["agency"],
        json!([{
            "mandate": b64url_encode(&[4; 16]),
            "principal": b64url_encode(&[2; 16]),
            "agent": b64url_encode(&[6; 16]),
        }])
    );
    assert_eq!(v["receipt"]["payload"], b64url_encode(&agent_receipt()));
    assert_eq!(v["receipt"]["cose_sign1"], b64url_encode(&SIGN1));
    let (status, _, body) = call(app(true), get_agency(FROM_STATE)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:receipt-unavailable"
    );
    let (status, _, body) = call(app(true), get_agency([0xe9; 32])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:exercise-unknown"
    );
    let (status, _, _) = call(app(true), get_agency(SIGNED)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// OP-149 m.5, OP-141 m.18 (b)
#[tokio::test]
async fn a_client_certificate_is_required() {
    for req in [
        get_key(ACTIVE, None, ""),
        batch(&[ACTIVE], "application/json"),
        Request::get("/access/v1/tenants")
            .body(Body::empty())
            .unwrap(),
        Request::get("/access/v1/tenants/tnt_01/snapshot")
            .body(Body::empty())
            .unwrap(),
        resolve_request(&parties_request()),
        get_exercise(SIGNED),
        get_agency(AGENT),
        get_party(HUMAN, None, ""),
        party_batch(&[HUMAN], "application/json"),
    ] {
        let (status, _, body) = call(app(false), req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // OP-149 m.12
        assert_eq!(
            problem_type(&body),
            "urn:suiss:access:problem:pep-unauthenticated"
        );
    }
}

/// The product routes a platform client may call with its assertion (OP-149 m.37), each with
/// its answer to a PEP.
fn dual_requests() -> Vec<(&'static str, Request<Body>)> {
    vec![
        ("snapshot", {
            Request::get("/access/v1/tenants/tnt_01/snapshot")
                .body(Body::empty())
                .unwrap()
        }),
        ("tenants", {
            Request::get("/access/v1/tenants")
                .body(Body::empty())
                .unwrap()
        }),
        ("key-cose", get_key(ACTIVE, None, "")),
        ("key-json", get_key(ENDED, Some("application/json"), "")),
        (
            "keys",
            batch(&[ACTIVE, ENDED, [0x77; 32]], "application/json"),
        ),
        ("party", get_party(HUMAN, Some("application/json"), "")),
        (
            "parties",
            party_batch(&[HUMAN, DEPARTED], "application/json"),
        ),
        ("resolve", resolve_request(&parties_request())),
        ("exercise", get_exercise(FROM_STATE)),
    ]
}

// OP-149 m.37, m.19 (e), m.5, m.28 (c), m.19 (g)
#[tokio::test]
async fn a_platform_client_assertion_names_the_caller_like_a_certificate() {
    for (i, ((name, as_pep), (_, as_client))) in
        dual_requests().into_iter().zip(dual_requests()).enumerate()
    {
        let (s1, h1, b1) = call(app(true), as_pep).await;
        let (s2, h2, b2) = call(app(false), bearing(as_client, &assertion(&format!("j{i}")))).await;
        assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK), "{name}");
        assert_eq!(b1, b2, "{name}");
        assert_eq!(h1[header::CONTENT_TYPE], h2[header::CONTENT_TYPE], "{name}");
        assert_eq!(h1.get(header::ETAG), h2.get(header::ETAG), "{name}");
        assert_eq!(
            h1.get(header::CACHE_CONTROL),
            h2.get(header::CACHE_CONTROL),
            "{name}"
        );
    }
    let path = "/access/v1/tenants/tnt_01/snapshot";
    let at_endpoint = format!("cli_relay|{API_BASE}{path}|endpoint");
    let req = bearing(
        Request::get(path).body(Body::empty()).unwrap(),
        &at_endpoint,
    );
    let (status, _, body) = call(app(false), req).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tenant"], "tnt_01");
}

// OP-149 m.37
#[tokio::test]
async fn a_platform_client_reads_an_exercise_without_its_receipt() {
    let (status, _, body) = call(app(true), get_exercise(SIGNED)).await;
    assert_eq!(status, StatusCode::OK);
    let mut as_pep: Value = serde_json::from_slice(&body).unwrap();
    assert!(as_pep["receipt"]["cose_sign1"].is_string());
    let (status, _, body) = call(app(false), bearing(get_exercise(SIGNED), &assertion("x"))).await;
    assert_eq!(status, StatusCode::OK);
    let as_client: Value = serde_json::from_slice(&body).unwrap();
    assert!(as_client.get("receipt").is_none());
    as_pep.as_object_mut().unwrap().remove("receipt");
    assert_eq!(as_client, as_pep);
    let (status, _, body) = call(app(false), bearing(get_agency(AGENT), &assertion("y"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:pep-unauthenticated"
    );
}

// OP-149 m.37, m.19 (e), m.20 (b), m.12
#[tokio::test]
async fn an_assertion_is_refused_plainly() {
    let snapshot = || {
        Request::get("/access/v1/tenants/tnt_01/snapshot")
            .body(Body::empty())
            .unwrap()
    };
    let shared = app(false);
    let (status, _, _) = call(shared.clone(), bearing(snapshot(), &assertion("once"))).await;
    assert_eq!(status, StatusCode::OK);
    let refused = [
        ("replayed jti", shared.clone(), assertion("once")),
        (
            "wrong audience",
            app(false),
            String::from("cli_relay|https://acme.id.example|a"),
        ),
        (
            "not a platform product",
            app(false),
            format!("cli_other|{PLATFORM_ISSUER}|b"),
        ),
        ("not a bearer", app(false), String::new()),
    ];
    for (why, app, token) in refused {
        let mut req = snapshot();
        let value = if token.is_empty() {
            "Basic Zm9vOmJhcg==".to_owned()
        } else {
            format!("Bearer {token}")
        };
        req.headers_mut()
            .insert(header::AUTHORIZATION, value.parse().unwrap());
        let (status, headers, body) = call(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{why}");
        assert_eq!(
            problem_type(&body),
            "urn:suiss:access:problem:client-unauthenticated",
            "{why}"
        );
        assert_eq!(
            headers[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\"",
            "{why}"
        );
    }
    let (status, _, body) = call(app(true), bearing(snapshot(), &assertion("both"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:ambiguous-caller"
    );
    // OP-149 m.37
    let mut other = parties_request();
    other["client_id"] = json!("cli_other");
    let (status, _, body) = call(
        app(false),
        bearing(resolve_request(&other), &assertion("mismatch")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:client-mismatch"
    );
    // OP-149 m.37
    let limits = Limits::default();
    let adp = harden(
        adp_router(
            AdpService::new(Eligible, limits.max_body_bytes),
            AdpDiscovery {
                issuer: API_BASE.to_owned(),
            },
        ),
        limits,
    );
    let check = Request::post("/access/v1/eligibility:check")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(eligibility_request().to_string()))
        .unwrap();
    let (status, _, body) = call(adp, bearing(check, &assertion("adp"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:pep-unauthenticated"
    );
}

// OP-149 m.5, CR-58
#[tokio::test]
async fn the_canonical_answer_is_signed() {
    for accept in [None, Some("application/cose"), Some("*/*")] {
        let (status, headers, body) = call(app(true), get_key(ACTIVE, accept, "")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers[header::CONTENT_TYPE],
            "application/cose; cose-type=\"cose-sign1\""
        );
        assert_eq!(body, SIGN1);
        assert_eq!(headers["access-key-excerpt"], b64url_encode(&EXCERPT));
        assert_eq!(headers[header::ETAG], "\"9\"");
        assert_eq!(headers[header::CACHE_CONTROL], "max-age=60");
        assert_eq!(headers[header::VARY], "Accept");
    }
}

// OP-149 m.5, OP-149 m.8
#[tokio::test]
async fn json_is_the_same_content_unsigned() {
    let (status, headers, body) =
        call(app(true), get_key(ENDED, Some("application/json"), "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert!(headers.get("access-key-excerpt").is_none());
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "max-age=31536000, immutable"
    );
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["consistency_token"], "ct-9");
    assert_eq!(v["position"], "9");
    assert_eq!(v["keys"][0]["key_state"], "ended");
    assert_eq!(v["keys"][0]["actor_kind"], "agent");
    assert_eq!(v["keys"][0]["ended"]["position"], "8");
    assert_eq!(v["keys"][0]["successor"], b64url_encode(&[5; 16]));
}

// OP-149 m.5, SEC12
#[tokio::test]
async fn a_compromised_key_names_its_compromise() {
    let (status, headers, body) = call(
        app(true),
        get_key(COMPROMISED, Some("application/json"), ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "max-age=60");
    let v: Value = serde_json::from_slice(&body).unwrap();
    let k = &v["keys"][0];
    assert_eq!(k["key_state"], "compromised");
    assert_eq!(k["compromise"]["from"], "2026-11-04T09:00:00Z");
    assert_eq!(k["compromise"]["declared_at"], "2026-11-04T10:02:00Z");
    assert_eq!(k["compromise"]["source"], b64url_encode(&[7; 16]));
}

// OP-149 m.5
#[tokio::test]
async fn lookups_are_refused_plainly() {
    let (status, _, body) = call(app(true), get_key([0xff; 32], None, "")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem_type(&body), "urn:suiss:access:problem:key-unknown");
    let bad_kid = Request::get(format!("/access/v1/keys/abc?domain={}", domain_text()))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = call(app(true), bad_kid).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_type(&body), "urn:suiss:access:problem:kid");
    let (status, _, body) = call(app(true), get_key(ACTIVE, None, "&as_of=yesterday")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_type(&body), "urn:suiss:access:problem:as_of");
    let (status, _, _) = call(
        app(true),
        get_key(ACTIVE, None, "&as_of=2026-11-04T10%3A00%3A00Z"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = call(app(true), get_key(ACTIVE, None, "&as_of=99")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // OP-149 m.12
    assert_eq!(problem_type(&body), "about:blank");
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["reason"], "consistency");
    let no_domain = Request::get(format!("/access/v1/keys/{}", b64url_encode(&ACTIVE)))
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(app(true), no_domain).await.0, StatusCode::BAD_REQUEST);
}

// OP-149 m.5
#[tokio::test]
async fn a_batch_answers_up_to_a_hundred_kids() {
    let (status, headers, body) = call(
        app(true),
        batch(&[ACTIVE, ENDED, [0xff; 32]], "application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "max-age=60");
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 2);
    assert_eq!(v["unknown"], json!([b64url_encode(&[0xff; 32])]));
    let (status, headers, _) = call(app(true), batch(&[ENDED], "application/json")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "max-age=31536000, immutable"
    );
    let many: Vec<[u8; 32]> = (0..=100u8).map(|i| [i; 32]).collect();
    let (status, _, body) = call(app(true), batch(&many, "application/json")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_type(&body), "urn:suiss:access:problem:kids");
}

// OP-149 m.28 (c), m.8, CR-58
#[tokio::test]
async fn a_party_status_is_answered_like_a_key() {
    for accept in [None, Some("application/cose"), Some("*/*")] {
        let (status, headers, body) = call(app(true), get_party(HUMAN, accept, "")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers[header::CONTENT_TYPE],
            "application/cose; cose-type=\"cose-sign1\""
        );
        assert_eq!(body, SIGN1);
        assert_eq!(headers["access-key-excerpt"], b64url_encode(&EXCERPT));
        assert_eq!(headers[header::ETAG], "\"9\"");
        assert_eq!(headers[header::CACHE_CONTROL], "max-age=60");
        assert_eq!(headers[header::VARY], "Accept");
    }
    let (status, headers, body) =
        call(app(true), get_party(HUMAN, Some("application/json"), "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert!(headers.get("access-key-excerpt").is_none());
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["consistency_token"], "ct-9");
    assert_eq!(v["position"], "9");
    assert_eq!(v["domain"], domain_text());
    let p = &v["parties"][0];
    assert_eq!(p["party"], b64url_encode(&HUMAN.0));
    assert_eq!(p["actor_kind"], "human");
    assert_eq!(p["since"]["position"], "4");
    assert_eq!(p["since"]["time"], "2026-11-04T10:00:00Z");
    assert!(p.get("ended").is_none());
    let (status, headers, body) =
        call(app(true), get_party(DEPARTED, Some("application/json"), "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "max-age=31536000, immutable"
    );
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["parties"][0]["actor_kind"], "system");
    assert_eq!(v["parties"][0]["ended"]["position"], "8");
    assert_eq!(v["parties"][0]["ended"]["time"], "2026-11-04T10:01:00Z");
}

// OP-149 m.28 (c)
#[tokio::test]
async fn party_lookups_are_refused_like_key_lookups() {
    let (status, _, body) = call(app(true), get_party(Id([0xff; 16]), None, "")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:party-unknown"
    );
    let short = Request::get(format!("/access/v1/parties/abc?domain={}", domain_text()))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = call(app(true), short).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_type(&body), "urn:suiss:access:problem:party");
    let no_domain = Request::get(format!("/access/v1/parties/{}", b64url_encode(&HUMAN.0)))
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(app(true), no_domain).await.0, StatusCode::BAD_REQUEST);
    let (status, _, body) = call(app(true), get_party(HUMAN, None, "&as_of=99")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["reason"], "consistency");
    let other = format!("sha-256:{}", b64url_encode(&[2; 32]));
    let elsewhere = |path: String| Request::get(path).body(Body::empty()).unwrap();
    let key = elsewhere(format!(
        "/access/v1/keys/{}?domain={other}",
        b64url_encode(&ACTIVE)
    ));
    let party = elsewhere(format!(
        "/access/v1/parties/{}?domain={other}",
        b64url_encode(&HUMAN.0)
    ));
    let (key_status, _, key_body) = call(app(true), key).await;
    let (party_status, _, party_body) = call(app(true), party).await;
    assert_eq!(
        (key_status, party_status),
        (StatusCode::SERVICE_UNAVAILABLE, key_status)
    );
    let (k, p): (Value, Value) = (
        serde_json::from_slice(&key_body).unwrap(),
        serde_json::from_slice(&party_body).unwrap(),
    );
    assert_eq!(
        (k["code"].clone(), k["reason"].clone()),
        (p["code"].clone(), p["reason"].clone())
    );
    assert_eq!(p["reason"], "unknown-domain");
}

// OP-149 m.28 (c)
#[tokio::test]
async fn a_batch_answers_up_to_a_hundred_parties() {
    let (status, headers, body) = call(
        app(true),
        party_batch(&[HUMAN, DEPARTED, Id([0xff; 16])], "application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "max-age=60");
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["parties"].as_array().unwrap().len(), 2);
    assert_eq!(v["unknown"], json!([b64url_encode(&[0xff; 16])]));
    let (status, headers, body) =
        call(app(true), party_batch(&[DEPARTED], "application/cose")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "max-age=31536000, immutable"
    );
    assert_eq!(body, SIGN1);
    let many: Vec<Id> = (0..=100u8).map(|i| Id([i; 16])).collect();
    let (status, _, body) = call(app(true), party_batch(&many, "application/json")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_type(&body), "urn:suiss:access:problem:parties");
    let (status, _, _) = call(app(true), party_batch(&[HUMAN, HUMAN], "application/json")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// OP-149 m.4
#[tokio::test]
async fn tenants_are_listed_by_cursor() {
    let get = |path: &str| Request::get(path).body(Body::empty()).unwrap();
    let (status, _, body) = call(app(true), get("/access/v1/tenants/tnt_02/snapshot")).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tenant"], "tnt_02");
    assert_eq!(v["status"], "suspended");
    assert_eq!(v["region"], "eu-central");
    // OP-149 m.4
    assert_eq!(v["realms"][0]["slug"], "shop2");
    assert_eq!(v["realms"][0]["issuer"], "https://shop2.id.example");
    assert_eq!(v["realms"][0]["id"], "a2a2a2a2-a2a2-a2a2-a2a2-a2a2a2a2a2a2");
    let (status, _, body) = call(app(true), get("/access/v1/tenants/tnt_09/snapshot")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        problem_type(&body),
        "urn:suiss:access:problem:tenant-unknown"
    );
    let (_, _, body) = call(app(true), get("/access/v1/tenants?cursor=tnt_01")).await;
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tenants"].as_array().unwrap().len(), 1);
    assert!(v.get("next_cursor").is_none());
    let (status, _, _) = call(app(true), get("/access/v1/tenants?cursor=x")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Answers every eligibility check with an allow at head "ct-3".
struct Eligible;

impl Pdp for Eligible {
    async fn evaluate(&self, _inc: Incoming) -> Result<Response, CoreError> {
        Err(CoreError::Protocol("unused"))
    }

    async fn eligible(&self, inc: Incoming, subject: Id) -> Result<Response, CoreError> {
        assert_eq!(inc.request.mode, Mode::Check);
        assert!(inc.ais.is_none());
        assert_eq!(subject, Id([2; 16]));
        Ok(Response {
            decision: Decision {
                outcome: Outcome::Allow,
                blockers: Vec::new(),
                unmet: Vec::new(),
                relied_on: Vec::new(),
            },
            exercise: None,
            record: None,
            replayed: false,
            basis_ref: None,
            consistency: Some("ct-3".to_owned()),
            receipt: None,
            signed_receipt: None,
            pap: None,
            signed_pap: None,
            ended: Vec::new(),
            explained: None,
        })
    }
}

fn eligibility_request() -> Value {
    json!({
        "subject": b64url_encode(&[2; 16]),
        "set": {
            "domain": b64url_encode(&DOMAIN.0),
            "intent": {
                "action": {
                    "namespace": "work",
                    "name": "approve",
                    "major": 1,
                    "schema": b64url_encode(&[4; 32]),
                },
                "resources": [{ "namespace": "work", "path": ["gate-1"] }],
                "validity": { "from": 0, "until": 2_000_000_000_000_u64 },
            },
            "basis": { "holding": { "grant": b64url_encode(&[6; 16]), "holder": b64url_encode(&[2; 16]), "since": 4 } },
            "capacity": "own",
        },
        "as_of": "ct-2",
    })
}

async fn eligibility(body: &Value) -> (StatusCode, Value) {
    let limits = Limits::default();
    let routes = adp_router(
        AdpService::new(Eligible, limits.max_body_bytes),
        AdpDiscovery {
            issuer: "https://access.test".to_owned(),
        },
    )
    .layer(axum::Extension(Pep("product-client".to_owned())));
    let req = Request::post("/access/v1/eligibility:check")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _, bytes) = call(harden(routes, limits), req).await;
    (status, serde_json::from_slice(&bytes).unwrap())
}

// OP-149 m.10, §9.5.2
#[tokio::test]
async fn eligibility_is_a_check_for_the_subject() {
    let (status, v) = eligibility(&eligibility_request()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v, json!({ "eligible": true, "consistency_token": "ct-3" }));
    for member in ["mode", "nonce", "payload"] {
        let mut body = eligibility_request();
        body["set"][member] = json!("x");
        let (status, v) = eligibility(&body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{member}");
        assert_eq!(v["type"], "urn:suiss:access:problem:set");
    }
}

fn settings() -> Settings {
    Settings {
        region: "eu-central".to_owned(),
        relay: "https://relay.example".to_owned(),
        management_api: "https://api.access.example".to_owned(),
        api_base: "https://access.example".to_owned(),
        products: BTreeMap::from([("work".to_owned(), "https://work.example".to_owned())]),
    }
}

// OP-149 m.3, CR-58 m.3
#[test]
fn discovery_cbor_is_the_endpoints_map() {
    let issuer = Issuer::parse("https://acme.id.example").unwrap();
    let map = suiss::endpoints(&issuer, &settings(), suiss::SERVED);
    let cbor = suiss::discovery_cbor(&map);
    assert_eq!(cbor, suiss::discovery_cbor(&map.clone()));
    check_file(
        &root().join("examples/access-v1/suiss-discovery.cbor.hex"),
        &format!("{}\n", hex(&cbor)),
    );
    let doc: Value =
        serde_json::from_str(&suiss::document(&issuer, &settings(), suiss::SERVED)).unwrap();
    assert_eq!(doc["endpoints"], json!(map));
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi")
}

fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s
}

fn check_file(path: &PathBuf, expected: &str) {
    if std::env::var_os("ACCESS_UPDATE_CONTRACTS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, expected).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    let same = committed == expected
        || serde_json::from_str::<Value>(&committed).ok()
            == serde_json::from_str::<Value>(expected).ok()
            && serde_json::from_str::<Value>(expected).is_ok();
    assert!(
        same,
        "{} is stale; run ACCESS_UPDATE_CONTRACTS=1 cargo test -p access-http --test product",
        path.display()
    );
}

// OP-65, TN-112, OP-149 m.1
#[test]
fn committed_openapi_matches_the_code() {
    check_file(&root().join("access-v1.json"), &pretty(&openapi()));
}

async fn body_of(req: Request<Body>) -> Value {
    let (status, _, body) = call(app(true), req).await;
    assert!(status.is_success() || status.is_client_error(), "{status}");
    serde_json::from_slice(&body).unwrap()
}

// OP-65, OP-149 m.1
#[tokio::test]
async fn committed_examples_match_the_code_and_the_schema() {
    let doc = openapi();
    let issuer = Issuer::parse("https://acme.id.example").unwrap();
    let batch_request = json!({
        "domain": domain_text(),
        "kids": [b64url_encode(&ACTIVE), b64url_encode(&COMPROMISED), b64url_encode(&[0xff; 32])],
        "as_of": "2026-11-04T10:00:00Z",
    });
    assert!(access_http::product::domain::batch(batch_request.to_string().as_bytes()).is_ok());
    let party_request = json!({
        "domain": domain_text(),
        "parties": [b64url_encode(&HUMAN.0), b64url_encode(&DEPARTED.0), b64url_encode(&[0xff; 16])],
        "as_of": "2026-11-04T10:00:00Z",
    });
    assert!(
        access_http::product::domain::party_batch(party_request.to_string().as_bytes()).is_ok()
    );
    assert!(
        access_http::adp::domain::decode_eligibility(
            eligibility_request().to_string().as_bytes(),
            Limits::default().max_body_bytes
        )
        .is_ok()
    );
    let examples: Vec<(&str, &str, Value)> = vec![
        (
            "key-lookup",
            "KeyLookup",
            body_of(get_key(ENDED, Some("application/json"), "")).await,
        ),
        (
            "key-batch-request",
            "KeyBatchRequest",
            batch_request.clone(),
        ),
        (
            "key-batch",
            "KeyLookup",
            body_of({
                let mut r = batch(&[ACTIVE, COMPROMISED, [0xff; 32]], "application/json");
                *r.body_mut() = Body::from(batch_request.to_string());
                r
            })
            .await,
        ),
        (
            "party-lookup",
            "PartyLookup",
            body_of(get_party(DEPARTED, Some("application/json"), "")).await,
        ),
        (
            "party-batch-request",
            "PartyBatchRequest",
            party_request.clone(),
        ),
        (
            "party-batch",
            "PartyLookup",
            body_of({
                let mut r = party_batch(&[HUMAN, DEPARTED, Id([0xff; 16])], "application/json");
                *r.body_mut() = Body::from(party_request.to_string());
                r
            })
            .await,
        ),
        (
            "eligibility-request",
            "EligibilityRequest",
            eligibility_request(),
        ),
        (
            "eligibility",
            "EligibilityResponse",
            eligibility(&eligibility_request()).await.1,
        ),
        (
            "tenant-snapshot",
            "TenantSnapshot",
            body_of(
                Request::get("/access/v1/tenants/tnt_01/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await,
        ),
        (
            "tenant-page",
            "TenantPage",
            body_of(
                Request::get("/access/v1/tenants")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await,
        ),
        (
            "suiss-configuration",
            "SuissConfiguration",
            serde_json::from_str(&suiss::document(&issuer, &settings(), suiss::SERVED)).unwrap(),
        ),
        (
            "subjects-resolve-request",
            "ResolveRequest",
            parties_request(),
        ),
        (
            "subjects-resolved",
            "Resolution",
            body_of(resolve_request(&parties_request())).await,
        ),
        ("exercise", "Exercise", body_of(get_exercise(SIGNED)).await),
        (
            "exercise-agency",
            "Agency",
            body_of(get_agency(AGENT)).await,
        ),
        (
            "problem",
            "Problem",
            body_of(get_key([0xff; 32], None, "")).await,
        ),
    ];
    for (name, schema, value) in examples {
        validate(
            &doc,
            &json!({ "$ref": format!("#/components/schemas/{schema}") }),
            &value,
            name,
        );
        check_file(
            &root()
                .join("examples/access-v1")
                .join(format!("{name}.json")),
            &pretty(&value),
        );
    }
}

fn resolve<'a>(doc: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let name = r.trim_start_matches("#/components/schemas/");
            resolve(doc, &doc["components"]["schemas"][name])
        }
        None => schema,
    }
}

fn errors(doc: &Value, schema: &Value, value: &Value, at: &str) -> Vec<String> {
    let schema = resolve(doc, schema);
    let mut out = Vec::new();
    if let Some(c) = schema.get("const")
        && c != value
    {
        out.push(format!("{at}: expected {c}"));
    }
    if let Some(e) = schema.get("enum").and_then(Value::as_array)
        && !e.contains(value)
    {
        out.push(format!("{at}: {value} not in enum"));
    }
    let ty = schema.get("type").and_then(Value::as_str);
    let type_ok = match ty {
        Some("object") => value.is_object(),
        Some("string") => value.is_string(),
        Some("integer") => value.is_u64() || value.is_i64(),
        Some("boolean") => value.is_boolean(),
        Some("array") => value.is_array(),
        _ => true,
    };
    if !type_ok {
        out.push(format!("{at}: not {}", ty.unwrap_or_default()));
        return out;
    }
    if let (Some(p), Some(s)) = (
        schema.get("pattern").and_then(Value::as_str),
        value.as_str(),
    ) {
        let ok = match p {
            "^[0-9]+$" => !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
            "^[A-Za-z0-9_-]+$" => {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            }
            "^[A-Za-z0-9_-]{43}$" => {
                s.len() == 43
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            }
            "^[A-Za-z0-9_-]{22}$" => {
                s.len() == 22
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            }
            "^sha-256:[A-Za-z0-9_-]{43}$" => {
                s.strip_prefix("sha-256:").is_some_and(|r| r.len() == 43)
            }
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" => {
                s.len() == 36
                    && s.bytes().enumerate().all(|(i, b)| {
                        if matches!(i, 8 | 13 | 18 | 23) {
                            b == b'-'
                        } else {
                            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                        }
                    })
            }
            other => panic!("pattern {other} not checked"),
        };
        if !ok {
            out.push(format!("{at}: {s} does not match {p}"));
        }
    }
    if let Some(choices) = schema.get("oneOf").and_then(Value::as_array) {
        let matching = choices
            .iter()
            .filter(|c| errors(doc, c, value, at).is_empty())
            .count();
        if matching != 1 {
            out.push(format!("{at}: {matching} oneOf choices match"));
        }
    }
    if let Some(items) = schema.get("items")
        && let Some(list) = value.as_array()
    {
        for (i, v) in list.iter().enumerate() {
            out.extend(errors(doc, items, v, &format!("{at}[{i}]")));
        }
    }
    if let Some(obj) = value.as_object() {
        for req in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !obj.contains_key(req.as_str().unwrap()) {
                out.push(format!("{at}: missing {req}"));
            }
        }
        let props = schema.get("properties").and_then(Value::as_object);
        for (k, v) in obj {
            match (
                props.and_then(|p| p.get(k)),
                schema.get("additionalProperties"),
            ) {
                (Some(s), _) => out.extend(errors(doc, s, v, &format!("{at}.{k}"))),
                (None, Some(Value::Bool(false))) => out.push(format!("{at}: unexpected {k}")),
                (None, Some(extra)) if extra.is_object() => {
                    out.extend(errors(doc, extra, v, &format!("{at}.{k}")));
                }
                _ => {}
            }
        }
    }
    out
}

fn validate(doc: &Value, schema: &Value, value: &Value, name: &str) {
    let errs = errors(doc, schema, value, name);
    assert!(errs.is_empty(), "{errs:#?}");
}

// OP-149 m.4, m.16 (a), m.17 (g)
#[test]
fn platform_examples_meet_the_contract() {
    let doc = openapi();
    for (name, schema) in [
        ("pairing-challenge-request", "PairingChallengeRequest"),
        ("pairing-challenges", "PairingChallenges"),
        ("pairing-request", "PairingRequest"),
        ("pairing-result", "PairingResult"),
        ("platform-streams", "PlatformStreams"),
        ("provider-declarations", "ProviderDeclarations"),
    ] {
        let path = root()
            .join("examples/access-v1")
            .join(format!("{name}.json"));
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        validate(
            &doc,
            &json!({ "$ref": format!("#/components/schemas/{schema}") }),
            &v,
            name,
        );
    }
    for (path, method) in [
        ("/access/v1/tenants/{tenant}/pairing/challenges", "post"),
        ("/access/v1/tenants/{tenant}/pairing", "post"),
        ("/access/v1/platform/streams", "post"),
        ("/access/v1/platform/streams", "get"),
        ("/access/v1/platform/streams/{id}", "get"),
        ("/access/v1/platform/streams/{id}", "delete"),
        ("/access/v1/platform/streams/{id}/status", "get"),
        ("/access/v1/platform/streams/{id}/status", "post"),
    ] {
        assert_eq!(
            doc["paths"][path][method]["security"],
            json!([{ "platform_client": [] }]),
            "{method} {path}"
        );
    }
    assert_eq!(
        doc["components"]["securitySchemes"]["platform_client"]["scheme"],
        "bearer"
    );
    // OP-149 m.37
    for (path, method) in [
        ("/access/v1/tenants", "get"),
        ("/access/v1/tenants/{tenant}/snapshot", "get"),
        ("/access/v1/keys/{kid}", "get"),
        ("/access/v1/keys:batchGet", "post"),
        ("/access/v1/parties/{party}", "get"),
        ("/access/v1/parties:batchGet", "post"),
        ("/access/v1/tenants/{tenant}/subjects:resolve", "post"),
        ("/access/v1/exercises/{id}", "get"),
    ] {
        assert_eq!(
            doc["paths"][path][method]["security"],
            json!([{ "client": [] }, { "platform_client": [] }]),
            "{method} {path}"
        );
    }
    for (path, method) in [
        ("/access/v1/exercises/{id}/agency", "get"),
        ("/access/v1/eligibility:check", "post"),
    ] {
        assert!(
            doc["paths"][path][method].get("security").is_none(),
            "{method} {path} inherits the client certificate"
        );
    }
    assert_eq!(doc["security"], json!([{ "client": [] }]));
}

// OP-149 m.5, SAI-46, OP-149 m.12
#[tokio::test]
async fn a_signed_lookup_names_why_it_waits() {
    let (status, _, body) = call(app(true), get_key(PENDING, None, "")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        (v["code"].as_str(), v["reason"].as_str()),
        (Some("unavailable"), Some("signer-no-key"))
    );
    let (status, _, _) = call(app(true), batch(&[ACTIVE, PENDING], "application/cose")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _, _) = call(app(true), batch(&[ACTIVE, PENDING], "application/json")).await;
    assert_eq!(status, StatusCode::OK);
}

/// Refuses every eligibility check the way the core does: with `code` for `reason`.
struct Refusing(CoreError);

impl Pdp for Refusing {
    async fn evaluate(&self, _inc: Incoming) -> Result<Response, CoreError> {
        Err(CoreError::Protocol("unused"))
    }

    async fn eligible(&self, _inc: Incoming, _subject: Id) -> Result<Response, CoreError> {
        Err(match &self.0 {
            CoreError::Protocol(r) => CoreError::Protocol(r),
            CoreError::Unavailable(r) => CoreError::Unavailable(r),
            _ => CoreError::Limited,
        })
    }
}

async fn eligibility_with<P: Pdp + 'static>(pdp: P, body: &Value) -> (StatusCode, Value) {
    let limits = Limits::default();
    let routes = adp_router(
        AdpService::new(pdp, limits.max_body_bytes),
        AdpDiscovery {
            issuer: "https://access.test".to_owned(),
        },
    )
    .layer(axum::Extension(Pep("product-client".to_owned())));
    let req = Request::post("/access/v1/eligibility:check")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _, bytes) = call(harden(routes, limits), req).await;
    (status, serde_json::from_slice(&bytes).unwrap())
}

// OP-149 m.10, m.12, RFC 9457 §3
#[tokio::test]
async fn eligibility_problems_name_the_refused_part() {
    let mut body = eligibility_request();
    body["set"]["basis"] = json!({ "holding": { "grant": "x" } });
    let (status, v) = eligibility(&body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        v["errors"],
        json!([{ "pointer": "#/set/basis", "code": "basis" }])
    );
    let mut body = eligibility_request();
    body["subject"] = json!("not-an-id");
    let (_, v) = eligibility(&body).await;
    assert_eq!(
        v["errors"],
        json!([{ "pointer": "#/subject", "code": "subject" }])
    );

    let (status, v) = eligibility_with(
        Refusing(CoreError::Protocol("domain")),
        &eligibility_request(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["code"], "protocol");
    assert_eq!(
        v["errors"],
        json!([{ "pointer": "#/set/domain", "code": "domain" }])
    );
    let (_, v) = eligibility_with(
        Refusing(CoreError::Protocol("consistency_token")),
        &eligibility_request(),
    )
    .await;
    assert_eq!(
        v["errors"],
        json!([{ "pointer": "#/as_of", "code": "consistency_token" }])
    );
    let (_, v) = eligibility_with(
        Refusing(CoreError::Protocol("eligibility")),
        &eligibility_request(),
    )
    .await;
    assert_eq!(v["errors"], json!([{ "code": "eligibility" }]));
    let (status, v) = eligibility_with(
        Refusing(CoreError::Unavailable("lease-held")),
        &eligibility_request(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["reason"], "lease-held");
}

// OP-150 m.2, m.3 (a), OP-149 m.3, CMP-8
#[test]
fn stage6_entries_are_documented_and_discovered_once_served() {
    let doc = openapi();
    for (path, method, served) in [
        ("/access/v1/claims:ingest", "post", true),
        ("/access/v1/status-lists/{list}", "get", true),
    ] {
        assert_eq!(
            doc["paths"][path][method]["x-suiss-served"],
            json!(served),
            "{method} {path}"
        );
    }
    for schema in [
        "ClaimSubmission",
        "ClaimVerdict",
        "StatusRef",
        "IntrospectionExtensions",
    ] {
        assert!(doc["components"]["schemas"][schema].is_object(), "{schema}");
    }
    assert!(suiss::SERVED.contains(&suiss::Endpoint::ClaimIngest));
    assert!(suiss::SERVED.contains(&suiss::Endpoint::StatusList));
    let issuer = Issuer::parse("https://acme.example").unwrap();
    let map = suiss::endpoints(&issuer, &settings(), suiss::SERVED);
    assert!(map.contains_key("claim_ingest") && map.contains_key("status_list"));
}
