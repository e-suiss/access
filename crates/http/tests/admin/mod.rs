//! A management API over in-memory ports, a read token issuer and an Instance key for AIS.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    dead_code,
    unreachable_pub,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use access_http::Limits;
use access_http::api::Api;
use access_http::api::adapters::{MemoryIdempotency, MemoryLimiter, SivCursors};
use access_http::api::app::{Ctx, router_for, submit};
use access_http::api::domain::Surface;
use access_http::api::domain::SurfaceScope;
use access_http::api::manifest::{
    Access, Answer, PLATFORM_ROOT, REALM_ROOT, Route, Verb, Visibility,
};
use access_http::api::ports::{
    Clock, CursorSeal, Entropy, Env, Presented, Proposal, Proposals, Proposed, RateLimiter,
    ReadToken, ReadTokens, Surfaces, Unavailable,
};
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Id;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use suiss_crypto::dcbor::{self, Limits as CborLimits};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};
use tower::ServiceExt;

/// The management origin the DPoP proofs name.
pub const ORIGIN: &str = "https://admin.access.test";

/// Trusted time, settable.
pub const START_MS: u64 = 1_800_000_000_000;

/// The realm the tests administer.
pub const REALM: &str = "acme";

/// A realm with no governing domain the fake knows: missing.
pub const MISSING: &str = "ghost";

pub fn realm_domain() -> Digest {
    Digest([7; 32])
}

pub fn platform_domain() -> Digest {
    Digest([9; 32])
}

/// The ledger behind the fake write path: every committed Exercise moves its position.
#[derive(Default)]
pub struct Ledger {
    pub position: AtomicU64,
    pub calls: AtomicU64,
}

pub struct Fake {
    pub now: AtomicU64,
    pub counter: AtomicU64,
    pub limiter: MemoryLimiter,
    pub cursors: SivCursors,
    pub tokens: Mutex<HashMap<String, ReadToken>>,
    pub keys: Mutex<HashMap<(Digest, [u8; 32]), PublicKey>>,
    pub ledger: Arc<Ledger>,
    pub idempotency: MemoryIdempotency,
}

pub struct Tokens<'a>(&'a Fake);

impl Clock for Fake {
    fn now_ms(&self) -> Result<u64, Unavailable> {
        Ok(self.now.load(Ordering::SeqCst))
    }
}

impl Entropy for Fake {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        for (i, b) in out.iter_mut().enumerate() {
            *b = n.to_be_bytes()[i % 8];
        }
        Ok(())
    }
}

/// The fake ports, shared by the API and the test.
#[derive(Clone)]
pub struct Shared(pub Arc<Fake>);

impl ReadTokens for Shared {
    fn verify(
        &self,
        presented: Presented<'_>,
    ) -> impl Future<Output = Result<Option<ReadToken>, Unavailable>> + Send {
        // TN-27: the fake binds a token to a proof naming this method and URI
        let expected = format!("{} {}", presented.method, presented.uri);
        let ok = presented.proofs == [expected.as_str()];
        let t = self.0.tokens.lock().unwrap().get(presented.token).cloned();
        std::future::ready(Ok(t.filter(|_| ok)))
    }
}

impl Surfaces for Shared {
    fn domain(
        &self,
        scope: &SurfaceScope,
    ) -> impl Future<Output = Result<Option<Digest>, Unavailable>> + Send {
        let d = match scope {
            SurfaceScope::Platform => Some(platform_domain()),
            SurfaceScope::Realm(s) if s == REALM => Some(realm_domain()),
            SurfaceScope::Realm(_) => None,
        };
        std::future::ready(Ok(d))
    }

    fn instance_key(
        &self,
        domain: Digest,
        kid: [u8; 32],
        _at_ms: u64,
    ) -> impl Future<Output = Result<Option<PublicKey>, Unavailable>> + Send {
        let k = self.0.keys.lock().unwrap().get(&(domain, kid)).cloned();
        std::future::ready(Ok(k))
    }
}

impl Proposals for Shared {
    fn propose(
        &self,
        proposal: Proposal,
    ) -> impl Future<Output = Result<Proposed, Unavailable>> + Send {
        let ledger = self.0.ledger.clone();
        ledger.calls.fetch_add(1, Ordering::SeqCst);
        if proposal.body.as_ref() == b"refuse" {
            return std::future::ready(Ok(Proposed::Refused));
        }
        if proposal.body.as_ref() == b"fail" {
            return std::future::ready(Err(Unavailable));
        }
        let position = ledger.position.fetch_add(1, Ordering::SeqCst) + 1;
        std::future::ready(Ok(Proposed::Committed {
            exercise_id: proposal.caller.statement.intent,
            position,
        }))
    }
}

impl access_http::api::ports::IdempotencyStore for Shared {
    fn begin(
        &self,
        scope: [u8; 32],
        request: [u8; 32],
        now_ms: u64,
    ) -> impl Future<Output = Result<access_http::api::ports::Begun, Unavailable>> + Send {
        self.0.idempotency.begin(scope, request, now_ms)
    }

    fn finish(
        &self,
        scope: [u8; 32],
        request: [u8; 32],
        answer: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send {
        self.0.idempotency.finish(scope, request, answer)
    }
}

pub struct TestEnv(pub Shared);

impl Env for TestEnv {
    type Tokens = Shared;
    type Surfaces = Shared;
    type Proposals = Shared;
    type Idempotency = Shared;

    fn clock(&self) -> &dyn Clock {
        &*self.0.0
    }
    fn entropy(&self) -> &dyn Entropy {
        &*self.0.0
    }
    fn limiter(&self) -> &dyn RateLimiter {
        &self.0.0.limiter
    }
    fn cursors(&self) -> &dyn CursorSeal {
        &self.0.0.cursors
    }
    fn tokens(&self) -> &Shared {
        &self.0
    }
    fn surfaces(&self) -> &Shared {
        &self.0
    }
    fn proposals(&self) -> &Shared {
        &self.0
    }
    fn idempotency(&self) -> &Shared {
        &self.0
    }
    fn origin(&self) -> &str {
        ORIGIN
    }
}

pub struct Harness {
    pub fake: Arc<Fake>,
    pub api: Arc<Api<TestEnv>>,
}

impl Harness {
    pub fn new() -> Self {
        let fake = Arc::new(Fake {
            now: AtomicU64::new(START_MS),
            counter: AtomicU64::new(0),
            limiter: MemoryLimiter::default(),
            cursors: SivCursors::new(Secret::new([3; 32])),
            tokens: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
            ledger: Arc::new(Ledger::default()),
            idempotency: MemoryIdempotency::default(),
        });
        let api = Api::new(TestEnv(Shared(fake.clone())), Limits::default());
        Self { fake, api }
    }

    pub fn router(&self) -> Router {
        access_http::api::router(&self.api).unwrap()
    }

    pub fn now(&self) -> u64 {
        self.fake.now.load(Ordering::SeqCst)
    }

    /// Issues a read token: `audience`, `scopes`, living `life_ms`.
    pub fn token(&self, name: &str, audience: &str, scopes: &[&str], life_ms: u64) -> String {
        let now = self.now();
        let t = ReadToken {
            audience: audience.to_owned(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            subject: "sub".to_owned(),
            issued_at_ms: now,
            expires_at_ms: now + life_ms,
            id: suiss_crypto::digest::sha256(name.as_bytes()),
        };
        self.fake.tokens.lock().unwrap().insert(name.to_owned(), t);
        name.to_owned()
    }

    /// A live Instance key of `domain`.
    pub fn instance(&self, domain: Digest) -> SoftSigner {
        let (signer, _) = SoftSigner::generate_ed25519().unwrap();
        let pk = signer.public_key();
        self.fake
            .keys
            .lock()
            .unwrap()
            .insert((domain, thumbprint(&pk)), pk);
        signer
    }

    /// The ledger's position.
    pub fn position(&self) -> u64 {
        self.fake.ledger.position.load(Ordering::SeqCst)
    }

    pub fn proposals(&self) -> u64 {
        self.fake.ledger.calls.load(Ordering::SeqCst)
    }
}

/// An AIS over a `commit` in `domain` with `nonce`, signed by `signer`.
pub fn ais(signer: &SoftSigner, domain: Digest, nonce: [u8; 16], iat: u64) -> String {
    ais_with(signer, domain, nonce, iat, Mode::Commit)
}

pub fn ais_with(
    signer: &SoftSigner,
    domain: Digest,
    nonce: [u8; 16],
    iat: u64,
    mode: Mode,
) -> String {
    let statement = Statement {
        domain,
        nonce: nonce.to_vec(),
        intent: Digest([0x44; 32]),
        mode,
        pep: "access-identity".to_owned(),
        capacity: Capacity::Own,
        basis: ExerciseBasis::Public(Id([1; 16])),
        iat,
        exercise: None,
    };
    let payload = dcbor::encode(&statement.to_value(), CborLimits::CEILING).unwrap();
    let sign1 = sign_sign1(
        signer as &dyn Signer,
        thumbprint(&signer.public_key()),
        CONTENT_TYPE,
        &payload,
    )
    .unwrap();
    b64url_encode(&sign1)
}

/// The DPoP proof the fake verifier expects for `method` on `path`.
pub fn proof(method: &str, path: &str) -> String {
    format!("{method} {ORIGIN}{path}")
}

/// A read request with a DPoP token and its proof.
pub fn read(path: &str, token: &str) -> Request<Body> {
    Request::get(path)
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof("GET", path))
        .body(Body::empty())
        .unwrap()
}

pub async fn send(router: &Router, request: Request<Body>) -> (Response<Body>, serde_json::Value) {
    let response = router.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (Response::from_parts(parts, Body::empty()), json)
}

/// A realm-admin write and a platform-admin write, for the guard's write half.
pub const REALM_PROBE: Route = Route {
    verb: Verb::Post,
    path: "/admin/v1/realms/{slug}/probes",
    surface: Surface::Realm,
    access: Access::Write,
    visibility: Visibility::Hidden,
    operation_id: "createRealmProbe",
    summary: "Test write.",
    query: &[],
    answer: Answer::Replay,
    lifecycle: None,
};

pub const PLATFORM_PROBE: Route = Route {
    verb: Verb::Post,
    path: "/admin/v1/platform/probes",
    surface: Surface::Platform,
    access: Access::Write,
    visibility: Visibility::Forbidden,
    operation_id: "createPlatformProbe",
    summary: "Test write.",
    query: &[],
    answer: Answer::Replay,
    lifecycle: None,
};

pub static ROWS: &[Route] = &[PLATFORM_ROOT, REALM_ROOT, REALM_PROBE, PLATFORM_PROBE];

pub async fn probe(
    Extension(ctx): Extension<Ctx<TestEnv>>,
    body: Bytes,
) -> axum::response::Response {
    match submit(&ctx, body).await {
        Ok(c) => axum::Json(c.json()).into_response(),
        Err(code) => code.problem().into_response(),
    }
}

pub async fn surface(Extension(_ctx): Extension<Ctx<TestEnv>>) -> axum::response::Response {
    StatusCode::OK.into_response()
}

pub fn test_router(h: &Harness) -> axum::Router {
    router_for(&h.api, ROWS, |b| {
        b.handle("getPlatformSurface", surface)?
            .handle("getRealmSurface", surface)?
            .handle("createRealmProbe", probe)?
            .handle("createPlatformProbe", probe)
    })
    .unwrap()
}
