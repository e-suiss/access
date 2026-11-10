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
use access_http::api::app::Ctx;
use access_http::api::domain::SurfaceScope;
use access_http::api::domain::caller::WriteCaller;
use access_http::api::manifest::{PLATFORM_ROOT, REALM_ROOT, Route};
use access_http::api::ports::{
    AuditProofQuery, AuditQuery, Clock, CursorSeal, Draft, Drafted, Entropy, Env, Item, JobItem,
    JobView, Jobs, Listing, NewJob, Pending, PlatformKind, PlatformQuery, PlatformResources,
    PlatformWrite, Presented, RateLimiter, ReadToken, ReadTokens, RealmResources, ResourceKind,
    ResourceQuery, ResourceWrite, Surfaces, Unavailable, Written,
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
use axum::http::StatusCode;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use serde_json::json;
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
    pub nonces: Mutex<HashMap<Vec<u8>, String>>,
    pub jobs: Mutex<HashMap<String, (JobView, Vec<JobItem>)>>,
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
        // TN-27
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

/// The key a fake realm resource is hidden behind: it belongs to another realm (TN-113).
pub const HIDDEN_KEY: &str = "elsewhere";

/// The key a fake realm write is refused under, before a decision.
pub const REFUSED_KEY: &str = "refuse";

/// The key a fake realm write fails under: the write path is unavailable.
pub const FAILING_KEY: &str = "fail";

fn fake_item(kind: ResourceKind, key: &str, version: u64) -> Item {
    let body = match kind {
        ResourceKind::Settings => json!({
            "signin_policy": { "methods": ["email"], "required_fields": [], "mfa_required": false,
                               "domain_allow": [], "domain_deny": [] },
            "session_policy": { "absolute_ms": 43_200_000, "idle_ms": 900_000, "binding": "asn" },
            "branding": { "csp_origins": [] },
            "extension_policy": { "allow_private_targets": false, "hook_disclosure": [] },
        }),
        ResourceKind::Clients => json!({ "client_id": key, "display_name": "Shop",
                                         "redirect_uris": [], "status": "active" }),
        ResourceKind::Accounts => json!({ "account_id": key, "status": "active" }),
        ResourceKind::Organizations => json!({ "organization": key, "display_name": "Acme",
                                               "hrd": false }),
        ResourceKind::SocialProviders => json!({ "preset": key, "client_id": "c",
                                                 "client_secret_ref": "secret://s",
                                                 "shared_development_client": false,
                                                 "status": "active", "warnings": [] }),
        ResourceKind::Groups | ResourceKind::UpstreamIdps => {
            json!({ "name": key, "display_name": "Fake", "status": "active" })
        }
        ResourceKind::Hooks => json!({ "hook_id": key, "point": "post_login",
                                       "url": "https://hooks.shop.example/h", "status": "active" }),
        ResourceKind::Webhooks => json!({ "webhook_id": key, "url": "https://sync.shop.example/w",
                                          "events": ["account.created"], "status": "active" }),
        ResourceKind::Signals => {
            json!({ "transmitters": [], "geoip": "not_configured", "verifiers": [] })
        }
        ResourceKind::Analytics => json!({ "days": [], "surges": [] }),
        ResourceKind::Deliveries => {
            json!({ "event_id": key, "event": "account.created", "state": "delivered" })
        }
        ResourceKind::RelayUndelivered => json!({ "event_id": key, "kind": "relay.message.otp.v1",
                                                  "reason": "rejected", "relay_status": 422,
                                                  "resends": [] }),
        ResourceKind::VaultResources => json!({ "resource": key, "upstream": "github",
                                                "status": "enabled" }),
        ResourceKind::ProtectedResources => json!({ "resource": key, "display_name": "MCP" }),
        ResourceKind::TrustAnchors => json!({ "anchor": key, "entity_id": "https://ta.example",
                                              "status": "live" }),
        ResourceKind::SamlSps => json!({ "name": key, "entity_id": "https://sp.test",
                                         "status": "live" }),
        ResourceKind::CustomDomains => json!({ "host": key, "status": "pending" }),
        ResourceKind::ExportSinks => json!({ "name": key, "adapter": "otlp", "status": "live" }),
        ResourceKind::SshHostGroups => json!({ "name": key, "description": "Web",
                                               "status": "live", "version": 1 }),
        ResourceKind::Proxies => json!({ "name": key, "host": "wiki.shop.example",
                                         "status": "live" }),
        ResourceKind::LinuxHosts => json!({ "name": key, "host_group": "prod-web",
                                            "status": "live", "version": 1 }),
        ResourceKind::HrSources => json!({ "name": key, "issuer": "AAAAAAAAAAAAAAAAAAAAAA",
                                           "status": "live", "people": 0, "version": 1 }),
        ResourceKind::HrConnectors => json!({ "name": key, "source": "hr", "vendor": "personio",
                                              "status": "live", "version": 1 }),
        ResourceKind::Agents => json!({ "agent": key, "display_name": "Helper",
                                        "agent_kind": "cloud", "status": "active",
                                        "sponsors": [], "instances": [] }),
        ResourceKind::AgentSponsors => json!({ "account_id": key }),
        ResourceKind::SsoEnforcementPreviews => json!({ "organization": key, "enforced": false,
                                                        "members": [], "service_accounts": [],
                                                        "pending_invitations": 0 }),
    };
    Item { body, version }
}

// TN-113
impl RealmResources for Shared {
    fn read(&self, q: ResourceQuery) -> Pending<'_, Option<Listing>> {
        let version = self.0.ledger.position.load(Ordering::SeqCst);
        let listing = (q.slug == REALM).then(|| {
            let keys: Vec<String> = match q.key {
                Some(k) if k == HIDDEN_KEY => Vec::new(),
                Some(k) => vec![k],
                None if q.kind == ResourceKind::Settings => vec![String::new()],
                None => vec!["a".to_owned(), "b".to_owned()],
            };
            Listing {
                items: keys.iter().map(|k| fake_item(q.kind, k, version)).collect(),
                last: None,
            }
        });
        Box::pin(async move { Ok(listing) })
    }

    fn draft(&self, w: ResourceWrite) -> Pending<'_, Drafted> {
        let bytes = serde_json::to_vec(&w.body).unwrap();
        let digest = Digest(suiss_crypto::digest::sha256(&bytes));
        let mut body = w.body;
        if let Some(o) = body.as_object_mut() {
            o.entry("validity").or_insert(json!({}));
        }
        Box::pin(async move {
            Ok(Drafted::Draft(Draft {
                body,
                domain: w.domain,
                intent: bytes,
                intent_digest: digest,
                pep: "access-identity".to_owned(),
            }))
        })
    }

    fn audit(&self, q: AuditQuery) -> Pending<'_, Option<Listing>> {
        let listing = (q.slug == REALM).then(|| Listing {
            items: vec![Item {
                body: json!({ "format": format!("{:?}", q.format), "reader": q.reader }),
                version: 0,
            }],
            last: None,
        });
        Box::pin(async move { Ok(listing) })
    }

    fn audit_proof(&self, q: AuditProofQuery) -> Pending<'_, Option<serde_json::Value>> {
        let proof = (q.slug == REALM && q.event != "8")
            .then(|| json!({ "event_id": q.event, "reader": q.reader, "size": 3 }));
        Box::pin(async move { Ok(proof) })
    }

    fn commit(&self, w: ResourceWrite, caller: WriteCaller) -> Pending<'_, Written> {
        let ledger = self.0.ledger.clone();
        ledger.calls.fetch_add(1, Ordering::SeqCst);
        // TI-8
        let request = format!("{} {:?} {}", w.operation, w.key, w.body);
        let spent = self
            .0
            .nonces
            .lock()
            .unwrap()
            .entry(caller.statement.nonce.clone())
            .or_insert_with(|| request.clone())
            .clone();
        Box::pin(async move {
            if spent != request {
                return Ok(Written::Rejected(
                    &access_http::problem::codes::EXERCISE_REFUSED,
                ));
            }
            if w.key.as_deref() == Some(HIDDEN_KEY) {
                return Ok(Written::Rejected(&access_http::problem::codes::NOT_FOUND));
            }
            if w.key.as_deref() == Some(REFUSED_KEY) {
                return Ok(Written::Rejected(
                    &access_http::problem::codes::EXERCISE_REFUSED,
                ));
            }
            if w.key.as_deref() == Some(FAILING_KEY) {
                return Err(Unavailable);
            }
            let position = ledger.position.fetch_add(1, Ordering::SeqCst) + 1;
            let kind = access_http::api::realm::spec(w.operation).unwrap().0;
            Ok(Written::Committed {
                exercise_id: caller.statement.intent,
                position,
                resource: Some(fake_item(kind, w.key.as_deref().unwrap_or("new"), position)),
                secret: matches!(
                    w.operation,
                    "registerHook" | "registerWebhook" | "rotateWebhookKey"
                )
                .then(|| "whpk_fake".to_owned()),
            })
        })
    }
}

/// A field a fake platform read leaks on purpose; the handler must drop it (INV-29, X31).
pub const LEAKED: &str = "email";

fn fake_platform(kind: PlatformKind, key: &str) -> Item {
    let body = match kind {
        PlatformKind::Tenants => json!({ "tenant_id": key, "status": "active",
                                         "placement": "pool-default", LEAKED: "a@b.example" }),
        PlatformKind::Realms | PlatformKind::SandboxDomains => json!({
            "slug": key, "tenant_id": "tnt_x", "status": "active", "sandbox": false,
            "domain": b64url_encode(&[7; 32]), "key_state": "pending",
            "signing_available_at": null, "sub": "leak", "redirect_uris": ["https://x"],
            "genesis": { "digest": b64url_encode(&[7; 32]), "recovery": "not_available",
                         "recovery_reason": "no-recover-entry", "claims": {} },
        }),
        PlatformKind::Health => json!({ "status": "ready", "checks": [], "record": "leak" }),
    };
    Item { body, version: 1 }
}

// INV-29, X31
impl PlatformResources for Shared {
    fn read(&self, q: PlatformQuery) -> Pending<'_, Option<Listing>> {
        let keys = q.key.map_or_else(|| vec!["a".to_owned()], |k| vec![k]);
        let listing = Listing {
            items: keys.iter().map(|k| fake_platform(q.kind, k)).collect(),
            last: None,
        };
        Box::pin(async move { Ok(Some(listing)) })
    }

    fn draft(&self, w: PlatformWrite) -> Pending<'_, Drafted> {
        let bytes = serde_json::to_vec(&w.body).unwrap();
        let digest = Digest(suiss_crypto::digest::sha256(&bytes));
        Box::pin(async move {
            Ok(Drafted::Draft(Draft {
                body: w.body,
                domain: w.domain,
                intent: bytes,
                intent_digest: digest,
                pep: "access-identity".to_owned(),
            }))
        })
    }

    fn commit(&self, w: PlatformWrite, caller: WriteCaller) -> Pending<'_, Written> {
        let ledger = self.0.ledger.clone();
        ledger.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let position = ledger.position.fetch_add(1, Ordering::SeqCst) + 1;
            let kind = access_http::api::platform::spec(w.operation).unwrap().0;
            Ok(Written::Committed {
                exercise_id: caller.statement.intent,
                position,
                resource: Some(fake_platform(kind, "new")),
                secret: Some("never-shown".to_owned()),
            })
        })
    }
}

pub struct TestEnv(pub Shared);

impl Env for TestEnv {
    type Tokens = Shared;
    type Surfaces = Shared;
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
    fn idempotency(&self) -> &Shared {
        &self.0
    }
    fn origin(&self) -> &str {
        ORIGIN
    }
    fn realm(&self) -> &dyn RealmResources {
        &self.0
    }
    fn platform(&self) -> &dyn PlatformResources {
        &self.0
    }
    fn jobs(&self) -> &dyn Jobs {
        &self.0
    }
}

// TN-125
impl Jobs for Shared {
    fn create(&self, slug: String, job: NewJob) -> Pending<'_, Option<String>> {
        let mut jobs = self.0.jobs.lock().unwrap();
        let id = format!("00000000-0000-0000-0000-{:012}", jobs.len() + 1);
        let created = (slug == REALM).then(|| {
            let items = job
                .items
                .iter()
                .enumerate()
                .map(|(i, (op, key))| JobItem {
                    index: u32::try_from(i).unwrap(),
                    operation: op.clone(),
                    key: key.clone(),
                    status: "pending".to_owned(),
                    http_status: None,
                    problem: None,
                    exercise_id: None,
                    position: None,
                })
                .collect();
            let view = JobView {
                id: id.clone(),
                mode: job.mode.to_owned(),
                status: "running".to_owned(),
                items: u32::try_from(job.items.len()).unwrap(),
                committed: 0,
                failed: 0,
                throttled: 0,
                created_ms: job.created_ms,
                finished_ms: None,
                expires_ms: job.expires_ms,
            };
            jobs.insert(id.clone(), (view, items));
            id
        });
        Box::pin(async move { Ok(created) })
    }

    fn record(&self, _: String, job: String, item: JobItem) -> Pending<'_, ()> {
        if let Some((view, items)) = self.0.jobs.lock().unwrap().get_mut(&job) {
            match item.status.as_str() {
                "committed" => view.committed += 1,
                "throttled" => view.throttled += 1,
                _ => view.failed += 1,
            }
            let i = item.index as usize;
            items[i] = item;
        }
        Box::pin(async { Ok(()) })
    }

    fn finish(&self, _: String, job: String, status: &'static str, now_ms: u64) -> Pending<'_, ()> {
        if let Some((view, _)) = self.0.jobs.lock().unwrap().get_mut(&job) {
            status.clone_into(&mut view.status);
            view.finished_ms = Some(now_ms);
        }
        Box::pin(async { Ok(()) })
    }

    fn read(&self, slug: String, job: String, now_ms: u64) -> Pending<'_, Option<JobView>> {
        let found = self
            .0
            .jobs
            .lock()
            .unwrap()
            .get(&job)
            .map(|(v, _)| v.clone())
            .or_else(|| {
                (job != HIDDEN_KEY).then(|| JobView {
                    id: job.clone(),
                    mode: "parallel".to_owned(),
                    status: "succeeded".to_owned(),
                    items: 1,
                    committed: 1,
                    failed: 0,
                    throttled: 0,
                    created_ms: now_ms,
                    finished_ms: Some(now_ms),
                    expires_ms: now_ms + 1,
                })
            })
            .filter(|v| slug == REALM && v.expires_ms > now_ms);
        Box::pin(async move { Ok(found) })
    }

    fn items(
        &self,
        _: String,
        job: String,
        after: Option<u32>,
        limit: u32,
    ) -> Pending<'_, Vec<JobItem>> {
        let page = self
            .0
            .jobs
            .lock()
            .unwrap()
            .get(&job)
            .map(|(_, items)| {
                items
                    .iter()
                    .filter(|i| after.is_none_or(|a| i.index > a))
                    .take(limit as usize)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Box::pin(async move { Ok(page) })
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
            nonces: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
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

    /// Moves the clock on by `ms`, so a test that walks every row stays inside the surface's
    /// write rate (TN-127).
    pub fn pass(&self, ms: u64) {
        self.fake.now.fetch_add(ms, Ordering::SeqCst);
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

    /// The writes the realm and platform resources were asked to commit.
    pub fn commits(&self) -> u64 {
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
    ais_over(signer, domain, nonce, iat, mode, Digest([0x44; 32]))
}

/// An AIS whose statement signs `intent`.
pub fn ais_over(
    signer: &SoftSigner,
    domain: Digest,
    nonce: [u8; 16],
    iat: u64,
    mode: Mode,
    intent: Digest,
) -> String {
    let statement = Statement {
        domain,
        nonce: nonce.to_vec(),
        intent,
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

pub static ROWS: &[Route] = &[PLATFORM_ROOT, REALM_ROOT];

#[allow(clippy::unused_async, reason = "an axum handler")]
pub async fn surface(Extension(_ctx): Extension<Ctx<TestEnv>>) -> axum::response::Response {
    StatusCode::OK.into_response()
}
