//! The MCP resource server SDK against the real server (OP-154 m.3 (v), OP-153 m.3 (gg)): a
//! bootstrapped realm whose sample subject holds a Grant of the sample action, tokens decided
//! and signed by the authority plane and its signer over the real sequencer and `SoftHSM`, Domain
//! Metadata and Token Status Lists from their real routes, and every `tools/call`, list check and
//! stream decision asked through the real ADP router with the MCP server as PEP.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use access_authority_core::status::Publisher;
use access_authority_core::status::adapters::{PgLists, SignerSocket};
use access_http::adp::adapters::{Discovery, Pep as PepId, router as adp_router};
use access_internal_api::projections::{
    Confirmation, Projections as _, TokenKind, TokenProjection, TokenProjectionRequest,
};
use access_kernel::json::{self as kjson, Json, b64url_decode};
use access_kernel::validity::{ProfileClass, ProfileVariant};
use access_kernel::verify::cose::{Algorithm, parse_sign1};
use access_kernel::verify::key_scope::DomainMetadata;
use access_sdk::auth::dpop::{ProofFor, ProofKey, proof};
use access_sdk::auth::replay::MemoryReplay;
use access_sdk::auth::{Random, RandomUnavailable};
use access_sdk::authorize::{AskDecision, ExerciseRequest, adp_body};
use access_sdk::mcp::cache::ListCache;
use access_sdk::mcp::client::meta;
use access_sdk::mcp::listen::{Closed, Next};
use access_sdk::mcp::prm::{Binding as PrmBinding, ProtectedResource};
use access_sdk::mcp::server::{Env, Handled, McpServer, Request as McpRequest, Response};
use access_sdk::mcp::state::StateKey;
use access_sdk::mcp::tool::{ToolDef, Tools, intent as tool_intent};
use access_sdk::mcp::wire::{Headers, Origins};
use access_sdk::resource::{
    Config, Introspector, KeySource, Keys, NonceSource, Ports, Profile, ResourceServer,
    Revocations, StatusSource,
};
use access_sdk::transport::{Answer, Clock, Fault, Response as Answered};
use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequest, header};
use suiss_crypto::signer::SoftSigner;
use tower::ServiceExt as _;

use super::*;

/// The MCP server: its canonical URI is the tokens' only audience.
const MCP: &str = "https://mcp.access.test/mcp";
/// The MCP server's PEP identity, as its client certificate names it to ADP.
const MCP_PEP: &str = "mcp-reference";
const MCP_HOST: &str = "mcp.access.test";
const ISSUER: &str = "https://access.test/realms/acme";

fn wall() -> u64 {
    now_ms()
}

struct Wall;

impl Clock for Wall {
    fn now(&self) -> Option<u64> {
        Some(wall())
    }
}

struct At(Cell<u64>);

impl Clock for At {
    fn now(&self) -> Option<u64> {
        Some(self.0.get())
    }
}

struct Csprng;

impl Random for Csprng {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        for chunk in out.chunks_mut(16) {
            let b: [u8; 16] = access_crypto::random::bytes().map_err(|_| RandomUnavailable)?;
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        Ok(())
    }
}

/// The agent's DPoP key.
struct DpopKey {
    signer: SoftSigner,
    public: PublicKey,
}

impl DpopKey {
    fn new() -> Self {
        let signer = SoftSigner::generate_p256().unwrap().0;
        let public = suiss_crypto::signer::Signer::public_key(&signer);
        Self { signer, public }
    }

    fn jkt(&self) -> [u8; 32] {
        thumbprint(&self.public)
    }
}

impl ProofKey for DpopKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        suiss_crypto::signer::Signer::sign(&self.signer, input).ok()
    }
}

/// The real routes in this process: ADP (the MCP server as transport-authenticated PEP) and
/// the Token Status Lists, reached from the SDK's blocking ports.
struct Live {
    adp: axum::Router,
    status: axum::Router,
    domain: Digest,
    asked: AtomicUsize,
}

fn block<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

fn fetch(router: &axum::Router, path: &str, pep: Option<&str>, body: Option<String>) -> Answer {
    let mut req = match body {
        Some(b) => HttpRequest::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b))
            .unwrap(),
        None => HttpRequest::get(path).body(Body::empty()).unwrap(),
    };
    if let Some(p) = pep {
        req.extensions_mut().insert(PepId(p.to_owned()));
    }
    let r = block(router.clone().oneshot(req)).unwrap();
    let status = r.status().as_u16();
    let content_type = r
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let key_excerpt = r
        .headers()
        .get("access-key-excerpt")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| b64url_decode(v).ok());
    let body = block(to_bytes(r.into_body(), 1 << 22)).unwrap().to_vec();
    Answer::Response(Answered {
        status,
        content_type,
        key_excerpt,
        body,
    })
}

impl AskDecision for Live {
    fn ask(&self, request: &ExerciseRequest<'_>) -> Answer {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let Some(body) = adp_body(request) else {
            return Answer::Unanswered(Fault::Transport);
        };
        fetch(
            &self.adp,
            "/access/v1/evaluation",
            Some(MCP_PEP),
            Some(body),
        )
    }
}

impl KeySource for Live {
    fn metadata(&self) -> Keys {
        Keys::Fetched(fetch(
            &self.adp,
            &format!(
                "/.well-known/access-domain-metadata/sha-256:{}",
                b64url_encode(&self.domain.0)
            ),
            None,
            None,
        ))
    }
}

impl StatusSource for Live {
    fn list(&self, uri: &str) -> Answer {
        match uri.strip_prefix("https://access.test") {
            Some(path) => fetch(&self.status, path, None, None),
            None => Answer::Unanswered(Fault::Unreachable),
        }
    }
}

/// The fast profile introspects nothing; an introspection is never answered here.
impl Introspector for Live {
    fn introspect(&self, _token: &str) -> Answer {
        Answer::Unanswered(Fault::Unreachable)
    }
}

impl NonceSource for Live {
    fn accept(&self, _nonce: Option<&str>) -> bool {
        true
    }
}

impl Revocations for Live {
    fn family_ended(&self, _family: &[u8; 16]) -> bool {
        false
    }
}

/// A bootstrapped realm with the sample subject's Grant, a Public Grant of the sample action and
/// a Grant of it that waits on an approval, and the MCP server's configuration.
struct Mcp {
    w: World,
    live: Live,
    signer_socket: PathBuf,
    domain: Digest,
    subject: HsmSigner,
    subject_party: Id,
    holding: HoldingRef,
    gated: HoldingRef,
    public: Id,
    action: ActionRef,
    rs: ResourceServer,
    pep: access_sdk::authorize::Pep,
    prm: ProtectedResource,
    metadata: String,
    origins: Origins,
    state: StateKey,
    cache: ListCache,
    replay: MemoryReplay<Wall>,
}

fn ledger(path: &str) -> ResourceRef {
    ResourceRef {
        namespace: String::from("work"),
        path: vec![String::from(path)],
        incarnation: 0,
    }
}

fn tool(name: &str, action: &ActionRef, public: Option<Id>) -> ToolDef {
    ToolDef {
        name: String::from(name),
        action: action.clone(),
        resource: ledger(name),
        scopes: vec![String::from("work:approve")],
        public,
        secret: BTreeSet::new(),
        listing: Json::Object(vec![(String::from("name"), Json::Str(String::from(name)))]),
    }
}

fn signed(key: &HsmSigner, s: &Statement) -> Vec<u8> {
    sign(key, s).unwrap()
}

/// Commits the root's `grant_issue` of `content` and returns the holding of `holder`.
async fn grant(w: &World, domain: Digest, content: GrantContent, holder: Id) -> (Id, u64) {
    let root = root_key(&w.keys).unwrap();
    let payload = Payload::GrantIssue(content);
    let now = server_time(&w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, holder, validity).unwrap();
    let digest = intent_digest(&intent).unwrap();
    let nonce = Csprng.bytes16();
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&domain));
    let ais = signed(
        &root,
        &Statement {
            domain,
            nonce: nonce.to_vec(),
            intent: digest,
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now,
            exercise: None,
        },
    );
    MetaExercises::lead(&w.plane, domain).await.unwrap();
    let verdict = MetaExercises::meta(
        &w.plane,
        Request {
            domain,
            mode: Mode::Commit,
            nonce: nonce.to_vec(),
            intent,
            payload: Some(payload),
            basis,
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        },
        ais,
        String::from(IDENTITY_PEP),
    )
    .await
    .unwrap();
    let Verdict::Committed(c) = verdict else {
        panic!("{verdict:?}");
    };
    (meta::object_id(&c.exercise, kind::GRANT, 0), c.position)
}

impl Csprng {
    fn bytes16(&self) -> [u8; 16] {
        let mut b = [0; 16];
        self.fill(&mut b).unwrap();
        b
    }
}

impl Mcp {
    async fn open(name: &str) -> Self {
        let (w, signer) = World::open(name, true).await;
        let signer = signer.unwrap();
        let summary = w.run(&sample_plan()).await;
        schedule(&signer);
        schedule(&signer);
        let json = serde_json::to_value(&summary).unwrap();
        let sample = &json["sample"];
        let domain = Digest(
            <[u8; 32]>::try_from(b64url_decode(sample["domain"].as_str().unwrap()).unwrap())
                .unwrap(),
        );
        let holding = holding_of(&sample["basis"]);
        let plan = sample_plan().sample.unwrap();
        let action = plan.action_ref();
        let subject = token_key(&w.keys, SUBJECT_LABEL).unwrap();
        let subject_party = root_party(&subject.public_key());
        assert_eq!(holding.holder, subject_party);
        let everyone = BTreeSet::from([action.clone()]);
        let (public, _) = grant(
            &w,
            domain,
            GrantContent {
                basis: GrantBasis::Anchor(meta::meta_anchor(&domain)),
                holder: SubjectSelector::Public,
                authority: authority(everyone.clone(), "work", BTreeSet::new()),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            },
            root_party(&root_key(&w.keys).unwrap().public_key()),
        )
        .await;
        let (gated_grant, since) = grant(
            &w,
            domain,
            grant_of(
                &domain,
                subject_party,
                authority(everyone, "work", BTreeSet::from([approval_term()])),
            ),
            subject_party,
        )
        .await;
        let gated = HoldingRef {
            grant: gated_grant,
            holder: subject_party,
            since,
        };
        let adp = adp_router(
            access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
            Discovery {
                issuer: String::from("https://access.test"),
            },
        );
        let live = Live {
            adp,
            status: crate::status::routes(w.db.app.clone()),
            domain,
            asked: AtomicUsize::new(0),
        };
        let cose = match live.metadata() {
            Keys::Fetched(Answer::Response(r)) if r.status == 200 => r.body,
            other => panic!("{other:?}"),
        };
        let pinned =
            DomainMetadata::from_bytes(&parse_sign1(&cose).unwrap().payload.unwrap()).unwrap();
        let rs = ResourceServer::new(Config {
            issuer: String::from(ISSUER),
            audience: String::from(MCP),
            domain,
            metadata: pinned.clone(),
            profile: Profile::Fast,
            algorithms: BTreeSet::from([Algorithm::Ed25519, Algorithm::Es256]),
            key_epoch_ms: 3_600_000,
        })
        .unwrap();
        let prm = ProtectedResource::new(
            MCP,
            vec![String::from(ISSUER)],
            vec![String::from("work:approve")],
            PrmBinding::Dpop(vec![String::from("ES256")]),
        )
        .unwrap();
        let signer_socket = std::env::temp_dir()
            .join(format!("abs-auth-{name}-{}", std::process::id()))
            .join("a.sock");
        Self {
            metadata: prm.json(),
            prm,
            live,
            signer_socket,
            domain,
            subject,
            subject_party,
            holding,
            gated,
            public,
            action,
            rs,
            pep: access_sdk::authorize::Pep {
                audience: String::from(MCP_PEP),
                domain,
                metadata: pinned,
            },
            origins: Origins {
                origins: vec![String::from("https://agent.example")],
                hosts: vec![String::from(MCP_HOST)],
            },
            state: StateKey::new(Secret::new(access_crypto::random::bytes().unwrap())),
            cache: ListCache::new(64),
            replay: MemoryReplay::new(Wall, 4096),
            w,
        }
    }

    /// The bounds token the sample subject's `projection.issue` gets for `audience`, bound to
    /// `dpop`, decided and signed by the authority plane, with the status lists published after.
    async fn token(&self, audience: &str, dpop: &DpopKey) -> String {
        let now = server_time(&self.w.db.app).await.unwrap();
        let mut bounds = authority(
            BTreeSet::from([self.action.clone()]),
            "work",
            BTreeSet::new(),
        );
        bounds.constraints.validity = Window {
            from: now - 1_000,
            until: now + 240_000,
        };
        let payload = Payload::ProjectionIssue {
            bounds,
            audience: BTreeSet::from([audience.to_owned()]),
            class: ProfileClass::Online,
            variant: ProfileVariant::OnlineStrict,
            max_staleness_ms: None,
            offline_slice: None,
        };
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let intent = self_signed_intent(&payload, self.subject_party, validity).unwrap();
        let nonce = Csprng.bytes16().to_vec();
        let basis = ExerciseBasis::Holding(self.holding);
        let ais = signed(
            &self.subject,
            &Statement {
                domain: self.domain,
                nonce: nonce.clone(),
                intent: intent_digest(&intent).unwrap(),
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity: Capacity::Own,
                basis,
                iat: now,
                exercise: None,
            },
        );
        let issued = self
            .w
            .plane
            .issue(TokenProjectionRequest {
                domain: self.domain,
                nonce,
                intent,
                payload: payload.to_bytes().unwrap(),
                basis,
                capacity: Capacity::Own,
                ais,
                pep: String::from(IDENTITY_PEP),
                issuer: String::from(ISSUER),
                client_id: String::from("https://agent.example/client.json"),
                kind: TokenKind::Bounds,
                target: None,
                confirmation: Confirmation::DpopJkt(dpop.jkt()),
                resources: vec![audience.to_owned()],
                family: None,
            })
            .await
            .unwrap();
        let TokenProjection::Issued(t) = issued else {
            panic!("{issued:?}");
        };
        Publisher::new(
            PgLists {
                app: self.w.db.app.clone(),
                sequencer: self.w.db.sequencer.clone(),
            },
            SignerSocket(self.signer_socket.clone()),
        )
        .publish(self.domain, server_time(&self.w.db.app).await.unwrap())
        .await
        .unwrap();
        t.token
    }

    /// The sample subject's statement for the MCP server as PEP.
    fn statement(
        &self,
        intent: Digest,
        nonce: &[u8],
        basis: HoldingRef,
        mode: Mode,
        exercise: Option<Digest>,
    ) -> Vec<u8> {
        signed(
            &self.subject,
            &Statement {
                domain: self.domain,
                nonce: nonce.to_vec(),
                intent,
                mode,
                pep: String::from(MCP_PEP),
                capacity: Capacity::Own,
                basis: ExerciseBasis::Holding(basis),
                iat: wall(),
                exercise,
            },
        )
    }

    fn server<'a>(&'a self, tools: &'a Tools, subscriptions: Option<&'a ToolDef>) -> McpServer<'a> {
        self.server_with(tools, subscriptions, &self.cache)
    }

    fn server_with<'a>(
        &'a self,
        tools: &'a Tools,
        subscriptions: Option<&'a ToolDef>,
        cache: &'a ListCache,
    ) -> McpServer<'a> {
        McpServer {
            prm: &self.prm,
            metadata: &self.metadata,
            origins: &self.origins,
            rs: &self.rs,
            pep: &self.pep,
            tools,
            subscriptions,
            state: &self.state,
            cache,
            approval_surface: "https://access.test/realms/acme/approve",
            list_ttl_ms: 30_000,
            discover: None,
            name: "mcp-reference",
        }
    }
}

/// One `POST /mcp` with `token` and a fresh DPoP proof by `dpop`, plus `extra` headers.
fn post(
    m: &Mcp,
    server: &McpServer<'_>,
    (token, dpop): (&str, &DpopKey),
    extra: &[(&str, &str)],
    body: &str,
) -> Handled {
    let p = proof(
        dpop,
        &ProofFor {
            method: "POST",
            uri: MCP,
            access_token: Some(token),
            nonce: None,
        },
        wall(),
        &Csprng,
    )
    .unwrap();
    let authorization = format!("DPoP {token}");
    let mut headers = vec![
        ("host", MCP_HOST),
        ("authorization", authorization.as_str()),
        ("dpop", p.as_str()),
    ];
    headers.extend_from_slice(extra);

    let ports = Ports {
        keys: &m.live,
        replay: &m.replay,
        nonces: &m.live,
        status: &m.live,
        introspection: &m.live,
        revocations: &m.live,
    };
    server.handle(
        &McpRequest {
            method: "POST",
            path: "/mcp",
            uri: MCP,
            headers: Headers(&headers),
            body: body.as_bytes(),
            certificate: None,
        },
        &Env {
            clock: &Wall,
            ports: &ports,
            decisions: &m.live,
            random: &Csprng,
        },
    )
}

fn respond(h: Handled) -> Response {
    match h {
        Handled::Respond(r) => r,
        other => panic!("{other:?}"),
    }
}

fn result_of(r: &Response) -> Json {
    kjson::parse(r.body.as_bytes(), 1 << 20)
        .unwrap()
        .get("result")
        .cloned()
        .unwrap_or(Json::Null)
}

fn rpc(method: &str, params: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#)
}

fn names(result: &Json) -> Vec<String> {
    match result.get("tools") {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|i| i.get("name").and_then(Json::as_str).map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

// U63, AGI-5, AG-12, RS-M17, A-10, AG-2, AG-11, §11.5.3, Ek B 4295, 4296, 4436, 4615, 4626
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_are_viewer_scoped_and_never_authorize_a_call() {
    let m = Mcp::open("mcp-lists").await;
    let viewer_a = DpopKey::new();
    let viewer_b = DpopKey::new();
    let token_a = m.token(MCP, &viewer_a).await;
    let token_b = m.token(MCP, &viewer_b).await;
    let tools = Tools::new(vec![
        tool("approve", &m.action, None),
        tool("probe", &m.action, Some(m.public)),
    ])
    .unwrap();
    let server = m.server(&tools, None);
    let list = rpc(
        "tools/list",
        &format!(r#"{{"_meta":{}}}"#, meta(None, None, None)),
    );
    for (token, key) in [(&token_a, &viewer_a), (&token_b, &viewer_b)] {
        let r = respond(post(&m, &server, (token, key), &[], &list));
        assert_eq!(r.status, 200, "{}", r.body);
        let result = result_of(&r);
        assert_eq!(
            result.get("cacheScope").and_then(Json::as_str),
            Some("private")
        );
        assert_eq!(names(&result), ["approve", "probe"]);
    }

    let public_only = Tools::new(vec![tool("probe", &m.action, Some(m.public))]).unwrap();
    let own_cache = ListCache::new(8);
    let public_server = m.server_with(&public_only, None, &own_cache);
    let r = respond(post(&m, &public_server, (&token_a, &viewer_a), &[], &list));
    let result = result_of(&r);
    assert_eq!(
        result.get("cacheScope").and_then(Json::as_str),
        Some("public"),
        "{}",
        r.body
    );
    assert_eq!(names(&result), ["probe"]);

    // A-10
    let before = m.live.asked.load(Ordering::SeqCst);
    let window = Window {
        from: wall() - 1_000,
        until: wall() + 60_000,
    };
    let foreign = HoldingRef {
        holder: Id([0x5a; 16]),
        ..m.holding
    };
    let digest =
        intent_digest(&tool_intent(&tool("approve", &m.action, None), None, window).unwrap())
            .unwrap();
    let nonce = Csprng.bytes16();
    let ais = m.statement(digest, &nonce, foreign, Mode::Commit, None);
    let call = rpc(
        "tools/call",
        &format!(
            r#"{{"name":"approve","_meta":{}}}"#,
            meta(Some(&ais), Some(window), None)
        ),
    );
    let r = respond(post(&m, &server, (&token_a, &viewer_a), &[], &call));
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(m.live.asked.load(Ordering::SeqCst), before + 1);

    // §11.5.3, §11.5.6
    let nonce = Csprng.bytes16();
    let ais = m.statement(digest, &nonce, m.holding, Mode::Commit, None);
    let call = rpc(
        "tools/call",
        &format!(
            r#"{{"name":"approve","clientInfo":{{"name":"root-console"}},"_meta":{}}}"#,
            meta(Some(&ais), Some(window), None)
        ),
    );
    let h = post(
        &m,
        &server,
        (&token_a, &viewer_a),
        &[("mcp-session-id", "s-1"), ("mcp-method", "tools/call")],
        &call,
    );
    let Handled::Call(c) = h else {
        panic!("{h:?}");
    };
    let r = c.run(|_, _, _| Json::Object(vec![(String::from("content"), Json::Array(Vec::new()))]));
    assert_eq!(r.status, 200);
    assert!(r.headers.iter().all(|(k, _)| k != "mcp-session-id"));
    m.w.domains.release().await;
}

// RS-M5, RS-M6, RS-M8, P48, §11.5.6, Ek B 4287, 4288, 4289, 4291, 4292
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_for_another_audience_is_401_and_bounds_ask_for_scope() {
    let m = Mcp::open("mcp-audience").await;
    let key = DpopKey::new();
    let other = m.token("https://other.access.test/mcp", &key).await;
    let tools = Tools::new(vec![tool("approve", &m.action, None)]).unwrap();
    let server = m.server(&tools, None);
    let list = rpc(
        "tools/list",
        &format!(r#"{{"_meta":{}}}"#, meta(None, None, None)),
    );
    let r = respond(post(&m, &server, (&other, &key), &[], &list));
    assert_eq!(r.status, 401, "{}", r.body);
    let challenges: Vec<&str> = r
        .headers
        .iter()
        .filter(|(k, _)| k == "www-authenticate")
        .map(|(_, v)| v.as_str())
        .collect();
    assert!(challenges[0].contains(r#"error="invalid_token""#));
    assert!(challenges[0].contains(
        r#"resource_metadata="https://mcp.access.test/.well-known/oauth-protected-resource/mcp""#
    ));
    assert!(challenges[1].starts_with(r#"DPoP algs="ES256""#));

    let mine = m.token(MCP, &key).await;
    let thief = DpopKey::new();
    let r = respond(post(&m, &server, (&mine, &thief), &[], &list));
    assert_eq!(r.status, 401);

    // RS-M11, §11.5.1
    let mut lock = tool("lock", &m.action, None);
    lock.action.name = String::from("lock");
    lock.scopes = vec![
        String::from("work:lock"),
        String::from("offline_access"),
        String::from("work:approve"),
    ];
    let wider = Tools::new(vec![tool("approve", &m.action, None), lock]).unwrap();
    let server = m.server(&wider, None);
    let call = rpc(
        "tools/call",
        &format!(r#"{{"name":"lock","_meta":{}}}"#, meta(None, None, None)),
    );
    let r = respond(post(&m, &server, (&mine, &key), &[], &call));
    assert_eq!(r.status, 403);
    let v = &r
        .headers
        .iter()
        .find(|(k, _)| k == "www-authenticate")
        .unwrap()
        .1;
    assert!(v.contains(r#"scope="work:lock work:approve""#), "{v}");
    let h = post(
        &m,
        &server,
        (&mine, &key),
        &[],
        &rpc(
            "tools/call",
            &format!(r#"{{"name":"approve","_meta":{}}}"#, meta(None, None, None)),
        ),
    );
    assert!(matches!(h, Handled::Call(_)), "{h:?}");
    m.w.domains.release().await;
}

// AGI-6, AG-13, RS-M12, RS-M13, EI-18, §9.9.5, P54, Ek B 4297, 4298, 4431
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_or_rebound_request_state_never_reaches_a_decision() {
    let m = Mcp::open("mcp-state").await;
    let key = DpopKey::new();
    let token = m.token(MCP, &key).await;
    let tools = Tools::new(vec![tool("approve", &m.action, None)]).unwrap();
    let server = m.server(&tools, None);
    let window = Window {
        from: wall() - 1_000,
        until: wall() + 60_000,
    };
    let digest =
        intent_digest(&tool_intent(&tool("approve", &m.action, None), None, window).unwrap())
            .unwrap();
    let nonce = Csprng.bytes16();
    let ais = m.statement(digest, &nonce, m.gated, Mode::Commit, None);
    let meta_call = meta(Some(&ais), Some(window), None);
    let call = rpc(
        "tools/call",
        &format!(r#"{{"name":"approve","_meta":{meta_call}}}"#),
    );
    let r = respond(post(&m, &server, (&token, &key), &[], &call));
    assert_eq!(r.status, 200, "{}", r.body);
    let result = result_of(&r);
    assert_eq!(
        result.get("resultType").and_then(Json::as_str),
        Some("input_required"),
        "{}",
        r.body
    );
    let elicitation = result
        .get("inputRequests")
        .and_then(|i| i.get("access.approval"))
        .and_then(|e| e.get("params"))
        .unwrap();
    assert_eq!(elicitation.get("mode").and_then(Json::as_str), Some("url"));
    assert_eq!(
        elicitation.get("url").and_then(Json::as_str),
        Some("https://access.test/realms/acme/approve")
    );
    let state = result
        .get("requestState")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();

    let rebound = rpc(
        "tools/call",
        &format!(
            r#"{{"name":"approve","arguments":{{"amount":5}},"requestState":"{state}","_meta":{meta_call}}}"#
        ),
    );
    let before = m.live.asked.load(Ordering::SeqCst);
    let r = respond(post(&m, &server, (&token, &key), &[], &rebound));
    assert!(r.body.contains("request-state"), "{}", r.body);
    assert_eq!(m.live.asked.load(Ordering::SeqCst), before);

    let retry = rpc(
        "tools/call",
        &format!(
            r#"{{"name":"approve","requestState":"{state}","inputResponses":{{"access.approval":{{"action":"accept"}}}},"_meta":{meta_call}}}"#
        ),
    );
    let r = respond(post(&m, &server, (&token, &key), &[], &retry));
    assert_eq!(m.live.asked.load(Ordering::SeqCst), before + 1);
    assert_eq!(
        result_of(&r).get("resultType").and_then(Json::as_str),
        Some("input_required"),
        "{}",
        r.body
    );

    let r = respond(post(&m, &server, (&token, &key), &[], &retry));
    assert!(r.body.contains("request-state-replayed"), "{}", r.body);
    assert_eq!(m.live.asked.load(Ordering::SeqCst), before + 1);
    m.w.domains.release().await;
}

// U64, AG-15, A-8, E31, Ek B 4300, 4301, 4437, 4609
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_carries_no_event_after_its_horizon() {
    let m = Mcp::open("mcp-listen").await;
    let key = DpopKey::new();
    let token = m.token(MCP, &key).await;
    let tools = Tools::new(Vec::new()).unwrap();
    let feed = tool("feed", &m.action, None);
    let server = m.server(&tools, Some(&feed));
    let now = wall();
    let window = Window {
        from: now - 1_000,
        until: now + 90_000,
    };
    let digest = intent_digest(&tool_intent(&feed, None, window).unwrap()).unwrap();
    let nonce = Csprng.bytes16();
    let exercise = meta::exercise_id(&m.domain, &nonce).unwrap();
    let ais = m.statement(digest, &nonce, m.holding, Mode::Commit, None);
    let cont = m.statement(
        digest,
        &Csprng.bytes16(),
        m.holding,
        Mode::Continue,
        Some(exercise),
    );
    let listen = rpc(
        "subscriptions/listen",
        &format!(
            r#"{{"_meta":{}}}"#,
            meta(Some(&ais), Some(window), Some(&cont))
        ),
    );
    let h = post(&m, &server, (&token, &key), &[], &listen);
    let Handled::Listen(mut stream) = h else {
        panic!("{h:?}");
    };
    let close = stream.listen.close_at();
    assert_eq!(close, window.until);
    assert_eq!(stream.listen.deliver(now + 1, "first"), Some("first"));
    let half = now + (close - now) / 2;
    assert!(matches!(stream.listen.next(half + 1), Next::Checkpoint(_)));
    assert_eq!(stream.listen.deliver(half + 2, "held"), None);
    let at = At(Cell::new(wall()));
    assert!(server.checkpoint(&mut stream, &at, &m.live));
    assert_eq!(stream.listen.deliver(half + 3, "second"), Some("second"));
    assert_eq!(
        stream.listen.present_token(&token),
        Err(access_sdk::mcp::listen::ListenError::Refresh)
    );
    assert_eq!(stream.listen.close_at(), close);
    assert_eq!(stream.listen.deliver(close, "late"), None);
    assert_eq!(stream.listen.deliver(close + 1, "later"), None);
    assert_eq!(stream.listen.next(close + 2), Next::Closed(Closed::Horizon));

    let nonce = Csprng.bytes16();
    let ais = m.statement(digest, &nonce, m.holding, Mode::Commit, None);
    let wrong = m.statement(
        digest,
        &Csprng.bytes16(),
        m.holding,
        Mode::Continue,
        Some(Digest([4; 32])),
    );
    let listen = rpc(
        "subscriptions/listen",
        &format!(
            r#"{{"_meta":{}}}"#,
            meta(Some(&ais), Some(window), Some(&wrong))
        ),
    );
    let Handled::Listen(mut stream) = post(&m, &server, (&token, &key), &[], &listen) else {
        panic!("listen");
    };
    stream.listen.signal();
    assert!(!server.checkpoint(&mut stream, &at, &m.live));
    assert_eq!(stream.listen.deliver(wall(), "after"), None);
    assert_eq!(stream.listen.next(wall()), Next::Closed(Closed::Denied));
    m.w.domains.release().await;
}

/// One request without a token, as the client sent it.
fn raw(
    m: &Mcp,
    server: &McpServer<'_>,
    (method, path): (&str, &str),
    headers: &[(&str, &str)],
    body: &str,
) -> Response {
    let ports = Ports {
        keys: &m.live,
        replay: &m.replay,
        nonces: &m.live,
        status: &m.live,
        introspection: &m.live,
        revocations: &m.live,
    };
    respond(server.handle(
        &McpRequest {
            method,
            path,
            uri: MCP,
            headers: Headers(headers),
            body: body.as_bytes(),
            certificate: None,
        },
        &Env {
            clock: &Wall,
            ports: &ports,
            decisions: &m.live,
            random: &Csprng,
        },
    ))
}

// RS-M1, RS-M14, RS-M15, AG-14, §11.5.2, §11.5.6, §11.5.7, Ek B 4289, 4299, 4543, 4544
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebinding_and_mismatched_headers_stop_before_any_decision() {
    let m = Mcp::open("mcp-wire").await;
    let key = DpopKey::new();
    let token = m.token(MCP, &key).await;
    let tools = Tools::new(vec![tool("approve", &m.action, None)]).unwrap();
    let server = m.server(&tools, None);
    let r = raw(
        &m,
        &server,
        ("GET", "/.well-known/oauth-protected-resource/mcp"),
        &[("host", MCP_HOST)],
        "",
    );
    assert_eq!(r.status, 200);
    let prm = kjson::parse(r.body.as_bytes(), 1 << 16).unwrap();
    assert_eq!(prm.get("resource").and_then(Json::as_str), Some(MCP));
    assert_eq!(
        prm.get("dpop_bound_access_tokens_required"),
        Some(&Json::Bool(true))
    );
    for method in ["GET", "DELETE"] {
        assert_eq!(
            raw(&m, &server, (method, "/mcp"), &[("host", MCP_HOST)], "").status,
            405
        );
    }

    let list = rpc(
        "tools/list",
        &format!(r#"{{"_meta":{}}}"#, meta(None, None, None)),
    );
    let before = m.live.asked.load(Ordering::SeqCst);
    let h = post(
        &m,
        &server,
        (&token, &key),
        &[("origin", "https://evil.example")],
        &list,
    );
    assert_eq!(respond(h).status, 403);
    let rebound = raw(
        &m,
        &server,
        ("POST", "/mcp"),
        &[("host", "rebound.example")],
        &list,
    );
    assert_eq!(rebound.status, 403);
    let call = rpc(
        "tools/call",
        &format!(
            r#"{{"name":"approve","arguments":{{"memo":"a"}},"_meta":{}}}"#,
            meta(None, None, None)
        ),
    );
    for header in [
        ("mcp-method", "tools/list"),
        ("mcp-name", "other"),
        ("mcp-param-memo", "b"),
        ("mcp-param-memo", "=?base64?Yg==?="),
    ] {
        let r = respond(post(&m, &server, (&token, &key), &[header], &call));
        assert_eq!(r.status, 400, "{header:?}");
        assert!(r.body.contains("-32020"), "{}", r.body);
    }
    let r = respond(post(
        &m,
        &server,
        (&token, &key),
        &[("x-trace", "a\r\nb")],
        &call,
    ));
    assert_eq!(r.status, 400);
    assert_eq!(m.live.asked.load(Ordering::SeqCst), before);
    let h = post(
        &m,
        &server,
        (&token, &key),
        &[
            ("mcp-param-memo", "=?base64?YQ==?="),
            ("origin", "https://agent.example"),
        ],
        &call,
    );
    assert!(matches!(h, Handled::Call(_)), "{h:?}");

    let discover = rpc(
        "server/discover",
        &format!(r#"{{"_meta":{}}}"#, meta(None, None, None)),
    );
    let r = raw(
        &m,
        &server,
        ("POST", "/mcp"),
        &[("host", MCP_HOST)],
        &discover,
    );
    assert_eq!(r.status, 401);
    let probe = access_sdk::mcp::server::Discoverable {
        action: m.action.clone(),
        resource: ledger("discover"),
        grant: m.public,
    };
    let open = McpServer {
        discover: Some(&probe),
        ..m.server(&tools, None)
    };
    let r = raw(
        &m,
        &open,
        ("POST", "/mcp"),
        &[("host", MCP_HOST)],
        &discover,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        result_of(&r).get("cacheScope").and_then(Json::as_str),
        Some("public")
    );
    m.w.domains.release().await;
}
