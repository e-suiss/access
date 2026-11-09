//! The reference MCP resource server (§11.5, AG-16, OP-154 m.3 (v)): the `mcp` module of this
//! SDK behind axum, its upstream ports over blocking HTTPS with the server's own client
//! certificate as its PEP identity (L1-ADP-2). It serves the protected resource metadata and
//! `POST` on the MCP path; every tool in its table runs only on an `Authorized` proof, and a
//! `subscriptions/listen` stream sends a heartbeat until its horizon.
//!
//! Configuration is read from the environment, nothing has a permissive default:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `MCP_RESOURCE` | The canonical MCP server URI, the tokens' only audience |
//! | `MCP_BIND` | The listen address; a loopback address must be `127.0.0.1` |
//! | `MCP_PEP` | This server's PEP name, as its client certificate names it to Access |
//! | `MCP_TOOLS` | Path of the tool table (JSON array of `{name, action, resource, scopes, public?}`) |
//! | `MCP_ORIGINS` | Allowed `Origin` values, comma-separated (may be empty) |
//! | `ACCESS_ISSUER` | The realm's authorization server issuer |
//! | `ACCESS_API` | The Access API origin (`https://…`) |
//! | `ACCESS_DOMAIN` | The domain, `sha-256:<base64url>` |
//! | `ACCESS_METADATA` | Path of the domain's signed Domain Metadata, pinned at deployment |
//! | `ACCESS_APPROVAL` | The realm's Approval Surface address |
//! | `ACCESS_CA`, `MCP_CERT`, `MCP_KEY` | PEM paths: the CA Access is verified under, this server's certificate and key |

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::model::{ActionRef, Id, ResourceRef};
use access_kernel::verify::cose::{Algorithm, parse_sign1};
use access_kernel::verify::key_scope::DomainMetadata;
use access_sdk::auth::replay::MemoryReplay;
use access_sdk::auth::{Random, RandomUnavailable};
use access_sdk::authorize::{AskDecision, ExerciseRequest, Pep, adp_body};
use access_sdk::mcp::cache::ListCache;
use access_sdk::mcp::listen::Next;
use access_sdk::mcp::prm::{Binding, ProtectedResource};
use access_sdk::mcp::server::{Env, Handled, McpServer, Request, Response, Stream, sse_event};
use access_sdk::mcp::state::StateKey;
use access_sdk::mcp::tool::{ToolDef, Tools};
use access_sdk::mcp::wire::{Headers, Origins, local_bind};
use access_sdk::resource::{
    Config, Introspector, KeySource, Keys, NonceSource, Ports, Profile, ResourceServer,
    Revocations, StatusSource,
};
use access_sdk::transport::{Answer, Clock, Fault, Response as Answered};
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use suiss_crypto::envelope::Dek;
use suiss_crypto::secret::Secret;

/// Longest any upstream call may take.
const UPSTREAM_DEADLINE: Duration = Duration::from_secs(5);

/// Largest upstream answer read.
const MAX_ANSWER: u64 = 1 << 20;

/// Interval of a stream's heartbeat event.
const HEARTBEAT: Duration = Duration::from_secs(10);

type Failure = Box<dyn std::error::Error + Send + Sync>;

fn var(name: &str) -> Result<String, Failure> {
    std::env::var(name).map_err(|_| Failure::from(format!("{name} is not set")))
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Option<u64> {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        u64::try_from(d.as_millis()).ok()
    }
}

struct Csprng;

impl Random for Csprng {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        for chunk in out.chunks_mut(32) {
            let dek = Dek::generate().map_err(|_| RandomUnavailable)?;
            let bytes = dek.secret().expose();
            let n = chunk.len();
            chunk.copy_from_slice(bytes.get(..n).ok_or(RandomUnavailable)?);
        }
        Ok(())
    }
}

/// Blocking HTTPS to Access with this server's client certificate.
struct Upstream {
    api: String,
    domain: Digest,
    tls: Arc<rustls::ClientConfig>,
}

fn split_url(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("https://")?;
    Some(rest.find('/').map_or((rest, "/"), |i| rest.split_at(i)))
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

impl Upstream {
    fn fetch(&self, method: &str, url: &str, body: Option<(&str, &[u8])>) -> Answer {
        self.try_fetch(method, url, body)
            .unwrap_or(Answer::Unanswered(Fault::Unreachable))
    }

    fn try_fetch(&self, method: &str, url: &str, body: Option<(&str, &[u8])>) -> Option<Answer> {
        let (authority, path) = split_url(url)?;
        let host = authority.split(':').next()?;
        let addr: SocketAddr = if authority.contains(':') {
            authority.to_socket_addrs().ok()?.next()?
        } else {
            (host, 443).to_socket_addrs().ok()?.next()?
        };
        let tcp = TcpStream::connect_timeout(&addr, UPSTREAM_DEADLINE).ok()?;
        tcp.set_read_timeout(Some(UPSTREAM_DEADLINE)).ok()?;
        tcp.set_write_timeout(Some(UPSTREAM_DEADLINE)).ok()?;
        let name = ServerName::try_from(host.to_owned()).ok()?;
        let conn = rustls::ClientConnection::new(Arc::clone(&self.tls), name).ok()?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        let mut head = format!("{method} {path} HTTP/1.0\r\nHost: {authority}\r\nAccept: */*\r\n");
        if let Some((content_type, b)) = body {
            let _ = write!(
                head,
                "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
                b.len()
            );
        }
        head.push_str("\r\n");
        tls.write_all(head.as_bytes()).ok()?;
        if let Some((_, b)) = body {
            tls.write_all(b).ok()?;
        }
        let mut raw = Vec::new();
        let _ = tls.take(MAX_ANSWER).read_to_end(&mut raw);
        let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
        let (head, rest) = raw.split_at(end);
        let head = std::str::from_utf8(head).ok()?;
        let status = head.split_whitespace().nth(1)?.parse().ok()?;
        Some(Answer::Response(Answered {
            status,
            content_type: header_value(head, "content-type").map(str::to_owned),
            key_excerpt: header_value(head, "access-key-excerpt")
                .and_then(|v| b64url_decode(v).ok()),
            body: rest.get(4..)?.to_vec(),
        }))
    }
}

impl AskDecision for Upstream {
    fn ask(&self, request: &ExerciseRequest<'_>) -> Answer {
        let Some(body) = adp_body(request) else {
            return Answer::Unanswered(Fault::Transport);
        };
        self.fetch(
            "POST",
            &format!("{}/access/v1/evaluation", self.api),
            Some(("application/json", body.as_bytes())),
        )
    }
}

impl KeySource for Upstream {
    fn metadata(&self) -> Keys {
        Keys::Fetched(self.fetch(
            "GET",
            &format!(
                "{}/.well-known/access-domain-metadata/{}",
                self.api,
                access_kernel::verify::projection::digest_text(&self.domain)
            ),
            None,
        ))
    }
}

impl StatusSource for Upstream {
    fn list(&self, uri: &str) -> Answer {
        if uri.starts_with(&self.api) {
            self.fetch("GET", uri, None)
        } else {
            Answer::Unanswered(Fault::Unreachable)
        }
    }
}

impl Introspector for Upstream {
    fn introspect(&self, _token: &str) -> Answer {
        Answer::Unanswered(Fault::Unreachable)
    }
}

impl NonceSource for Upstream {
    fn accept(&self, _nonce: Option<&str>) -> bool {
        true
    }
}

impl Revocations for Upstream {
    fn family_ended(&self, _family: &[u8; 16]) -> bool {
        false
    }
}

/// Everything one request borrows.
struct State {
    prm: ProtectedResource,
    metadata: String,
    origins: Origins,
    rs: ResourceServer,
    pep: Pep,
    tools: Tools,
    feed: Option<ToolDef>,
    sealer: StateKey,
    cache: ListCache,
    replay: MemoryReplay<SystemClock>,
    upstream: Upstream,
    approval: String,
    path: String,
}

impl State {
    fn server(&self) -> McpServer<'_> {
        McpServer {
            prm: &self.prm,
            metadata: &self.metadata,
            origins: &self.origins,
            rs: &self.rs,
            pep: &self.pep,
            tools: &self.tools,
            subscriptions: self.feed.as_ref(),
            state: &self.sealer,
            cache: &self.cache,
            approval_surface: &self.approval,
            list_ttl_ms: 30_000,
            discover: None,
            name: "access-mcp-reference",
        }
    }

    fn handle(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Handled {
        let pairs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let ports = Ports {
            keys: &self.upstream,
            replay: &self.replay,
            nonces: &self.upstream,
            status: &self.upstream,
            introspection: &self.upstream,
            revocations: &self.upstream,
        };
        let env = Env {
            clock: &SystemClock,
            ports: &ports,
            decisions: &self.upstream,
            random: &Csprng,
        };
        self.server().handle(
            &Request {
                method,
                path,
                uri: self.prm.resource(),
                headers: Headers(&pairs),
                body,
                certificate: None,
            },
            &env,
        )
    }
}

fn reply(r: Response) -> axum::response::Response {
    let mut out = axum::response::Response::new(Body::from(r.body));
    *out.status_mut() = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    for (k, v) in r.headers {
        if let (Ok(k), Ok(v)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) {
            out.headers_mut().append(k, v);
        }
    }
    out
}

/// The tool's result: the arguments echoed as text (a reference tool performs no effect).
fn echo(arguments: &Json) -> Json {
    let mut text = String::new();
    text.push_str(&access_sdk::mcp::render_json(arguments));
    Json::Object(vec![(
        String::from("content"),
        Json::Array(vec![Json::Object(vec![
            (String::from("type"), Json::Str(String::from("text"))),
            (String::from("text"), Json::Str(text)),
        ])]),
    )])
}

/// Drives one stream: a heartbeat every [`HEARTBEAT`] while [`Next::Open`], the checkpoint
/// asked when due, and the end at the close.
fn stream(state: Arc<State>, mut s: Stream) -> axum::response::Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::task::spawn_blocking(move || {
        loop {
            let Some(now) = SystemClock.now() else { return };
            match s.listen.next(now) {
                Next::Closed(_) => return,
                Next::Checkpoint(_) => {
                    if !state
                        .server()
                        .checkpoint(&mut s, &SystemClock, &state.upstream)
                    {
                        return;
                    }
                }
                Next::Open => {
                    let event = Json::Object(vec![
                        (String::from("jsonrpc"), Json::Str(String::from("2.0"))),
                        (
                            String::from("method"),
                            Json::Str(String::from("notifications/heartbeat")),
                        ),
                    ]);
                    if let Some(e) = s.listen.deliver(now, sse_event(&event))
                        && tx.blocking_send(Ok(Bytes::from(e))).is_err()
                    {
                        return;
                    }
                    let left = s.listen.close_at().saturating_sub(now);
                    std::thread::sleep(HEARTBEAT.min(Duration::from_millis(left.max(1))));
                }
            }
        }
    });
    let body = Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }));
    let mut out = axum::response::Response::new(body);
    for (k, v) in Stream::headers() {
        if let (Ok(k), Ok(v)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) {
            out.headers_mut().insert(k, v);
        }
    }
    out
}

async fn endpoint(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
        .collect();
    let path = uri.path().to_owned();
    let worker = Arc::clone(&state);
    let handled = tokio::task::spawn_blocking(move || {
        match worker.handle(method.as_str(), &path, &pairs, &body) {
            Handled::Respond(r) => Ok(r),
            Handled::Call(c) => Ok(c.run(|_, arguments, _| echo(arguments))),
            Handled::Listen(s) => Err(Box::new(s)),
        }
    })
    .await;
    match handled {
        Ok(Ok(r)) => reply(r),
        Ok(Err(s)) => stream(state, *s),
        Err(_) => reply(Response {
            status: 500,
            headers: Vec::new(),
            body: String::new(),
        }),
    }
}

fn tool_of(v: &Json) -> Result<ToolDef, Failure> {
    let text = |o: &Json, k: &str| -> Result<String, Failure> {
        o.get(k)
            .and_then(Json::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Failure::from(format!("tool member {k}")))
    };
    let action = v.get("action").ok_or("tool action")?;
    let resource = v.get("resource").ok_or("tool resource")?;
    let schema = access_sdk::resource::claims::digest_of_text(&text(action, "schema")?)
        .ok_or("tool action schema")?;
    let path = match resource.get("path") {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    let public = match v.get("public").and_then(Json::as_str) {
        None => None,
        Some(p) => Some(Id(<[u8; 16]>::try_from(b64url_decode(p)?.as_slice())?)),
    };
    Ok(ToolDef {
        name: text(v, "name")?,
        action: ActionRef {
            namespace: text(action, "namespace")?,
            name: text(action, "name")?,
            major: action
                .get("major")
                .and_then(Json::as_int)
                .and_then(|m| u64::try_from(m).ok())
                .ok_or("tool action major")?,
            schema,
        },
        resource: ResourceRef {
            namespace: text(resource, "namespace")?,
            path,
            incarnation: 0,
        },
        scopes: match v.get("scopes") {
            Some(Json::Array(s)) => s
                .iter()
                .filter_map(|i| i.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        },
        public,
        secret: BTreeSet::new(),
        listing: Json::Object(vec![(String::from("name"), Json::Str(text(v, "name")?))]),
    })
}

fn tls(ca: &str, cert: &str, key: &str) -> Result<rustls::ClientConfig, Failure> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(ca)? {
        roots.add(c?)?;
    }
    let chain = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key)?;
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_client_auth_cert(chain, key)?)
}

#[allow(clippy::too_many_lines, reason = "one pass over the configuration")]
fn state() -> Result<(SocketAddr, State), Failure> {
    let bind: SocketAddr = var("MCP_BIND")?.parse()?;
    // §11.5.6, RS-M15
    if bind.ip().is_loopback() || bind.ip().is_unspecified() {
        local_bind(bind.ip())?;
    }
    let resource = var("MCP_RESOURCE")?;
    let issuer = var("ACCESS_ISSUER")?;
    let api = var("ACCESS_API")?;
    let domain = access_sdk::resource::claims::digest_of_text(&var("ACCESS_DOMAIN")?)
        .ok_or("ACCESS_DOMAIN")?;
    let cose = std::fs::read(var("ACCESS_METADATA")?)?;
    let pinned = DomainMetadata::from_bytes(
        &parse_sign1(&cose)
            .map_err(|_| "ACCESS_METADATA")?
            .payload
            .ok_or("ACCESS_METADATA")?,
    )
    .map_err(|_| "ACCESS_METADATA")?;
    let tools_json = std::fs::read(var("MCP_TOOLS")?)?;
    let Json::Array(items) = json::parse(&tools_json, 1 << 20).map_err(|_| "MCP_TOOLS")? else {
        return Err(Failure::from("MCP_TOOLS is not an array"));
    };
    let mut table = Vec::new();
    let mut feed = None;
    for item in &items {
        let t = tool_of(item)?;
        if item.get("stream") == Some(&Json::Bool(true)) {
            feed = Some(t);
        } else {
            table.push(t);
        }
    }
    let scopes: Vec<String> = table
        .iter()
        .flat_map(|t| t.scopes.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let prm = ProtectedResource::new(
        &resource,
        vec![issuer.clone()],
        scopes,
        Binding::Dpop(vec![String::from("ES256"), String::from("EdDSA")]),
    )?;
    let rs = ResourceServer::new(Config {
        issuer,
        audience: resource.clone(),
        domain,
        metadata: pinned.clone(),
        profile: Profile::Fast,
        algorithms: BTreeSet::from([Algorithm::Ed25519, Algorithm::Es256]),
        key_epoch_ms: 3_600_000,
    })
    .map_err(|e| format!("{e}"))?;
    let mut key = [0u8; 32];
    Csprng.fill(&mut key).map_err(|_| "random")?;
    let origins = var("MCP_ORIGINS").unwrap_or_default();
    let host = resource
        .split_once("://")
        .and_then(|(_, r)| r.split('/').next())
        .ok_or("MCP_RESOURCE")?
        .to_owned();
    let path = access_sdk::mcp::client::canonical_resource(&resource)
        .ok()
        .and_then(|c| {
            c.split_once("://").map(|(_, r)| {
                r.find('/')
                    .map_or(String::from("/"), |i| r.get(i..).unwrap_or("/").to_owned())
            })
        })
        .ok_or("MCP_RESOURCE")?;
    Ok((
        bind,
        State {
            metadata: prm.json(),
            prm,
            origins: Origins {
                origins: origins
                    .split(',')
                    .filter(|o| !o.is_empty())
                    .map(str::to_owned)
                    .collect(),
                hosts: vec![host],
            },
            rs,
            pep: Pep {
                audience: var("MCP_PEP")?,
                domain,
                metadata: pinned,
            },
            tools: Tools::new(table).map_err(|e| format!("{e}"))?,
            feed,
            sealer: StateKey::new(Secret::new(key)),
            cache: ListCache::new(4096),
            replay: MemoryReplay::new(SystemClock, 100_000),
            upstream: Upstream {
                api,
                domain,
                tls: Arc::new(tls(
                    &var("ACCESS_CA")?,
                    &var("MCP_CERT")?,
                    &var("MCP_KEY")?,
                )?),
            },
            approval: var("ACCESS_APPROVAL")?,
            path,
        },
    ))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Failure> {
    let (bind, state) = state()?;
    let state = Arc::new(state);
    let metadata_path = state.prm.well_known_path();
    let mcp_path = state.path.clone();
    let app = axum::Router::new()
        .route(&metadata_path, axum::routing::any(endpoint))
        .route(&mcp_path, axum::routing::any(endpoint))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
