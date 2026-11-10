//! The Relay twin (OP-146 m.4 (b), OP-156 m.3 (c)): a real HTTPS listener with Relay's
//! discovery document, its event intake and its Access event receiver, for every lane's tests.
//!
//! - `GET /.well-known/relay-configuration` answers the discovery document (Relay E-81).
//! - `POST /v1/events` takes a `CloudEvent` in structured mode. It checks the bearer credential
//!   and the `Idempotency-Key`, validates the event against `relay-message.v1.schema.json`,
//!   deduplicates by id (`409`) and answers from a script: accept (`202`), a status with an
//!   optional `Retry-After`, or a delay before accepting.
//! - `POST /v1/access/events` takes SSF push SETs (RFC 8935, Relay E-94) and the Suiss webhook
//!   profile (TN-136) as an ordinary receiver: it keeps what came and answers `202`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    reason = "test kit; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Relay's event intake path.
pub const EVENTS: &str = "/v1/events";
/// Relay's receiver of Access events (SSF push, webhooks).
pub const ACCESS_EVENTS: &str = "/v1/access/events";
/// The discovery document's path.
pub const DISCOVERY: &str = "/.well-known/relay-configuration";
/// The events capability URN.
pub const EVENTS_CAPABILITY: &str = "urn:suiss:relay:events:1";

/// How the twin answers the next event post.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// `202 Accepted`.
    Accept,
    /// This status, with `Retry-After` seconds when given.
    Status(u16, Option<u64>),
    /// Waits, then accepts.
    Delay(Duration),
}

/// One event post as the twin saw it.
#[derive(Clone, Debug)]
pub struct Post {
    /// The `CloudEvents` id.
    pub id: String,
    /// `Idempotency-Key`.
    pub idempotency_key: Option<String>,
    /// `Authorization`.
    pub authorization: Option<String>,
    /// The event.
    pub event: Value,
    /// What the schema found wrong; empty when it is valid.
    pub schema_errors: Vec<String>,
    /// The status the twin answered.
    pub status: u16,
}

/// One post to the Access event receiver.
#[derive(Clone, Debug)]
pub struct Received {
    /// `Content-Type`.
    pub content_type: String,
    /// Every header, lower-cased names.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

#[derive(Default)]
struct State {
    script: VecDeque<Answer>,
    posts: Vec<Post>,
    accepted: BTreeSet<String>,
    received: Vec<Received>,
    discovery: Option<Value>,
    discoveries: usize,
}

/// A running Relay twin.
#[derive(Clone)]
pub struct RelayTwin {
    /// `https://localhost:<port>`, the Relay issuer.
    pub base: String,
    /// A client configuration that trusts the twin.
    pub tls: Arc<rustls::ClientConfig>,
    /// The twin's certificate, PEM, for a `ca_file`.
    pub ca_pem: String,
    token: String,
    access_issuer: String,
    state: Arc<Mutex<State>>,
}

/// What a schema check of `v` against `schema` finds, starting at `root`.
#[must_use]
pub fn check(schema: &Value, root: &Value, v: &Value, path: &str) -> Vec<String> {
    let mut errs = Vec::new();
    if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
        let Some(name) = r.strip_prefix("#/$defs/") else {
            return vec![format!("{path}: unsupported $ref {r}")];
        };
        return check(&root["$defs"][name], root, v, path);
    }
    if let Some(c) = schema.get("const")
        && v != c
    {
        errs.push(format!("{path}: {v} != {c}"));
    }
    if let Some(Value::Array(e)) = schema.get("enum")
        && !e.contains(v)
    {
        errs.push(format!("{path}: {v} not in enum"));
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("string") if !v.is_string() => errs.push(format!("{path}: not a string")),
        Some("object") if !v.is_object() => errs.push(format!("{path}: not an object")),
        _ => {}
    }
    if let (Some(Value::Object(o)), Some(Value::Array(req))) = (Some(v), schema.get("required")) {
        for r in req {
            if !o.contains_key(r.as_str().unwrap_or_default()) {
                errs.push(format!("{path}: missing {r}"));
            }
        }
    }
    if let (Value::Object(o), Some(Value::Object(props))) = (v, schema.get("properties")) {
        for (k, val) in o {
            match props.get(k) {
                Some(p) => errs.extend(check(p, root, val, &format!("{path}.{k}"))),
                None if schema.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    errs.push(format!("{path}: unexpected {k}"));
                }
                None => {}
            }
        }
    }
    if let Some(Value::Array(all)) = schema.get("allOf") {
        for a in all {
            if check(&a["if"], root, v, path).is_empty() {
                errs.extend(check(&a["then"], root, v, path));
            }
        }
    }
    errs
}

/// The Relay message contract.
#[must_use]
pub fn schema() -> Value {
    serde_json::from_str(include_str!("../../contracts/relay-message.v1.schema.json"))
        .expect("the committed schema parses")
}

/// What the Relay message contract finds wrong with `event`.
#[must_use]
pub fn schema_errors(event: &Value) -> Vec<String> {
    let s = schema();
    check(&s, &s, event, "$")
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(at) = req.parse(&buf).ok()? {
            let headers: Vec<(String, String)> = req
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_ascii_lowercase(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect();
            let len: usize = headers
                .iter()
                .find(|(n, _)| n == "content-length")
                .and_then(|(_, v)| v.trim().parse().ok())
                .unwrap_or(0);
            let method = req.method?.to_owned();
            let path = req.path?.to_owned();
            while buf.len() < at + len {
                let n = s.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            return Some(Request {
                method,
                path,
                headers,
                body: buf[at..at + len].to_vec(),
            });
        }
        if buf.len() > 1 << 20 {
            return None;
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn response(status: u16, extra: &str, body: &[u8], content_type: &str) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\n{extra}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

impl RelayTwin {
    /// Starts a twin on a local port that accepts `token` as the bearer credential and names
    /// `access_issuer` as the Access it belongs to.
    pub async fn start(token: &str, access_issuer: &str) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let der: CertificateDer<'static> = cert.cert.der().clone();
        let ca_pem = cert.cert.pem();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let twin = Self {
            base: format!("https://localhost:{port}"),
            tls: Arc::new(tls),
            ca_pem,
            token: token.to_owned(),
            access_issuer: access_issuer.to_owned(),
            state: Arc::default(),
        };
        let serving = twin.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let twin = serving.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Some(req) = read_request(&mut s).await else {
                        return;
                    };
                    let out = twin.answer(&req).await;
                    let _ = s.write_all(&out).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        twin
    }

    /// The intake URL.
    #[must_use]
    pub fn events_url(&self) -> String {
        format!("{}{EVENTS}", self.base)
    }

    /// The Access event receiver URL.
    #[must_use]
    pub fn access_events_url(&self) -> String {
        format!("{}{ACCESS_EVENTS}", self.base)
    }

    /// The discovery document the twin serves.
    #[must_use]
    pub fn discovery(&self) -> Value {
        if let Some(d) = self.state.lock().unwrap().discovery.clone() {
            return d;
        }
        json!({
            "issuer": self.base,
            "api_base": format!("{}/v1", self.base),
            "region": "local",
            "access_issuer": self.access_issuer,
            "contract_version": "2026-11-01",
            "contract_versions_supported": ["2026-11-01"],
            "jwks_uri": format!("{}/.well-known/relay-jwks.json", self.base),
            "capabilities": [EVENTS_CAPABILITY],
            "events_endpoint": self.events_url(),
        })
    }

    /// Serves `doc` as the discovery document from now on.
    pub fn set_discovery(&self, doc: Value) {
        self.state.lock().unwrap().discovery = Some(doc);
    }

    /// Answers the next event posts in this order, then accepts.
    pub fn script(&self, answers: impl IntoIterator<Item = Answer>) {
        self.state.lock().unwrap().script.extend(answers);
    }

    /// Every event post so far.
    #[must_use]
    pub fn posts(&self) -> Vec<Post> {
        self.state.lock().unwrap().posts.clone()
    }

    /// The ids Relay took, once each.
    #[must_use]
    pub fn accepted(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .accepted
            .iter()
            .cloned()
            .collect()
    }

    /// How often the discovery document was read.
    #[must_use]
    pub fn discoveries(&self) -> usize {
        self.state.lock().unwrap().discoveries
    }

    /// Every post to the Access event receiver so far.
    #[must_use]
    pub fn received(&self) -> Vec<Received> {
        self.state.lock().unwrap().received.clone()
    }

    async fn answer(&self, req: &Request) -> Vec<u8> {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", DISCOVERY) => {
                self.state.lock().unwrap().discoveries += 1;
                let body = serde_json::to_vec(&self.discovery()).unwrap();
                response(
                    200,
                    "Cache-Control: public, max-age=300\r\n",
                    &body,
                    "application/json",
                )
            }
            ("POST", EVENTS) => self.event(req).await,
            ("POST", ACCESS_EVENTS) => {
                self.state.lock().unwrap().received.push(Received {
                    content_type: req.header("content-type").unwrap_or_default(),
                    headers: req.headers.clone(),
                    body: req.body.clone(),
                });
                response(202, "", b"", "text/plain")
            }
            _ => response(404, "", b"", "text/plain"),
        }
    }

    async fn event(&self, req: &Request) -> Vec<u8> {
        let authorization = req.header("authorization");
        let idempotency_key = req.header("idempotency-key");
        let content_type = req.header("content-type").unwrap_or_default();
        let event: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let id = event["id"].as_str().unwrap_or_default().to_owned();
        let mut schema_errors = schema_errors(&event);
        if idempotency_key.as_deref() != Some(id.as_str()) {
            schema_errors.push(String::from("Idempotency-Key is not the event id"));
        }
        let (status, extra) = if authorization.as_deref() != Some(&format!("Bearer {}", self.token))
        {
            (401, String::new())
        } else if !content_type.starts_with("application/cloudevents+json") {
            (415, String::new())
        } else if !schema_errors.is_empty() {
            (422, String::new())
        } else {
            let next = self.state.lock().unwrap().script.pop_front();
            match next.unwrap_or(Answer::Accept) {
                Answer::Accept => (202, String::new()),
                Answer::Delay(d) => {
                    tokio::time::sleep(d).await;
                    (202, String::new())
                }
                Answer::Status(s, retry) => (
                    s,
                    retry.map_or_else(String::new, |r| format!("Retry-After: {r}\r\n")),
                ),
            }
        };
        let status = {
            let mut st = self.state.lock().unwrap();
            let status = if status == 202 && !st.accepted.insert(id.clone()) {
                409
            } else {
                status
            };
            st.posts.push(Post {
                id,
                idempotency_key,
                authorization,
                event,
                schema_errors,
                status,
            });
            status
        };
        response(status, &extra, b"", "text/plain")
    }
}
