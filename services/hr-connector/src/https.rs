//! The production ports over HTTPS (OP-62): Access's realm-admin surface as any administrator's
//! tool reaches it, and the HR system's employee listing. One request per connection; a read
//! token, a credential or a key comes from a file the operator provides, read at each call, never
//! from the command line. Any failure is a [`Fault`], never a guess.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use access_sdk::auth::dpop::{ProofFor, proof};
use rustls::pki_types::ServerName;
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::key::InstanceKey;
use crate::ports::{Access, Clock, Fault, Pull};

/// Largest answer read.
pub const MAX_ANSWER: usize = 32 * 1024 * 1024;

/// How long one request may take.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// An `https` origin and path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Path and query.
    pub path: String,
}

impl Target {
    /// Parses `https://host[:port][/path]`.
    #[must_use]
    pub fn parse(url: &str) -> Option<Self> {
        let rest = url.strip_prefix("https://")?;
        let (authority, path) = rest.find('/').map_or((rest, "/"), |i| {
            (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("/"))
        });
        if authority.is_empty() || authority.contains('@') || path.contains(['\r', '\n', ' ']) {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => (h, p.parse().ok()?),
            Some(_) => return None,
            None => (authority, 443),
        };
        Some(Self {
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        })
    }
}

fn header_safe(s: &str) -> bool {
    !s.contains(['\r', '\n'])
}

struct Request<'a> {
    method: &'a str,
    url: &'a str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn exchange(connector: &TlsConnector, req: &Request<'_>) -> Option<(u16, Vec<u8>)> {
    let at = Target::parse(req.url)?;
    if !header_safe(req.method)
        || req
            .headers
            .iter()
            .any(|(k, v)| !header_safe(k) || !header_safe(v))
    {
        return None;
    }
    let name = ServerName::try_from(at.host.clone()).ok()?;
    let tcp = TcpStream::connect((at.host.as_str(), at.port)).await.ok()?;
    let mut tls = connector.connect(name, tcp).await.ok()?;
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\n",
        req.method, at.path, at.host, at.port
    );
    for (k, v) in &req.headers {
        let _ = write!(head, "{k}: {v}\r\n");
    }
    let _ = write!(
        head,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        req.body.len()
    );
    tls.write_all(head.as_bytes()).await.ok()?;
    tls.write_all(&req.body).await.ok()?;
    tls.flush().await.ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = tls.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(chunk.get(..n)?);
        if buf.len() > MAX_ANSWER {
            return None;
        }
    }
    parse(&buf)
}

/// Parses one HTTP/1.1 response read to the end of the connection: its status and body.
#[must_use]
pub fn parse(buf: &[u8]) -> Option<(u16, Vec<u8>)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(head) = parsed.parse(buf).ok()? else {
        return None;
    };
    let status = parsed.code?;
    let find = |name: &str| {
        parsed
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
    };
    let chunked = find("transfer-encoding").is_some_and(|t| t.eq_ignore_ascii_case("chunked"));
    let rest = buf.get(head..)?;
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(len) = find("content-length") {
        rest.get(..len.trim().parse::<usize>().ok()?)?.to_vec()
    } else {
        rest.to_vec()
    };
    Some((status, body))
}

fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(rest.get(..line)?).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        rest = rest.get(line.checked_add(2)?..)?;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size.checked_add(2)?..)?;
    }
}

async fn send(connector: &TlsConnector, req: &Request<'_>) -> Result<(u16, Value), Fault> {
    let Ok(answer) = tokio::time::timeout(TIMEOUT, exchange(connector, req)).await else {
        return Err(Fault::Unreachable);
    };
    let (status, body) = answer.ok_or(Fault::Unreachable)?;
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).map_err(|_| Fault::Malformed)?
    };
    Ok((status, json))
}

/// A TLS client trusting `roots`, without a client certificate.
///
/// # Errors
/// The TLS configuration's error.
pub fn client(roots: rustls::RootCertStore) -> Result<TlsConnector, rustls::Error> {
    let c = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(c)))
}

fn read_secret(path: &PathBuf) -> Result<String, Fault> {
    let text = std::fs::read_to_string(path).map_err(|_| Fault::Credential)?;
    let text = text.trim();
    if text.is_empty() || !header_safe(text) {
        return Err(Fault::Credential);
    }
    Ok(text.to_owned())
}

struct Rng(Arc<rustls::crypto::CryptoProvider>);

impl access_sdk::auth::Random for Rng {
    fn fill(&self, out: &mut [u8]) -> Result<(), access_sdk::auth::RandomUnavailable> {
        self.0
            .secure_random
            .fill(out)
            .map_err(|_| access_sdk::auth::RandomUnavailable)
    }
}

/// Access's realm-admin surface over HTTPS: a draft carries the operator's DPoP-bound read token
/// with a proof of the Instance key; a commit carries the AIS only (OP-151 m.3 (c)).
pub struct AccessHttps<C> {
    connector: TlsConnector,
    origin: String,
    token: PathBuf,
    key: Arc<InstanceKey<C>>,
    rng: Rng,
}

impl<C: Clock> AccessHttps<C> {
    /// Access at `origin` (`https://host[:port]`) with the read token in file `token`.
    #[must_use]
    pub fn new(
        connector: TlsConnector,
        origin: &str,
        token: PathBuf,
        key: Arc<InstanceKey<C>>,
    ) -> Self {
        Self {
            connector,
            origin: origin.trim_end_matches('/').to_owned(),
            token,
            key,
            rng: Rng(Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
        }
    }
}

fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl<C: Clock> Access for AccessHttps<C> {
    async fn draft(&self, slug: &str, ask: Value) -> Result<Value, Fault> {
        if !segment(slug) {
            return Err(Fault::Malformed);
        }
        let path = format!("/admin/v1/realms/{slug}/intents");
        let url = format!("{}{path}", self.origin);
        let token = read_secret(&self.token)?;
        let now = self.key.clock.now().ok_or(Fault::Credential)?;
        let dpop = proof(
            &*self.key,
            &ProofFor {
                method: "POST",
                uri: &url,
                access_token: Some(&token),
                nonce: None,
            },
            now,
            &self.rng,
        )
        .map_err(|_| Fault::Credential)?;
        let req = Request {
            method: "POST",
            url: &url,
            headers: vec![
                (String::from("Accept"), String::from("application/json")),
                (
                    String::from("Content-Type"),
                    String::from("application/json"),
                ),
                (String::from("Authorization"), format!("DPoP {token}")),
                (String::from("DPoP"), dpop),
            ],
            body: ask.to_string().into_bytes(),
        };
        match send(&self.connector, &req).await? {
            (200, v) => Ok(v),
            (s, v) => Err(Fault::Refused(
                s,
                String::from(v.get("code").and_then(Value::as_str).unwrap_or("")),
            )),
        }
    }

    async fn commit(
        &self,
        path: &str,
        body: Value,
        (ais, key): (&str, &str),
    ) -> Result<(u16, Value), Fault> {
        if !path.starts_with('/') || path.contains("..") || !header_safe(ais) || !header_safe(key) {
            return Err(Fault::Malformed);
        }
        let url = format!("{}{path}", self.origin);
        let req = Request {
            method: "POST",
            url: &url,
            headers: vec![
                (String::from("Accept"), String::from("application/json")),
                (
                    String::from("Content-Type"),
                    String::from("application/json"),
                ),
                (String::from("X-Access-AIS"), String::from(ais)),
                (String::from("Idempotency-Key"), String::from(key)),
            ],
            body: body.to_string().into_bytes(),
        };
        send(&self.connector, &req).await
    }
}

/// The HR system's employee listing over HTTPS: one request with the operator's credential
/// (`Authorization` header value) from a file, and a JSON body for vendors that search by POST.
pub struct VendorHttps {
    /// The TLS client.
    pub connector: TlsConnector,
    /// The listing's URL.
    pub url: String,
    /// `GET` or `POST`.
    pub method: &'static str,
    /// The JSON body of a `POST` listing.
    pub body: Option<Value>,
    /// The file holding the `Authorization` header value.
    pub credential: PathBuf,
}

impl Pull for VendorHttps {
    async fn pages(&self) -> Result<Vec<Value>, Fault> {
        let credential = read_secret(&self.credential)?;
        let mut headers = vec![
            (String::from("Accept"), String::from("application/json")),
            (String::from("Authorization"), credential),
        ];
        let body = match &self.body {
            Some(b) => {
                headers.push((
                    String::from("Content-Type"),
                    String::from("application/json"),
                ));
                b.to_string().into_bytes()
            }
            None => Vec::new(),
        };
        let req = Request {
            method: self.method,
            url: &self.url,
            headers,
            body,
        };
        match send(&self.connector, &req).await? {
            (200, v) => Ok(vec![v]),
            (s, _) => Err(Fault::Refused(s, String::from("vendor"))),
        }
    }
}
