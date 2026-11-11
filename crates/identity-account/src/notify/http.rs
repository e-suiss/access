//! HTTP adapter of [`RelayPort`] (E42, OP-146 m.4 (b)): one HTTPS `POST` per event, `CloudEvents`
//! structured mode, `Idempotency-Key` = event id (OP-63), over a pool of kept-alive
//! connections, so an event does not open a connection of its own (OP-158 m.3 (y), OP-72). The bearer credential is read from a
//! secret file and re-read when it rotates (CR-35, OP-129 m.3); client certificates for mTLS
//! come with the operator's [`rustls::ClientConfig`] (OP-136). Only `https` is accepted.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_crypto::Secret;
use access_crypto::secret_file::{SecretFile, SecretFileError};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::notify::delivery::{CloudEvent, SendFailure, classify};
use crate::notify::ports::RelayPort;

/// Largest response head read.
const MAX_HEAD: usize = 16 * 1024;

/// Largest response body read before a connection goes back to the pool.
const MAX_BODY: usize = 64 * 1024;

/// Idle connections kept per adapter (OP-158 m.3 (y); PD).
pub const POOL_MAX: usize = 8;

type Connection = Box<tokio_rustls::client::TlsStream<TcpStream>>;

/// A Relay intake URL that is not `https://host[:port]/path`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("relay endpoint must be https://host[:port]/path")]
pub struct BadEndpoint;

/// Where Relay takes events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayEndpoint {
    host: String,
    port: u16,
    path: String,
}

fn token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~/%:@!$&'()*+,;=".contains(c)
}

impl RelayEndpoint {
    /// `https://host[:port]` followed by `path`, as Access writes the Relay issuer.
    #[must_use]
    pub fn url(&self) -> String {
        if self.port == 443 {
            format!("https://{}{}", self.host, self.path)
        } else {
            format!("https://{}:{}{}", self.host, self.port, self.path)
        }
    }

    /// Parses `https://host[:port]/path`.
    ///
    /// # Errors
    /// [`BadEndpoint`].
    pub fn parse(url: &str) -> Result<Self, BadEndpoint> {
        let rest = url.strip_prefix("https://").ok_or(BadEndpoint)?;
        let (authority, path) = rest.find('/').map_or((rest, "/"), |i| {
            (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("/"))
        });
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| BadEndpoint)?),
            None => (authority, 443),
        };
        let host_ok = !host.is_empty()
            && host.len() <= 253
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
        if !host_ok || port == 0 || !path.chars().all(token_char) {
            return Err(BadEndpoint);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        })
    }
}

/// How the adapter is set up.
pub struct HttpRelayConfig {
    /// Relay's event intake.
    pub endpoint: RelayEndpoint,
    /// TLS client settings: the trust anchors for Relay and, for mTLS, the client certificate.
    pub tls: Arc<rustls::ClientConfig>,
    /// File holding the bearer credential Relay accepts from Access.
    pub token_file: PathBuf,
    /// Bound on one exchange.
    pub timeout: Duration,
}

/// Posts events to Relay over HTTPS.
pub struct HttpRelay {
    endpoint: RelayEndpoint,
    connector: TlsConnector,
    token: Mutex<SecretFile>,
    timeout: Duration,
    idle: Mutex<Vec<Connection>>,
    opened: std::sync::atomic::AtomicU64,
}

/// How one exchange on a connection ended.
enum Exchanged {
    /// An answer; the connection may carry the next event.
    Answer(Result<(), SendFailure>, Option<Connection>),
    /// The connection failed before any answer byte: a kept-alive connection the peer closed.
    Stale,
}

impl HttpRelay {
    /// Reads the credential file and builds the client.
    ///
    /// # Errors
    /// [`SecretFileError`] when the credential file is missing or readable by others.
    pub fn new(config: HttpRelayConfig) -> Result<Self, SecretFileError> {
        Ok(Self {
            token: Mutex::new(SecretFile::load(config.token_file)?),
            connector: TlsConnector::from(config.tls),
            endpoint: config.endpoint,
            timeout: config.timeout,
            idle: Mutex::new(Vec::new()),
            opened: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Connections opened so far.
    #[must_use]
    pub fn connections_opened(&self) -> u64 {
        self.opened.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn pooled(&self) -> Option<Connection> {
        self.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
    }

    fn keep(&self, connection: Connection) {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if idle.len() < POOL_MAX {
            idle.push(connection);
        }
    }

    async fn connect(&self) -> Option<Connection> {
        let name = ServerName::try_from(self.endpoint.host.clone()).ok()?;
        let tcp = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .ok()?;
        let tls = self.connector.connect(name, tcp).await.ok()?;
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(Box::new(tls))
    }

    fn token(&self) -> Secret<String> {
        let mut f = self
            .token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = f.reload_if_changed() {
            tracing::warn!(error = %e, "relay credential reload failed; the previous one stays");
        }
        f.value().clone()
    }

    fn request(&self, event: &CloudEvent) -> Option<Zeroizing<Vec<u8>>> {
        let token = self.token();
        if token.expose().bytes().any(|b| !b.is_ascii_graphic()) {
            tracing::warn!("relay credential holds characters a header cannot carry");
            return None;
        }
        let body = event.body();
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/cloudevents+json; charset=utf-8\r\n\
             Content-Length: {}\r\nIdempotency-Key: {}\r\nConnection: keep-alive\r\nAuthorization: Bearer ",
            self.endpoint.path,
            self.endpoint.host,
            self.endpoint.port,
            body.len(),
            event.id,
        );
        let mut out = Zeroizing::new(Vec::with_capacity(
            head.len()
                .saturating_add(token.expose().len())
                .saturating_add(body.len())
                .saturating_add(4),
        ));
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(token.expose().as_bytes());
        out.extend_from_slice(b"\r\n\r\n");
        out.extend_from_slice(body);
        Some(out)
    }

    async fn exchange(&self, event: &CloudEvent) -> Result<(), SendFailure> {
        let transient = SendFailure::Transient {
            retry_after_ms: None,
        };
        let request = self.request(event).ok_or(transient)?;
        if let Some(pooled) = self.pooled() {
            match Self::on(pooled, &request).await {
                Exchanged::Answer(result, back) => {
                    if let Some(c) = back {
                        self.keep(c);
                    }
                    return result;
                }
                Exchanged::Stale => {}
            }
        }
        let fresh = self.connect().await.ok_or(transient)?;
        match Self::on(fresh, &request).await {
            Exchanged::Answer(result, back) => {
                if let Some(c) = back {
                    self.keep(c);
                }
                result
            }
            Exchanged::Stale => Err(transient),
        }
    }

    /// One request and its answer on `tls`; the connection comes back when the answer was
    /// read to its end and the peer keeps it open.
    async fn on(mut tls: Connection, request: &[u8]) -> Exchanged {
        let transient = SendFailure::Transient {
            retry_after_ms: None,
        };
        if tls.write_all(request).await.is_err() || tls.flush().await.is_err() {
            return Exchanged::Stale;
        }
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0_u8; 1024];
        loop {
            let n = match tls.read(&mut chunk).await {
                Ok(0) | Err(_) if buf.is_empty() => return Exchanged::Stale,
                Ok(0) | Err(_) => return Exchanged::Answer(Err(transient), None),
                Ok(n) => n,
            };
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&buf) {
                Ok(httparse::Status::Complete(head)) => {
                    let Some(status) = resp.code else {
                        return Exchanged::Answer(Err(transient), None);
                    };
                    let header = |name: &str| {
                        resp.headers
                            .iter()
                            .find(|h| h.name.eq_ignore_ascii_case(name))
                            .and_then(|h| core::str::from_utf8(h.value).ok())
                            .map(str::trim)
                    };
                    let retry_after_ms = header("retry-after")
                        .and_then(|v| v.parse::<u64>().ok())
                        .and_then(|s| s.checked_mul(1000));
                    let closes =
                        header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
                    let length = header("content-length").and_then(|v| v.parse::<usize>().ok());
                    let result = classify(status, retry_after_ms);
                    let back = match length {
                        Some(len) if !closes && len <= MAX_BODY => {
                            Self::drain(&mut tls, buf.len().saturating_sub(head), len)
                                .await
                                .then_some(tls)
                        }
                        _ => None,
                    };
                    return Exchanged::Answer(result, back);
                }
                Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => {}
                _ => return Exchanged::Answer(Err(transient), None),
            }
        }
    }

    /// Reads the rest of a body of `len` bytes, `have` of which came with the head.
    async fn drain(tls: &mut Connection, have: usize, len: usize) -> bool {
        let mut left = len.saturating_sub(have);
        if have > len {
            return false;
        }
        let mut chunk = [0_u8; 1024];
        while left > 0 {
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => left = left.saturating_sub(n),
            }
        }
        true
    }
}

impl RelayPort for HttpRelay {
    async fn send(&self, event: &CloudEvent) -> Result<(), SendFailure> {
        match tokio::time::timeout(self.timeout, self.exchange(event)).await {
            Ok(r) => r,
            Err(_) => Err(SendFailure::Transient {
                retry_after_ms: None,
            }),
        }
    }
}

/// Largest discovery document read.
const MAX_DISCOVERY: usize = 64 * 1024;

/// Why the discovery document could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("relay discovery unavailable")]
pub struct DiscoveryUnavailable;

/// Reads Relay's discovery document `GET <issuer>/.well-known/relay-configuration` (Relay E-81)
/// over `tls`, within `timeout`.
///
/// # Errors
/// [`DiscoveryUnavailable`] when Relay cannot be reached, answers other than `200` or the body
/// is not JSON.
pub async fn discover(
    relay: &str,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<serde_json::Value, DiscoveryUnavailable> {
    let at = RelayEndpoint::parse(&format!(
        "{relay}{}",
        crate::notify::delivery::DISCOVERY_PATH
    ))
    .map_err(|_| DiscoveryUnavailable)?;
    tokio::time::timeout(timeout, fetch(&at, tls))
        .await
        .map_err(|_| DiscoveryUnavailable)?
}

async fn fetch(
    at: &RelayEndpoint,
    tls: Arc<rustls::ClientConfig>,
) -> Result<serde_json::Value, DiscoveryUnavailable> {
    let e = |_| DiscoveryUnavailable;
    let name = ServerName::try_from(at.host.clone()).map_err(|_| DiscoveryUnavailable)?;
    let tcp = TcpStream::connect((at.host.as_str(), at.port))
        .await
        .map_err(e)?;
    let mut s = TlsConnector::from(tls)
        .connect(name, tcp)
        .await
        .map_err(e)?;
    let head = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        at.path, at.host, at.port
    );
    s.write_all(head.as_bytes()).await.map_err(e)?;
    s.flush().await.map_err(e)?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        let n = s.read(&mut chunk).await.map_err(e)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        if buf.len() > MAX_DISCOVERY {
            return Err(DiscoveryUnavailable);
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(body_at) = resp.parse(&buf).map_err(|_| DiscoveryUnavailable)?
    else {
        return Err(DiscoveryUnavailable);
    };
    if resp.code != Some(200) {
        return Err(DiscoveryUnavailable);
    }
    let body = buf.get(body_at..).ok_or(DiscoveryUnavailable)?;
    serde_json::from_slice(body).map_err(|_| DiscoveryUnavailable)
}
