//! HTTP adapter of [`RelayPort`] (E42, OP-146 m.4 (b)): one HTTPS `POST` per event, `CloudEvents`
//! structured mode, `Idempotency-Key` = event id (OP-63). The bearer credential is read from a
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
        })
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
             Content-Length: {}\r\nIdempotency-Key: {}\r\nConnection: close\r\nAuthorization: Bearer ",
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
        let name = ServerName::try_from(self.endpoint.host.clone()).map_err(|_| transient)?;
        let tcp = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .map_err(|_| transient)?;
        let mut tls = self
            .connector
            .connect(name, tcp)
            .await
            .map_err(|_| transient)?;
        tls.write_all(&request).await.map_err(|_| transient)?;
        tls.flush().await.map_err(|_| transient)?;
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0_u8; 1024];
        loop {
            let n = tls.read(&mut chunk).await.map_err(|_| transient)?;
            if n == 0 {
                return Err(transient);
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&buf) {
                Ok(httparse::Status::Complete(_)) => {
                    let status = resp.code.ok_or(transient)?;
                    let retry_after_ms = resp
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("retry-after"))
                        .and_then(|h| core::str::from_utf8(h.value).ok())
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .and_then(|s| s.checked_mul(1000));
                    return classify(status, retry_after_ms);
                }
                Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => {}
                _ => return Err(transient),
            }
        }
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
