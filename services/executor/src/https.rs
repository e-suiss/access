//! The production ports: Access's public routes over HTTPS with this executor's client
//! certificate, as any third-party PEP reaches them (OP-62, CMP-16 pattern), and the upstreams
//! over HTTPS with the server's certificate checked. One request per connection; any failure is
//! [`Answer::Unanswered`], never a guess.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use access_kernel::json::b64url_encode;
use access_sdk::transport::{Answer, Fault, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::drivers::HttpRequest;
use crate::ports::{Access, Upstream};

/// Largest answer read.
pub const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// How long one request may take.
pub const TIMEOUT: Duration = Duration::from_secs(30);

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

/// The PEP name Access derives from a client certificate: the base64url SHA-256 of the leaf
/// (RFC 8705 `x5t#S256`).
#[must_use]
pub fn pep_name(leaf: &CertificateDer<'_>) -> String {
    b64url_encode(&suiss_crypto::digest::sha256(leaf.as_ref()))
}

fn header_safe(s: &str) -> bool {
    !s.contains(['\r', '\n'])
}

async fn exchange(connector: &TlsConnector, url: &str, req: &HttpRequest) -> Option<Response> {
    let at = Target::parse(url)?;
    if !header_safe(&req.method)
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

async fn timed(connector: &TlsConnector, url: &str, req: &HttpRequest) -> Answer {
    match tokio::time::timeout(TIMEOUT, exchange(connector, url, req)).await {
        Ok(Some(r)) => Answer::Response(r),
        Ok(None) => Answer::Unanswered(Fault::Unreachable),
        Err(_) => Answer::Unanswered(Fault::Timeout),
    }
}

/// Parses one HTTP/1.1 response read to the end of the connection.
#[must_use]
pub fn parse(buf: &[u8]) -> Option<Response> {
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
    let content_type = find("content-type").map(String::from);
    let chunked = find("transfer-encoding").is_some_and(|t| t.eq_ignore_ascii_case("chunked"));
    let rest = buf.get(head..)?;
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(len) = find("content-length") {
        rest.get(..len.trim().parse::<usize>().ok()?)?.to_vec()
    } else {
        rest.to_vec()
    };
    Some(Response {
        status,
        content_type,
        key_excerpt: None,
        body,
    })
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

fn config(
    roots: rustls::RootCertStore,
) -> Result<
    rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>,
    rustls::Error,
> {
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots))
}

/// Access over HTTPS with this executor's client certificate.
pub struct AccessHttps {
    connector: TlsConnector,
    origin: String,
}

impl AccessHttps {
    /// A client presenting `chain` and `key` to `origin` (`https://host[:port]`), trusting
    /// `roots`.
    ///
    /// # Errors
    /// The TLS configuration's error.
    pub fn new(
        roots: rustls::RootCertStore,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        origin: &str,
    ) -> Result<Self, rustls::Error> {
        let c = config(roots)?.with_client_auth_cert(chain, key)?;
        Ok(Self {
            connector: TlsConnector::from(Arc::new(c)),
            origin: origin.trim_end_matches('/').to_owned(),
        })
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Answer {
        let mut h = vec![(String::from("Accept"), String::from("application/json"))];
        if !body.is_empty() {
            h.push((
                String::from("Content-Type"),
                String::from("application/json"),
            ));
        }
        h.extend(headers);
        let req = HttpRequest {
            method: String::from(method),
            url: format!("{}{path}", self.origin),
            headers: h,
            body,
        };
        timed(&self.connector, &req.url, &req).await
    }
}

fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Access for AccessHttps {
    async fn evaluate(&self, body: Vec<u8>) -> Answer {
        self.call("POST", "/access/v1/evaluation", Vec::new(), body)
            .await
    }

    async fn metadata(&self, domain: String) -> Answer {
        if !segment(&domain) {
            return Answer::Unanswered(Fault::Transport);
        }
        self.call(
            "GET",
            &format!("/.well-known/access-domain-metadata/sha-256:{domain}"),
            Vec::new(),
            Vec::new(),
        )
        .await
    }

    async fn release(&self, realm: String, body: Vec<u8>) -> Answer {
        if !segment(&realm) {
            return Answer::Unanswered(Fault::Transport);
        }
        self.call(
            "POST",
            &format!("/realms/{realm}/v1/vault/releases"),
            Vec::new(),
            body,
        )
        .await
    }

    async fn ingest(&self, key: String, body: Vec<u8>) -> Answer {
        if !segment(&key) {
            return Answer::Unanswered(Fault::Transport);
        }
        self.call(
            "POST",
            "/access/v1/claims:ingest",
            vec![(String::from("Idempotency-Key"), key)],
            body,
        )
        .await
    }
}

/// The upstreams over HTTPS, server certificates checked against `roots`; no client
/// certificate, no proxy.
pub struct UpstreamHttps {
    connector: TlsConnector,
}

impl UpstreamHttps {
    /// A client trusting `roots`.
    ///
    /// # Errors
    /// The TLS configuration's error.
    pub fn new(roots: rustls::RootCertStore) -> Result<Self, rustls::Error> {
        let c = config(roots)?.with_no_client_auth();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(c)),
        })
    }
}

impl Upstream for UpstreamHttps {
    async fn send(&self, request: HttpRequest) -> Answer {
        timed(&self.connector, &request.url.clone(), &request).await
    }
}
