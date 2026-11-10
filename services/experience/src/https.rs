//! The production [`Upstream`]: Access's public search route over HTTPS with this service's
//! client certificate, as any third-party PEP calls it (OP-141 m.18 (b), XI-18). Access names
//! the PEP by the certificate's `x5t#S256`, which [`pep_name`] computes the same way. One
//! request per connection; a failure of any kind is [`Answer::Unanswered`], never a guess.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use access_kernel::json::b64url_encode;
use access_sdk::transport::{Answer, Fault, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::contract::Kind;
use crate::ports::Upstream;

/// Largest answer read.
pub const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// How long one search may take, the search deadline of Access included.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// An Access endpoint: host, port and the TLS name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
}

impl Endpoint {
    /// Parses `https://host[:port]`.
    #[must_use]
    pub fn parse(url: &str) -> Option<Self> {
        let rest = url.strip_prefix("https://")?.trim_end_matches('/');
        if rest.contains('/') || rest.contains('@') || rest.is_empty() {
            return None;
        }
        match rest.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => Some(Self {
                host: h.to_owned(),
                port: p.parse().ok()?,
            }),
            Some(_) => None,
            None => Some(Self {
                host: rest.to_owned(),
                port: 443,
            }),
        }
    }
}

/// The PEP name Access derives from a client certificate: the base64url SHA-256 of the leaf
/// (RFC 8705 `x5t#S256`).
#[must_use]
pub fn pep_name(leaf: &CertificateDer<'_>) -> String {
    b64url_encode(&suiss_crypto::digest::sha256(leaf.as_ref()))
}

/// Access over HTTPS: a default endpoint and the endpoints of other domains.
pub struct Https {
    connector: TlsConnector,
    default: Endpoint,
    routes: BTreeMap<String, Endpoint>,
}

impl Https {
    /// A client presenting `chain` and `key`, trusting `roots`, sending every domain to
    /// `default` unless `routes` names its endpoint.
    ///
    /// # Errors
    /// The TLS configuration's error.
    pub fn new(
        roots: rustls::RootCertStore,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        default: Endpoint,
        routes: BTreeMap<String, Endpoint>,
    ) -> Result<Self, rustls::Error> {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            default,
            routes,
        })
    }

    async fn post(
        &self,
        at: &Endpoint,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Option<Response> {
        self.send(at, "POST", path, authorization, body).await
    }

    async fn send(
        &self,
        at: &Endpoint,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Option<Response> {
        let name = ServerName::try_from(at.host.clone()).ok()?;
        let tcp = TcpStream::connect((at.host.as_str(), at.port)).await.ok()?;
        let mut tls = self.connector.connect(name, tcp).await.ok()?;
        let credential = authorization
            .map(|a| format!("Authorization: {a}\r\n"))
            .unwrap_or_default();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\n\
             Accept: application/json\r\n{credential}Content-Length: {}\r\nConnection: close\r\n\r\n",
            at.host,
            at.port,
            body.len()
        );
        tls.write_all(head.as_bytes()).await.ok()?;
        tls.write_all(body).await.ok()?;
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

impl Upstream for Https {
    async fn search(&self, domain: &str, kind: Kind, body: Vec<u8>) -> Answer {
        let at = self.routes.get(domain).unwrap_or(&self.default);
        let path = format!("/access/v1/search/{}", kind.search());
        match tokio::time::timeout(TIMEOUT, self.post(at, &path, None, &body)).await {
            Ok(Some(r)) => Answer::Response(r),
            Ok(None) => Answer::Unanswered(Fault::Unreachable),
            Err(_) => Answer::Unanswered(Fault::Timeout),
        }
    }

    async fn discovery(&self, realm: &str) -> Answer {
        let path = format!("/.well-known/suiss-configuration/realms/{realm}");
        self.get(&self.default, &path).await
    }

    async fn relay_status(&self) -> Answer {
        self.get(&self.default, "/access/v1/relay-status").await
    }

    async fn attention(&self, url: &str, party: &str) -> Answer {
        let Some(rest) = url.strip_prefix("https://") else {
            return Answer::Unanswered(Fault::Unreachable);
        };
        let at = rest.find('/').unwrap_or(rest.len());
        let (origin, path) = rest.split_at(at);
        let Some(endpoint) = Endpoint::parse(&format!("https://{origin}")) else {
            return Answer::Unanswered(Fault::Unreachable);
        };
        if !party
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || path.contains(['?', '#', ' '])
        {
            return Answer::Unanswered(Fault::Unreachable);
        }
        let path = if path.is_empty() { "/" } else { path };
        self.get(&endpoint, &format!("{path}?party={party}")).await
    }
}

impl Https {
    async fn get(&self, at: &Endpoint, path: &str) -> Answer {
        match tokio::time::timeout(TIMEOUT, self.send(at, "GET", path, None, &[])).await {
            Ok(Some(r)) => Answer::Response(r),
            Ok(None) => Answer::Unanswered(Fault::Unreachable),
            Err(_) => Answer::Unanswered(Fault::Timeout),
        }
    }
}

/// Where to poll and with what: `https://host[:port]/path` and a bearer credential that is one
/// header-safe token; `None` otherwise.
#[must_use]
pub fn poll_target(url: &str, bearer: &str) -> Option<(Endpoint, String, String)> {
    let rest = url.strip_prefix("https://")?;
    let at = rest.find('/')?;
    let (origin, path) = rest.split_at(at);
    let endpoint = Endpoint::parse(&format!("https://{origin}"))?;
    let bearer = bearer.trim();
    if bearer.is_empty() || !bearer.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    Some((endpoint, path.to_owned(), format!("Bearer {bearer}")))
}

/// Access's SSF poll route for this service's stream (RFC 8936), with the stream's bearer
/// credential (OP-153 m.8 (d)).
pub struct SsfPoll {
    https: Https,
    path: String,
    authorization: Credential,
}

/// The `Authorization` value of the stream; never printed (OP-64).
struct Credential(String);

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(redacted)")
    }
}

impl SsfPoll {
    /// Polls `url` through `https` with `bearer` (see [`poll_target`]).
    #[must_use]
    pub fn new(https: Https, url: &str, bearer: &str) -> Option<Self> {
        let (default, path, authorization) = poll_target(url, bearer)?;
        Some(Self {
            https: Https { default, ..https },
            path,
            authorization: Credential(authorization),
        })
    }
}

impl crate::feed::Poll for SsfPoll {
    async fn poll(&self, body: Vec<u8>) -> Answer {
        let call = self.https.post(
            &self.https.default,
            &self.path,
            Some(self.authorization.0.as_str()),
            &body,
        );
        match tokio::time::timeout(TIMEOUT, call).await {
            Ok(Some(r)) => Answer::Response(r),
            Ok(None) => Answer::Unanswered(Fault::Unreachable),
            Err(_) => Answer::Unanswered(Fault::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-141 m.18 (b)
    #[test]
    fn endpoints_are_https_origins_only() {
        assert_eq!(
            Endpoint::parse("https://access.test:9443"),
            Some(Endpoint {
                host: "access.test".to_owned(),
                port: 9443
            })
        );
        assert_eq!(Endpoint::parse("https://access.test").unwrap().port, 443);
        assert_eq!(Endpoint::parse("http://access.test"), None);
        assert_eq!(Endpoint::parse("https://access.test/x"), None);
        assert_eq!(Endpoint::parse("https://u@access.test"), None);
    }

    // OP-153 m.8 (d)
    #[test]
    fn the_poll_target_is_an_https_path_and_one_credential_token() {
        let (at, path, auth) =
            poll_target("https://access.test:8443/realms/acme/ssf/poll", " t0k ").unwrap();
        assert_eq!(
            (at.port, path.as_str(), auth.as_str()),
            (8443, "/realms/acme/ssf/poll", "Bearer t0k")
        );
        assert!(poll_target("https://access.test", "t").is_none());
        assert!(poll_target("http://access.test/ssf/poll", "t").is_none());
        assert!(poll_target("https://access.test/ssf/poll", "a\r\nX: y").is_none());
        assert!(poll_target("https://access.test/ssf/poll", " ").is_none());
    }

    #[test]
    fn responses_parse_with_length_or_chunks() {
        let plain =
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}";
        let r = parse(plain).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"{}"[..]));
        let chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(parse(chunked).unwrap().body, b"{}");
        assert!(parse(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\n{}").is_none());
    }
}
