//! The production ports: Access's public routes over HTTPS with this gateway's client
//! certificate, as any registered proxy reaches them (OP-62, B22), and the MCP server over
//! HTTPS with its certificate checked. One request per connection; any failure is
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

use crate::app::MAX_ANSWER;
use crate::ports::{Access, Upstream};

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
        if authority.is_empty() || authority.contains('@') || path.contains(['\r', '\n', ' ', '#'])
        {
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

struct Sent<'a> {
    method: &'a str,
    url: &'a str,
    accept: &'a str,
    body: &'a [u8],
}

async fn exchange(connector: &TlsConnector, s: &Sent<'_>) -> Option<Response> {
    let at = Target::parse(s.url)?;
    let name = ServerName::try_from(at.host.clone()).ok()?;
    let tcp = TcpStream::connect((at.host.as_str(), at.port)).await.ok()?;
    let mut tls = connector.connect(name, tcp).await.ok()?;
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: {}\r\n",
        s.method, at.path, at.host, at.port, s.accept
    );
    if !s.body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    let _ = write!(
        head,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        s.body.len()
    );
    tls.write_all(head.as_bytes()).await.ok()?;
    tls.write_all(s.body).await.ok()?;
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

async fn timed(connector: &TlsConnector, s: &Sent<'_>) -> Answer {
    match tokio::time::timeout(TIMEOUT, exchange(connector, s)).await {
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

/// The JSON-RPC answer of a Streamable HTTP body: the body itself for `application/json`, the
/// last `data:` event for `text/event-stream`.
#[must_use]
pub fn json_body(r: Response) -> Option<Response> {
    let sse = r
        .content_type
        .as_deref()
        .is_some_and(|c| c.trim_start().starts_with("text/event-stream"));
    if !sse {
        return Some(r);
    }
    let text = std::str::from_utf8(&r.body).ok()?;
    let mut last = None;
    for event in text.split("\n\n") {
        let data: Vec<&str> = event
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim_start)
            .collect();
        if !data.is_empty() {
            last = Some(data.join("\n"));
        }
    }
    Some(Response {
        status: r.status,
        content_type: Some(String::from("application/json")),
        key_excerpt: None,
        body: last?.into_bytes(),
    })
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

/// Access over HTTPS with this gateway's client certificate.
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

    async fn call(&self, method: &str, path: &str, body: &[u8]) -> Answer {
        let url = format!("{}{path}", self.origin);
        timed(
            &self.connector,
            &Sent {
                method,
                url: &url,
                accept: "application/json",
                body,
            },
        )
        .await
    }
}

impl Access for AccessHttps {
    async fn tools(&self, body: Vec<u8>) -> Answer {
        self.call("POST", "/proxy/v1/mcp/tools", &body).await
    }

    async fn calls(&self, body: Vec<u8>) -> Answer {
        self.call("POST", "/proxy/v1/mcp/calls", &body).await
    }

    async fn metadata(&self, domain: String) -> Answer {
        if domain.is_empty()
            || !domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Answer::Unanswered(Fault::Transport);
        }
        self.call(
            "GET",
            &format!("/.well-known/access-domain-metadata/sha-256:{domain}"),
            &[],
        )
        .await
    }
}

/// The MCP server over HTTPS, its certificate checked against `roots`; no client
/// certificate, no proxy, and no credential of the agent's.
pub struct UpstreamHttps {
    connector: TlsConnector,
    url: String,
}

impl UpstreamHttps {
    /// A client of the MCP endpoint `url` (`https://…`) trusting `roots`.
    ///
    /// # Errors
    /// The TLS configuration's error.
    pub fn new(roots: rustls::RootCertStore, url: &str) -> Result<Self, rustls::Error> {
        let c = config(roots)?.with_no_client_auth();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(c)),
            url: String::from(url),
        })
    }
}

impl Upstream for UpstreamHttps {
    async fn send(&self, body: Vec<u8>) -> Answer {
        let answer = timed(
            &self.connector,
            &Sent {
                method: "POST",
                url: &self.url,
                accept: "application/json, text/event-stream",
                body: &body,
            },
        )
        .await;
        match answer {
            Answer::Response(r) => {
                json_body(r).map_or(Answer::Unanswered(Fault::Transport), Answer::Response)
            }
            a @ Answer::Unanswered(_) => a,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn a_streamed_answer_is_its_last_data_event() {
        let r = json_body(Response {
            status: 200,
            content_type: Some(String::from("text/event-stream")),
            key_excerpt: None,
            body: b"event: message\ndata: {\"a\":1}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n"
                .to_vec(),
        })
        .unwrap();
        assert_eq!(r.body, b"{\"jsonrpc\":\"2.0\"}");
        assert_eq!(Target::parse("http://mcp.example.com/mcp"), None);
        assert_eq!(
            Target::parse("https://mcp.example.com:8443/mcp")
                .unwrap()
                .port,
            8443
        );
    }
}
