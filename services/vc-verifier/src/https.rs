//! The production ports: Claim Ingest on Access's public listener with the verifier's client
//! certificate (OP-62), and the guarded outbound fetcher for DID documents, issuer metadata,
//! status lists and trusted lists: `https` only, the name resolved once and every address
//! checked public before connecting, no redirect followed, bounded size and time. Any failure is
//! [`Answer::Unanswered`], never a guess.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::ports::{Access, Answer, Fault, Fetch, Response};

/// Largest answer read.
pub const MAX_ANSWER: usize = 8 * 1024 * 1024;

/// How long one request may take.
pub const TIMEOUT: Duration = Duration::from_secs(20);

struct Target {
    host: String,
    port: u16,
    path: String,
}

fn target(url: &str) -> Option<Target> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| {
        (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("/"))
    });
    if authority.is_empty()
        || authority.contains(['@', '[', ']'])
        || path.contains(['\r', '\n', ' ', '#'])
    {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (h, p.parse().ok()?),
        Some(_) => return None,
        None => (authority, 443),
    };
    Some(Target {
        host: host.to_owned(),
        port,
        path: path.to_owned(),
    })
}

/// Whether an address may be fetched from: not loopback, private, link-local, shared, multicast,
/// documentation, unspecified or reserved.
#[must_use]
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (18..=19).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

async fn send(
    connector: &TlsConnector,
    addr: SocketAddr,
    at: &Target,
    head_extra: &str,
    method: &str,
    body: &[u8],
) -> Option<Response> {
    let name = ServerName::try_from(at.host.clone()).ok()?;
    let tcp = TcpStream::connect(addr).await.ok()?;
    let mut tls = connector.connect(name, tcp).await.ok()?;
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: access-vc-verifier/1\r\n{head_extra}",
        at.path, at.host, at.port
    );
    let _ = write!(
        head,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
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

/// Access over HTTPS with the verifier's client certificate.
pub struct AccessHttps {
    connector: TlsConnector,
    origin: String,
}

impl AccessHttps {
    /// A client presenting `chain` and `key` to `origin`, trusting `roots`.
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
}

impl Access for AccessHttps {
    async fn ingest(&self, key: String, body: Vec<u8>) -> Answer {
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Answer::Unanswered(Fault::Transport);
        }
        let Some(at) = target(&format!("{}/access/v1/claims:ingest", self.origin)) else {
            return Answer::Unanswered(Fault::Transport);
        };
        let head = format!(
            "Accept: application/json\r\nContent-Type: application/json\r\nIdempotency-Key: {key}\r\n"
        );
        let addr = match tokio::net::lookup_host((at.host.as_str(), at.port)).await {
            Ok(mut a) => a.next(),
            Err(_) => None,
        };
        let Some(addr) = addr else {
            return Answer::Unanswered(Fault::Unreachable);
        };
        match tokio::time::timeout(
            TIMEOUT,
            send(&self.connector, addr, &at, &head, "POST", &body),
        )
        .await
        {
            Ok(Some(r)) => Answer::Response(r),
            Ok(None) => Answer::Unanswered(Fault::Unreachable),
            Err(_) => Answer::Unanswered(Fault::Timeout),
        }
    }
}

/// The guarded outbound fetcher.
pub struct GuardedFetch {
    connector: TlsConnector,
}

impl GuardedFetch {
    /// A fetcher trusting `roots`.
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

impl Fetch for GuardedFetch {
    async fn get(&self, url: String, accept: &'static str) -> Answer {
        let Some(at) = target(&url) else {
            return Answer::Unanswered(Fault::Transport);
        };
        let addrs: Vec<SocketAddr> =
            match tokio::net::lookup_host((at.host.as_str(), at.port)).await {
                Ok(a) => a.collect(),
                Err(_) => return Answer::Unanswered(Fault::Unreachable),
            };
        if addrs.is_empty() || addrs.iter().any(|a| !public(a.ip())) {
            return Answer::Unanswered(Fault::Transport);
        }
        let Some(addr) = addrs.first().copied() else {
            return Answer::Unanswered(Fault::Unreachable);
        };
        let head = format!("Accept: {accept}\r\n");
        match tokio::time::timeout(TIMEOUT, send(&self.connector, addr, &at, &head, "GET", &[]))
            .await
        {
            Ok(Some(r)) if (300..400).contains(&r.status) => Answer::Unanswered(Fault::Transport),
            Ok(Some(r)) => Answer::Response(r),
            Ok(None) => Answer::Unanswered(Fault::Unreachable),
            Err(_) => Answer::Unanswered(Fault::Timeout),
        }
    }
}
