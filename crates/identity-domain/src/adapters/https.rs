//! HTTPS to the operator's ACME directory (OP-156 m.3 (i)): TLS 1.3 to the directory's own
//! origin and nowhere else, one request per connection, every answer bounded and every request
//! under one deadline. The operator names the directory and its trust anchors; the server's URLs
//! are already held to its origin by the client.

use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::acme::wire::{JOSE_JSON, PEM_CHAIN, origin};
use crate::ports::{AcmeHttp, Answer, Unavailable};

/// Largest response head read.
pub const MAX_HEAD: usize = 16 * 1024;

/// Most response headers read.
const MAX_HEADERS: usize = 64;

/// The ACME directory's origin over TLS.
#[derive(Clone)]
pub struct AcmeHttps {
    origin: String,
    host: String,
    port: u16,
    connector: TlsConnector,
    timeout: Duration,
}

fn down(what: &str) -> Unavailable {
    Unavailable(format!("acme: {what}"))
}

impl AcmeHttps {
    /// A client of the directory at `directory` (an `https` URL) over `tls`, each exchange
    /// within `timeout`.
    ///
    /// # Errors
    /// [`Unavailable`] for a URL that is not `https://host[:port]/…`.
    pub fn new(
        directory: &str,
        tls: Arc<rustls::ClientConfig>,
        timeout: Duration,
    ) -> Result<Self, Unavailable> {
        let origin = origin(directory).ok_or_else(|| down("directory url"))?;
        let authority = origin.strip_prefix("https://").unwrap_or_default();
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(']') || h.ends_with(']') => (
                h.trim_start_matches('[').trim_end_matches(']'),
                p.parse::<u16>().map_err(|_| down("port"))?,
            ),
            _ => (authority, 443),
        };
        if host.is_empty() {
            return Err(down("host"));
        }
        Ok(Self {
            origin: origin.to_owned(),
            host: host.to_owned(),
            port,
            connector: TlsConnector::from(tls),
            timeout,
        })
    }

    fn path<'u>(&self, url: &'u str) -> Result<&'u str, Unavailable> {
        let rest = url
            .strip_prefix(self.origin.as_str())
            .ok_or_else(|| down("url off origin"))?;
        match rest {
            "" => Ok("/"),
            r if r.starts_with('/') => Ok(r),
            _ => Err(down("url off origin")),
        }
    }

    fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    async fn exchange(
        &self,
        request: Vec<u8>,
        max_body: usize,
        head: bool,
    ) -> Result<Answer, Unavailable> {
        let addr = (self.host.as_str(), self.port);
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|_| down("connect"))?;
        let name = ServerName::try_from(self.host.clone()).map_err(|_| down("server name"))?;
        let mut tls = self
            .connector
            .connect(name, tcp)
            .await
            .map_err(|_| down("tls"))?;
        tls.write_all(&request).await.map_err(|_| down("write"))?;
        tls.flush().await.map_err(|_| down("write"))?;
        let limit = MAX_HEAD
            .saturating_add(max_body.saturating_mul(2))
            .saturating_add(4096);
        let mut raw = Vec::with_capacity(4096);
        let mut chunk = [0_u8; 4096];
        loop {
            let n = match tls.read(&mut chunk).await {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(_) => return Err(down("read")),
            };
            if n == 0 {
                break;
            }
            raw.extend_from_slice(chunk.get(..n).unwrap_or_default());
            if raw.len() > limit {
                return Err(down("answer too large"));
            }
        }
        parse(&raw, max_body, head)
    }

    async fn bounded(
        &self,
        request: Vec<u8>,
        max_body: usize,
        head: bool,
    ) -> Result<Answer, Unavailable> {
        tokio::time::timeout(self.timeout, self.exchange(request, max_body, head))
            .await
            .map_err(|_| down("deadline"))?
    }
}

fn header(headers: &[httparse::Header<'_>], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| core::str::from_utf8(h.value).ok())
        .map(|v| v.trim().to_owned())
}

fn dechunk(mut raw: &[u8], max_body: usize) -> Result<Vec<u8>, Unavailable> {
    let mut out = Vec::new();
    loop {
        let end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| down("chunk"))?;
        let size_line =
            core::str::from_utf8(raw.get(..end).unwrap_or_default()).map_err(|_| down("chunk"))?;
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| down("chunk"))?;
        let from = end.saturating_add(2);
        if size == 0 {
            return Ok(out);
        }
        let to = from.checked_add(size).ok_or_else(|| down("chunk"))?;
        out.extend_from_slice(raw.get(from..to).ok_or_else(|| down("chunk"))?);
        if out.len() > max_body {
            return Err(down("body too large"));
        }
        raw = raw
            .get(to.saturating_add(2)..)
            .ok_or_else(|| down("chunk"))?;
    }
}

/// Reads one HTTP/1.1 answer read to the end of the connection.
///
/// # Errors
/// [`Unavailable`].
pub fn parse(raw: &[u8], max_body: usize, head: bool) -> Result<Answer, Unavailable> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let at = match resp.parse(raw) {
        Ok(httparse::Status::Complete(at)) if at <= MAX_HEAD => at,
        _ => return Err(down("head")),
    };
    let status = resp.code.ok_or_else(|| down("status"))?;
    let hs = resp.headers;
    let mut answer = Answer {
        status,
        nonce: header(hs, "replay-nonce"),
        location: header(hs, "location"),
        retry_after_s: header(hs, "retry-after").and_then(|v| v.parse::<u64>().ok()),
        content_type: header(hs, "content-type"),
        body: Vec::new(),
    };
    if head {
        return Ok(answer);
    }
    let after = raw.get(at..).unwrap_or_default();
    let chunked =
        header(hs, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    answer.body = if chunked {
        dechunk(after, max_body)?
    } else {
        let body = match header(hs, "content-length") {
            Some(l) => {
                let l = l.parse::<usize>().map_err(|_| down("length"))?;
                after.get(..l).ok_or_else(|| down("short body"))?
            }
            None => after,
        };
        body.to_vec()
    };
    if answer.body.len() > max_body {
        return Err(down("body too large"));
    }
    Ok(answer)
}

impl AcmeHttp for AcmeHttps {
    async fn get(&self, url: &str, max_body: usize) -> Result<Answer, Unavailable> {
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nUser-Agent: access\r\n\
             Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
            self.path(url)?,
            self.host_header()
        );
        self.bounded(request.into_bytes(), max_body, false).await
    }

    async fn head(&self, url: &str) -> Result<Answer, Unavailable> {
        let request = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: access\r\nConnection: close\r\n\r\n",
            self.path(url)?,
            self.host_header()
        );
        self.bounded(request.into_bytes(), 0, true).await
    }

    async fn post(&self, url: &str, body: &[u8], max_body: usize) -> Result<Answer, Unavailable> {
        let mut request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {JOSE_JSON}\r\nContent-Length: {}\r\n\
             Accept: application/json, {PEM_CHAIN}\r\nUser-Agent: access\r\n\
             Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
            self.path(url)?,
            self.host_header(),
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        self.bounded(request, max_body, false).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8555 §6.5, §7.2
    #[test]
    fn answers_carry_the_acme_headers_and_stay_bounded() {
        let raw =
            b"HTTP/1.1 201 Created\r\nReplay-Nonce: abc\r\nLocation: https://a.example/acct/1\r\n\
Retry-After: 3\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let a = parse(raw, 1024, false).unwrap();
        assert_eq!(a.status, 201);
        assert_eq!(a.nonce.as_deref(), Some("abc"));
        assert_eq!(a.location.as_deref(), Some("https://a.example/acct/1"));
        assert_eq!(a.retry_after_s, Some(3));
        assert_eq!(a.body, b"{}");
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(parse(chunked, 1024, false).unwrap().body, b"{}");
        assert!(parse(raw, 1, false).is_err());
        let c = AcmeHttps::new(
            "https://pebble:14000/dir",
            Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
            ),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(c.path("https://pebble:14000/dir").unwrap(), "/dir");
        assert!(c.path("https://pebble:14001/dir").is_err());
        assert!(c.path("https://pebble:140000/dir").is_err());
        assert_eq!(c.host_header(), "pebble:14000");
    }
}
