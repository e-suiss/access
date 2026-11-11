//! The command line's HTTP port and its HTTPS adapter: one request at a time (HTTP/1.1,
//! `Connection: close`) over TLS verified against the CA file the operator names. There is no
//! plain-HTTP path and no switch that skips verification (TI-9, OP-69).

use std::fmt::Write as _;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Largest answer read, bytes.
pub(crate) const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// Why no answer came.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpError {
    /// The URL is not `https://host[:port]/path`.
    #[error("not an https URL: {0}")]
    Url(String),
    /// TLS or the connection failed.
    #[error("connection: {0}")]
    Connect(String),
    /// The answer is not HTTP/1.1, or too large.
    #[error("answer: {0}")]
    Answer(String),
    /// The CA file cannot be used.
    #[error("CA file: {0}")]
    Ca(String),
}

/// An `https` URL split for the request line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Url {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
}

impl Url {
    /// Splits `url`; anything but `https://host[:port]/path?query` is refused.
    pub(crate) fn parse(url: &str) -> Result<Self, HttpError> {
        let bad = || HttpError::Url(url.to_owned());
        let rest = url.strip_prefix("https://").ok_or_else(bad)?;
        if url.contains('#') {
            return Err(bad());
        }
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.is_empty() || authority.contains('@') {
            return Err(bad());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(']') || h.ends_with(']') => {
                (h, p.parse::<u16>().map_err(|_| bad())?)
            }
            _ => (authority, 443),
        };
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            path: if tail.is_empty() {
                String::from("/")
            } else {
                tail.to_owned()
            },
        })
    }
}

/// One request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) method: &'static str,
    pub(crate) url: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<(&'static str, Vec<u8>)>,
}

impl Request {
    #[cfg(test)]
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Response {
    /// The first header `name` (case-insensitive).
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as JSON, `Null` when it is not.
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// The HTTP port.
pub(crate) trait Transport {
    /// Sends `request`.
    fn send(&self, request: Request) -> impl Future<Output = Result<Response, HttpError>>;
}

/// The HTTPS adapter.
#[derive(Clone)]
pub(crate) struct Https {
    connector: TlsConnector,
}

impl Https {
    /// A client trusting only the certificates in `ca` (PEM).
    pub(crate) fn new(ca: &Path) -> Result<Self, HttpError> {
        let pem = std::fs::read(ca).map_err(|e| HttpError::Ca(e.to_string()))?;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|e| HttpError::Ca(e.to_string()))?;
            roots.add(cert).map_err(|e| HttpError::Ca(e.to_string()))?;
        }
        if roots.is_empty() {
            return Err(HttpError::Ca(String::from("no certificate")));
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| HttpError::Ca(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

impl Https {
    /// A client trusting only the certificates in `ca` (PEM) that presents the certificate in
    /// `cert` with the key in `key` (PEM files), for a PEP channel (L1-ADP-2).
    pub(crate) fn with_client(ca: &Path, cert: &Path, key: &Path) -> Result<Self, HttpError> {
        let pem = std::fs::read(ca).map_err(|e| HttpError::Ca(e.to_string()))?;
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(&pem) {
            let c = c.map_err(|e| HttpError::Ca(e.to_string()))?;
            roots.add(c).map_err(|e| HttpError::Ca(e.to_string()))?;
        }
        if roots.is_empty() {
            return Err(HttpError::Ca(String::from("no certificate")));
        }
        let chain_pem = std::fs::read(cert).map_err(|e| HttpError::Ca(e.to_string()))?;
        let chain = CertificateDer::pem_slice_iter(&chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| HttpError::Ca(e.to_string()))?;
        if chain.is_empty() {
            return Err(HttpError::Ca(String::from("no client certificate")));
        }
        let key_pem = std::fs::read(key).map_err(|e| HttpError::Ca(e.to_string()))?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
            .map_err(|_| HttpError::Ca(String::from("client key")))?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| HttpError::Ca(e.to_string()))?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .map_err(|e| HttpError::Ca(e.to_string()))?;
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

fn head(request: &Request, url: &Url) -> String {
    let mut out = format!("{} {} HTTP/1.1\r\nHost: ", request.method, url.path);
    if url.port == 443 {
        out.push_str(&url.host);
    } else {
        let _ = write!(out, "{}:{}", url.host, url.port);
    }
    out.push_str("\r\nConnection: close\r\nAccept: application/json\r\n");
    for (n, v) in &request.headers {
        let _ = write!(out, "{n}: {v}\r\n");
    }
    if let Some((ct, body)) = &request.body {
        let _ = write!(
            out,
            "Content-Type: {ct}\r\nContent-Length: {}\r\n",
            body.len()
        );
    } else if request.method != "GET" {
        out.push_str("Content-Length: 0\r\n");
    }
    out.push_str("\r\n");
    out
}

fn parse_answer(raw: &[u8]) -> Result<Response, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let status = parsed
        .parse(raw)
        .map_err(|e| HttpError::Answer(e.to_string()))?;
    let httparse::Status::Complete(at) = status else {
        return Err(HttpError::Answer(String::from("incomplete head")));
    };
    let code = parsed
        .code
        .ok_or_else(|| HttpError::Answer(String::from("status")))?;
    let headers: Vec<(String, String)> = parsed
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    let body = raw.get(at..).unwrap_or_default();
    let chunked = headers
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Ok(Response {
        status: code,
        headers,
        body,
    })
}

fn dechunk(mut raw: &[u8]) -> Result<Vec<u8>, HttpError> {
    let bad = || HttpError::Answer(String::from("chunked body"));
    let mut out = Vec::new();
    loop {
        let line_end = raw.windows(2).position(|w| w == b"\r\n").ok_or_else(bad)?;
        let size_text =
            std::str::from_utf8(raw.get(..line_end).ok_or_else(bad)?).map_err(|_| bad())?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| bad())?;
        let start = line_end.checked_add(2).ok_or_else(bad)?;
        if size == 0 {
            return Ok(out);
        }
        let end = start.checked_add(size).ok_or_else(bad)?;
        out.extend_from_slice(raw.get(start..end).ok_or_else(bad)?);
        if out.len() > MAX_ANSWER {
            return Err(bad());
        }
        raw = raw
            .get(end.checked_add(2).ok_or_else(bad)?..)
            .ok_or_else(bad)?;
    }
}

impl Transport for Https {
    async fn send(&self, request: Request) -> Result<Response, HttpError> {
        let url = Url::parse(&request.url)?;
        let name =
            ServerName::try_from(url.host.clone()).map_err(|e| HttpError::Url(e.to_string()))?;
        let tcp = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .map_err(|e| HttpError::Connect(e.to_string()))?;
        let mut tls = self
            .connector
            .connect(name, tcp)
            .await
            .map_err(|e| HttpError::Connect(e.to_string()))?;
        let mut bytes = head(&request, &url).into_bytes();
        if let Some((_, body)) = &request.body {
            bytes.extend_from_slice(body);
        }
        tls.write_all(&bytes)
            .await
            .map_err(|e| HttpError::Connect(e.to_string()))?;
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tls
                .read(&mut buf)
                .await
                .map_err(|e| HttpError::Connect(e.to_string()))?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(buf.get(..n).unwrap_or_default());
            if raw.len() > MAX_ANSWER {
                return Err(HttpError::Answer(String::from("too large")));
            }
        }
        parse_answer(&raw)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn only_https_urls_are_accepted() {
        assert!(Url::parse("http://a.example/x").is_err());
        assert!(Url::parse("https://u@a.example/x").is_err());
        assert!(Url::parse("https://a.example/x#f").is_err());
        let u = Url::parse("https://a.example:9443/admin/v1").unwrap();
        assert_eq!((u.port, u.path.as_str()), (9443, "/admin/v1"));
    }

    #[test]
    fn a_chunked_answer_is_read() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nETag: \"v1\"\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let r = parse_answer(raw).unwrap();
        assert_eq!(r.body, b"abcde");
        assert_eq!(r.header("etag"), Some("\"v1\""));
    }
}
