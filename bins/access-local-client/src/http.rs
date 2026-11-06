//! One HTTPS request at a time (HTTP/1.1, `Connection: close`) over TLS verified against the
//! local CA, with an optional client certificate for the PEP routes (OP-141 m.18 (b)). The host
//! may be reached at another address (`connect_to`), the way `curl --resolve` does, so a flow
//! against `https://access-server:8443` runs from outside the compose network too.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::ClientError;

/// Largest answer read, bytes.
pub const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// An `https` URL split for the request line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// The host name.
    pub host: String,
    /// The port.
    pub port: u16,
    /// Path and query.
    pub path: String,
}

impl Url {
    /// Splits `url`; anything but `https://host[:port]/path?query` is refused.
    ///
    /// # Errors
    /// [`ClientError::Url`].
    pub fn parse(url: &str) -> Result<Self, ClientError> {
        let bad = || ClientError::Url(String::from(url));
        let rest = url.strip_prefix("https://").ok_or_else(bad)?;
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
            host: String::from(host),
            port,
            path: if tail.is_empty() {
                String::from("/")
            } else {
                String::from(tail)
            },
        })
    }

    /// `host` or `host:port` for the `Host` header.
    #[must_use]
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// `https://host[:port]`.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("https://{}", self.host_header())
    }
}

/// One answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status.
    pub status: u16,
    /// The headers, names lower-case.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// The first header `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every header `name`.
    pub fn all(&self, name: &str) -> impl Iterator<Item = &str> {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as JSON, `Null` when it is not.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// The body as text, lossily.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// The TLS client identity of a PEP: its certificate chain and key, PEM.
pub struct Identity {
    /// The chain, leaf first.
    pub chain_pem: Vec<u8>,
    /// The key.
    pub key_pem: Vec<u8>,
}

/// The HTTPS client.
#[derive(Clone)]
pub struct Http {
    connector: TlsConnector,
    connect_to: Option<SocketAddr>,
}

fn tls(e: impl core::fmt::Display) -> ClientError {
    ClientError::Tls(e.to_string())
}

/// The DER of the first certificate in `pem`: a PEP's `x5t#S256` thumbprint is over it.
///
/// # Errors
/// [`ClientError::File`] when it holds none.
pub fn leaf_der(pem: &[u8]) -> Result<Vec<u8>, ClientError> {
    CertificateDer::pem_slice_iter(pem)
        .next()
        .and_then(Result::ok)
        .map(|c| c.as_ref().to_vec())
        .ok_or_else(|| {
            ClientError::File(
                String::from("certificate"),
                String::from("no certificate in the PEM"),
            )
        })
}

impl Http {
    /// A client trusting `ca_pem` only, with `identity` when the PEP routes are called, reaching
    /// every host at `connect_to` when given.
    ///
    /// # Errors
    /// [`ClientError::Tls`].
    pub fn new(
        ca_pem: &[u8],
        identity: Option<&Identity>,
        connect_to: Option<SocketAddr>,
    ) -> Result<Self, ClientError> {
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(
            CertificateDer::pem_slice_iter(ca_pem).filter_map(Result::ok),
        );
        if added == 0 {
            return Err(ClientError::Tls(String::from(
                "no certificate in the CA file",
            )));
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls)?
            .with_root_certificates(roots);
        let config = match identity {
            None => builder.with_no_client_auth(),
            Some(id) => {
                let chain: Vec<CertificateDer<'static>> =
                    CertificateDer::pem_slice_iter(&id.chain_pem)
                        .collect::<Result<_, _>>()
                        .map_err(tls)?;
                let key = PrivateKeyDer::from_pem_slice(&id.key_pem).map_err(tls)?;
                builder.with_client_auth_cert(chain, key).map_err(tls)?
            }
        };
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            connect_to,
        })
    }

    /// `method url` with `headers` and `body`, the answer read whole.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<Response, ClientError> {
        let target = Url::parse(url)?;
        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: access-local-client\r\n\
             Accept: application/json, */*\r\nConnection: close\r\n",
            target.path,
            target.host_header()
        );
        for (name, value) in headers {
            if !header_ok(name, value) {
                return Err(ClientError::Http(format!(
                    "header {name} cannot be carried"
                )));
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        if let Some((content_type, bytes)) = body {
            let _ = write!(
                head,
                "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
                bytes.len()
            );
        }
        head.push_str("\r\n");
        let mut request = head.into_bytes();
        if let Some((_, bytes)) = body {
            request.extend_from_slice(bytes);
        }
        let tcp = match self.connect_to {
            Some(addr) => TcpStream::connect(addr).await,
            None => TcpStream::connect((target.host.as_str(), target.port)).await,
        }
        .map_err(|e| ClientError::Http(format!("connect {}: {e}", target.host_header())))?;
        let name = ServerName::try_from(target.host.clone()).map_err(tls)?;
        let mut stream = self.connector.connect(name, tcp).await.map_err(tls)?;
        stream
            .write_all(&request)
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let n = match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(ClientError::Http(e.to_string())),
            };
            raw.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            if raw.len() > MAX_ANSWER {
                return Err(ClientError::Http(String::from("answer too large")));
            }
        }
        parse(&raw)
    }
}

fn header_ok(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        && value.bytes().all(|c| c == b' ' || c.is_ascii_graphic())
}

/// Parses a whole HTTP/1.1 answer.
///
/// # Errors
/// [`ClientError::Http`].
pub fn parse(raw: &[u8]) -> Result<Response, ClientError> {
    let mut slots = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut slots);
    let head = match parsed.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return Err(ClientError::Http(String::from("answer cut short")));
        }
        Err(e) => return Err(ClientError::Http(e.to_string())),
    };
    let status = parsed
        .code
        .ok_or_else(|| ClientError::Http(String::from("no status")))?;
    let headers: Vec<(String, String)> = parsed
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).trim().to_owned(),
            )
        })
        .collect();
    let rest = raw.get(head..).unwrap_or(&[]);
    let chunked = headers
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        dechunk(rest)?
    } else {
        let length = headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .and_then(|(_, v)| v.parse::<usize>().ok());
        match length {
            Some(n) => rest.get(..n.min(rest.len())).unwrap_or(&[]).to_vec(),
            None => rest.to_vec(),
        }
    };
    Ok(Response {
        status,
        headers,
        body,
    })
}

fn dechunk(mut raw: &[u8]) -> Result<Vec<u8>, ClientError> {
    let malformed = || ClientError::Http(String::from("malformed chunked body"));
    let mut out = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(malformed)?;
        let line = core::str::from_utf8(raw.get(..line_end).ok_or_else(malformed)?)
            .map_err(|_| malformed())?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| malformed())?;
        let start = line_end.checked_add(2).ok_or_else(malformed)?;
        if size == 0 {
            return Ok(out);
        }
        let end = start.checked_add(size).ok_or_else(malformed)?;
        out.extend_from_slice(raw.get(start..end).ok_or_else(malformed)?);
        let next = end.checked_add(2).ok_or_else(malformed)?;
        if raw.get(end..next) != Some(b"\r\n") {
            return Err(malformed());
        }
        raw = raw.get(next..).ok_or_else(malformed)?;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    // OP-149 m.22, m.26 (b): only https, the port and path kept; the host header carries the
    // port unless it is 443
    #[test]
    fn urls_are_https_only() {
        let u = Url::parse("https://access-server:8443/realms/acme/authorize?a=1").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("access-server", 8443, "/realms/acme/authorize?a=1")
        );
        assert_eq!(u.host_header(), "access-server:8443");
        assert_eq!(u.origin(), "https://access-server:8443");
        let plain = Url::parse("https://id.example").unwrap();
        assert_eq!((plain.port, plain.path.as_str()), (443, "/"));
        assert_eq!(plain.host_header(), "id.example");
        for bad in [
            "http://access-server:8443/",
            "https://",
            "https://user@host/",
            "access-server:8443",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    // a chunked or content-length body is read whole; headers are lower-cased
    #[test]
    fn answers_are_parsed() {
        let r = parse(
            b"HTTP/1.1 303 See Other\r\nLocation: /x\r\nSet-Cookie: a=1; Path=/\r\n\
              Content-Length: 2\r\n\r\nok",
        )
        .unwrap();
        assert_eq!((r.status, r.header("location")), (303, Some("/x")));
        assert_eq!(r.body, b"ok");
        let c = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n2\r\n\":\r\n2\r\n1}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(c.json()["a"], 1);
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length").is_err());
    }
}
