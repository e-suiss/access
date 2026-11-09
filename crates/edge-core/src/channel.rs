//! The edge channel client (OP-155 m.3 (c), IDP-26): one TLS 1.3 connection per call to
//! access-server, authenticated both ways. The gateway proves its identity with its own client
//! certificate; access-server is verified against the operator's roots. HTTP/1.1, one request,
//! bounded head and body, one deadline.

use std::sync::Arc;
use std::time::Duration;

use access_internal_api::edge::{CONTENT_TYPE, Call, MAX_BODY};
use rustls::RootCertStore;
use rustls::crypto::aws_lc_rs;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Longest one call may take.
pub const DEADLINE: Duration = Duration::from_secs(10);

/// Largest response head.
pub const MAX_HEAD: usize = 16 * 1024;

/// Why a call has no answer the gateway can use.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// access-server refused the call with a problem code (e.g. `edge-realm`).
    #[error("refused ({status}): {code}")]
    Refused {
        /// HTTP status.
        status: u16,
        /// The problem's stable code.
        code: String,
    },
    /// No answer: connection, TLS, I/O or the deadline failed.
    #[error("edge channel unavailable")]
    Unavailable,
    /// The answer is not HTTP/1.1 or is larger than allowed.
    #[error("malformed answer")]
    Malformed,
}

/// Why the channel configuration was refused; the gateway does not start (OP-52).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A PEM input holds no usable certificate or key.
    #[error("{0}")]
    Pem(&'static str),
    /// rustls refused the configuration.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
}

/// Where access-server is and how both sides prove who they are, read before the lockdown.
pub struct ChannelConfig {
    /// `host:port` of access-server's TLS listener.
    pub addr: String,
    /// The name access-server's certificate is verified for.
    pub server_name: String,
    /// The operator's roots for access-server's certificate, PEM.
    pub roots_pem: Vec<u8>,
    /// The gateway's certificate chain, PEM; its leaf names the gateway in its SAN URI.
    pub chain_pem: Vec<u8>,
    /// The gateway's private key, PEM.
    pub key_pem: Vec<u8>,
}

impl core::fmt::Debug for ChannelConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelConfig")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// The channel.
#[derive(Clone)]
pub struct Channel {
    addr: String,
    host: String,
    name: ServerName<'static>,
    connector: TlsConnector,
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// The channel for `config`.
    ///
    /// # Errors
    /// [`ConfigError`].
    pub fn new(config: &ChannelConfig) -> Result<Self, ConfigError> {
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(
            CertificateDer::pem_slice_iter(&config.roots_pem).filter_map(Result::ok),
        );
        if added == 0 {
            return Err(ConfigError::Pem("no root certificate"));
        }
        let chain = CertificateDer::pem_slice_iter(&config.chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigError::Pem("certificate chain"))?;
        if chain.is_empty() {
            return Err(ConfigError::Pem("no client certificate"));
        }
        let key = PrivateKeyDer::from_pem_slice(&config.key_pem)
            .map_err(|_| ConfigError::Pem("private key"))?;
        // CR-12
        let mut tls =
            rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_client_auth_cert(chain, key)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(config.server_name.clone())
            .map_err(|_| ConfigError::Pem("server name"))?;
        Ok(Self {
            addr: config.addr.clone(),
            host: config.server_name.clone(),
            name,
            connector: TlsConnector::from(Arc::new(tls)),
        })
    }

    /// Makes `call` with the CBOR `body`; returns the CBOR answer.
    ///
    /// # Errors
    /// [`ChannelError`].
    pub async fn call(&self, call: Call, body: &[u8]) -> Result<Vec<u8>, ChannelError> {
        tokio::time::timeout(DEADLINE, self.exchange(call, body))
            .await
            .map_err(|_| ChannelError::Unavailable)?
    }

    async fn exchange(&self, call: Call, body: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let down = |_| ChannelError::Unavailable;
        let tcp = TcpStream::connect(&self.addr).await.map_err(down)?;
        let mut tls = self
            .connector
            .connect(self.name.clone(), tcp)
            .await
            .map_err(down)?;
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            call.path(),
            self.host,
            body.len()
        );
        tls.write_all(head.as_bytes()).await.map_err(down)?;
        tls.write_all(body).await.map_err(down)?;
        tls.flush().await.map_err(down)?;
        let limit = MAX_HEAD.saturating_add(MAX_BODY);
        let mut answer = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let n = match tls.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => return Err(ChannelError::Unavailable),
            };
            if answer.len().saturating_add(n) > limit {
                return Err(ChannelError::Malformed);
            }
            answer.extend_from_slice(chunk.get(..n).ok_or(ChannelError::Malformed)?);
        }
        parse(&answer)
    }
}

/// Reads one HTTP/1.1 answer with a `Content-Length` body.
///
/// # Errors
/// [`ChannelError`].
pub fn parse(answer: &[u8]) -> Result<Vec<u8>, ChannelError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut r = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(at) = r.parse(answer).map_err(|_| ChannelError::Malformed)?
    else {
        return Err(ChannelError::Malformed);
    };
    let status = r.code.ok_or(ChannelError::Malformed)?;
    let length = r
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| core::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
        .ok_or(ChannelError::Malformed)?;
    if at > MAX_HEAD || length > MAX_BODY {
        return Err(ChannelError::Malformed);
    }
    let body = answer
        .get(at..)
        .and_then(|b| b.get(..length))
        .ok_or(ChannelError::Malformed)?;
    if status == 200 {
        return Ok(body.to_vec());
    }
    let code = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(String::from))
        .unwrap_or_else(|| String::from("edge-refused"));
    Err(ChannelError::Refused { status, code })
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-155 m.3 (c)
    #[test]
    fn answers_are_bounded_and_refusals_keep_their_code() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\xa0\x00";
        assert_eq!(parse(ok), Ok(vec![0xa0, 0]));
        let refused =
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 22\r\n\r\n{\"code\":\"edge-realm\"}  ";
        assert_eq!(
            parse(refused),
            Err(ChannelError::Refused {
                status: 403,
                code: String::from("edge-realm")
            })
        );
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\n\r\n"),
            Err(ChannelError::Malformed)
        );
        let huge = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(parse(huge.as_bytes()), Err(ChannelError::Malformed));
    }
}
