//! `S4U2Proxy` (§10.6.4, IDP-17, OP-155 m.3 (o)): with the proxy credential of an accepted ticket,
//! the gateway asks the KDC for a ticket to the one configured backend SPN for the same user
//! (constrained delegation; the KDC enforces what the gateway's account may delegate to) and
//! forwards one `GET` to the backend with it. The backend's answer comes back bounded.

use std::sync::Arc;
use std::time::Duration;

use libgssapi::context::{ClientCtx, CtxFlags};
use libgssapi::credential::Cred;
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL};
use rustls::RootCertStore;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::Backend;

/// Largest backend answer passed back.
pub const MAX_ANSWER: usize = 1024 * 1024;

/// Longest the backend may take.
pub const DEADLINE: Duration = Duration::from_secs(15);

/// Why the backend was not reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    /// The configuration is unusable; the gateway does not start.
    #[error("backend configuration")]
    Config,
    /// The ticket allows no delegation, or the KDC refused constrained delegation.
    #[error("delegation refused")]
    Delegation,
    /// The backend could not be reached or answered outside HTTP/1.1.
    #[error("backend unavailable")]
    Unavailable,
}

/// The backend as the gateway reaches it.
#[derive(Clone)]
pub struct Proxy {
    spn: String,
    addr: String,
    host: String,
    name: ServerName<'static>,
    connector: TlsConnector,
}

impl core::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Proxy")
            .field("spn", &self.spn)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    /// The backend of `b`.
    ///
    /// # Errors
    /// [`ProxyError::Config`].
    pub fn new(b: &Backend) -> Result<Self, ProxyError> {
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(
            CertificateDer::pem_slice_iter(&b.roots_pem).filter_map(Result::ok),
        );
        if added == 0 {
            return Err(ProxyError::Config);
        }
        // CR-12
        let mut tls =
            rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| ProxyError::Config)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(b.server_name.clone()).map_err(|_| ProxyError::Config)?;
        Ok(Self {
            spn: b.spn.clone(),
            addr: b.addr.clone(),
            host: b.server_name.clone(),
            name,
            connector: TlsConnector::from(Arc::new(tls)),
        })
    }

    /// A Kerberos token for the backend SPN from the proxy credential `delegated`. Blocking:
    /// call it off the runtime.
    ///
    /// # Errors
    /// [`ProxyError::Delegation`].
    pub fn token(&self, delegated: Cred) -> Result<Vec<u8>, ProxyError> {
        let target = Name::new(self.spn.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
            .and_then(|n| n.canonicalize(Some(GSS_MECH_KRB5)))
            .map_err(|_| ProxyError::Delegation)?;
        let mut ctx = ClientCtx::new(
            Some(delegated),
            target,
            CtxFlags::GSS_C_INTEG_FLAG,
            Some(GSS_MECH_KRB5),
        );
        let token = ctx
            .step(None, None)
            .map_err(|_| ProxyError::Delegation)?
            .ok_or(ProxyError::Delegation)?;
        Ok(token.to_vec())
    }

    /// Forwards `GET path` with `Authorization: Negotiate <spnego>`; returns the backend's raw
    /// HTTP/1.1 answer, at most [`MAX_ANSWER`] bytes.
    ///
    /// # Errors
    /// [`ProxyError::Unavailable`].
    pub async fn get(&self, path: &str, spnego: &str) -> Result<Vec<u8>, ProxyError> {
        tokio::time::timeout(DEADLINE, self.exchange(path, spnego))
            .await
            .map_err(|_| ProxyError::Unavailable)?
    }

    async fn exchange(&self, path: &str, spnego: &str) -> Result<Vec<u8>, ProxyError> {
        let down = |_| ProxyError::Unavailable;
        let tcp = TcpStream::connect(&self.addr).await.map_err(down)?;
        let mut tls = self
            .connector
            .connect(self.name.clone(), tcp)
            .await
            .map_err(down)?;
        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Negotiate {spnego}\r\nConnection: close\r\n\r\n",
            self.host
        );
        tls.write_all(head.as_bytes()).await.map_err(down)?;
        tls.flush().await.map_err(down)?;
        let mut answer = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let n = match tls.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => return Err(ProxyError::Unavailable),
            };
            if answer.len().saturating_add(n) > MAX_ANSWER {
                return Err(ProxyError::Unavailable);
            }
            answer.extend_from_slice(chunk.get(..n).ok_or(ProxyError::Unavailable)?);
        }
        if answer.starts_with(b"HTTP/1.1 ") {
            Ok(answer)
        } else {
            Err(ProxyError::Unavailable)
        }
    }
}
