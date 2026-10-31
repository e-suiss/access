//! TLS 1.3 listener (CR-12, OP-36): the only protocol version, the hybrid post-quantum key
//! exchange first, no 0-RTT, bounded concurrent handshakes and a handshake deadline. A client
//! certificate, when one is presented, names the PEP (OP-141 m.18 (b)).

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use access_kernel::json::b64url_encode;
use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::RootCertStore;
pub use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::adp::adapters::Pep;

/// Most TLS handshakes in progress at once (OP-36, PD).
pub const HANDSHAKES: usize = 256;

/// Longest a handshake may take (PD).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the TLS configuration was refused; the server does not start (OP-52).
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The certificate chain is not PEM or is empty.
    #[error("certificate chain: {0}")]
    Certificates(String),
    /// The private key is not a PEM key.
    #[error("private key: {0}")]
    Key(String),
    /// The client CA bundle is not PEM, is empty or is refused.
    #[error("client CA: {0}")]
    ClientCa(String),
    /// rustls refused the chain, the key or the versions.
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
}

/// A TLS 1.3-only server configuration for a PEM chain and key, read before the lockdown.
/// With `client_ca_pem` the server asks for a client certificate chaining to it but does not
/// require one (OP-141 m.18 (b)).
///
/// # Errors
/// [`TlsError`].
pub fn server_config(
    chain_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Certificates(e.to_string()))?;
    if chain.is_empty() {
        return Err(TlsError::Certificates("no certificate".to_owned()));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| TlsError::Key(e.to_string()))?;
    // CR-12: aws-lc-rs with X25519MLKEM768 preferred (rustls `prefer-post-quantum`)
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let builder = match client_ca_pem {
        None => builder.with_no_client_auth(),
        Some(pem) => {
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(pem) {
                let cert = cert.map_err(|e| TlsError::ClientCa(e.to_string()))?;
                roots
                    .add(cert)
                    .map_err(|e| TlsError::ClientCa(e.to_string()))?;
            }
            if roots.is_empty() {
                return Err(TlsError::ClientCa("no certificate".to_owned()));
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .allow_unauthenticated()
                .build()
                .map_err(|e| TlsError::ClientCa(e.to_string()))?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder.with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // OP-36: no 0-RTT
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// Serves `app` over TLS on `listener` until `shutdown` resolves; in-flight requests finish.
///
/// # Errors
/// The listener's accept error.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    let handshakes = Arc::new(Semaphore::new(HANDSHAKES));
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            () = &mut shutdown => break,
        };
        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "too many TLS handshakes in progress; connection dropped");
            continue;
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(error)) => {
                    tracing::debug!(%peer, %error, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            drop(permit);
            let service = TowerToHyperService::new(match pep(tls.get_ref().1) {
                Some(pep) => app.layer(Extension(pep)),
                None => app,
            });
            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tls), service);
            if let Err(error) = watcher.watch(conn.into_owned()).await {
                tracing::debug!(%peer, %error, "connection ended with an error");
            }
        });
    }
    graceful.shutdown().await;
    Ok(())
}

/// The PEP named by the verified client certificate: the base64url SHA-256 of the leaf, as
/// RFC 8705 `x5t#S256` (OP-141 m.18 (b)).
fn pep(conn: &rustls::ServerConnection) -> Option<Pep> {
    let leaf = conn.peer_certificates()?.first()?;
    Some(Pep(b64url_encode(&suiss_crypto::digest::sha256(
        leaf.as_ref(),
    ))))
}
