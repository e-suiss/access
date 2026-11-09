//! TLS 1.3 listener (CR-12, OP-36): the only protocol version, the hybrid post-quantum key
//! exchange first, no 0-RTT, bounded concurrent handshakes and a handshake deadline. A client
//! certificate, when one is presented, names the PEP (OP-141 m.18 (b)); one whose leaf names a
//! SPIFFE ID is an X.509-SVID instead, its possession proven by the handshake and its chain
//! checked by the authorization server against its trust domain's bundle (OP-154 m.3 (r)).

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
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
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

/// The client certificate chain of a connection whose leaf names a SPIFFE ID, leaf first, DER
/// (OP-154 m.3 (r), §11.15): an X.509-SVID the authorization server verifies; never a PEP.
#[derive(Clone, Debug)]
pub struct ClientChain(pub Arc<[Vec<u8>]>);

/// Whether `leaf` names exactly one SPIFFE ID in its subjectAltName.
fn svid_leaf(leaf: &[u8]) -> bool {
    access_identity_attest::domain::svid::x509_subject(leaf).is_ok()
}

/// The operator's client CA for PEPs, and the handshake proof alone for an X.509-SVID, whose
/// chain the authorization server verifies (OP-154 m.3 (r)).
#[derive(Debug)]
struct PepOrSvid(Arc<dyn ClientCertVerifier>);

impl ClientCertVerifier for PepOrSvid {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls_pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if svid_leaf(end_entity.as_ref()) {
            return Ok(ClientCertVerified::assertion());
        }
        self.0.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

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
    // CR-12
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
            builder.with_client_cert_verifier(Arc::new(PepOrSvid(verifier)))
        }
    };
    let mut config = builder.with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // OP-36
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// A client configuration for requests to clients' own endpoints (§10.4.6, §11.3.6): the
/// operator's PEM trust anchors, TLS 1.3 with aws-lc-rs, no client certificate.
///
/// # Errors
/// [`TlsError::ClientCa`] when the bundle holds no usable certificate.
pub fn client_config(roots_pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(
        CertificateDer::pem_slice_iter(roots_pem).filter_map(Result::ok),
    );
    if added == 0 {
        return Err(TlsError::ClientCa("no certificate".to_owned()));
    }
    let provider = Arc::new(aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
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
            let app = app.layer(Extension(crate::login::Peer(peer.ip())));
            let app = match svid_chain(tls.get_ref().1) {
                Some(chain) => app.layer(Extension(chain)),
                None => app,
            };
            // OP-155 m.3 (c)
            let app = match gateway(tls.get_ref().1) {
                Some(gateway) => app.layer(Extension(gateway)),
                None => app,
            };
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

/// The X.509-SVID chain the connection presented (OP-154 m.3 (r)).
fn svid_chain(conn: &rustls::ServerConnection) -> Option<ClientChain> {
    let chain = conn.peer_certificates()?;
    if !svid_leaf(chain.first()?.as_ref()) {
        return None;
    }
    Some(ClientChain(
        chain.iter().map(|c| c.as_ref().to_vec()).collect(),
    ))
}

/// The protocol gateway the verified client certificate names (OP-155 m.3 (c)).
fn gateway(conn: &rustls::ServerConnection) -> Option<crate::edge::GatewayCert> {
    crate::edge::gateway_cert(conn.peer_certificates()?.first()?.as_ref())
}

/// The PEP named by the verified client certificate: the base64url SHA-256 of the leaf, as
/// RFC 8705 `x5t#S256` (OP-141 m.18 (b)). An X.509-SVID or a gateway names no PEP (IDI-11).
fn pep(conn: &rustls::ServerConnection) -> Option<Pep> {
    let leaf = conn.peer_certificates()?.first()?;
    if svid_leaf(leaf.as_ref()) || crate::edge::gateway_cert(leaf.as_ref()).is_some() {
        return None;
    }
    Some(Pep(b64url_encode(&suiss_crypto::digest::sha256(
        leaf.as_ref(),
    ))))
}
