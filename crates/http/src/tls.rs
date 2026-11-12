//! TLS 1.3 listener (CR-12, OP-36): the only protocol version, the hybrid post-quantum key
//! exchange first, no 0-RTT, bounded concurrent handshakes and a handshake deadline. A client
//! certificate, when one is presented, names the PEP (OP-141 m.18 (b)); one whose leaf names a
//! SPIFFE ID is an X.509-SVID instead, its possession proven by the handshake and its chain
//! checked by the authorization server against its trust domain's bundle (OP-154 m.3 (r)).
//!
//! The mTLS listener (OP-155 m.3 (k), (m), §10.2.5) is a separate port, 8443 by default, that
//! asks every client for a certificate and requires none. A presented chain only proves
//! possession of the leaf's key; it reaches the routes as [`MtlsChain`], and certificate
//! sign-in and client authentication decide trust. A proxy's forwarded certificate header is
//! dropped on every listener: trust comes only from TLS that ends at access-server.
//!
//! The public listener picks its certificate by SNI ([`Sni`], OP-156 m.3 (i)): the operator's
//! certificate for the names it covers, a realm's own certificate for each verified custom
//! domain, and, only for a client that offers nothing but `acme-tls/1`, the TLS-ALPN-01
//! challenge certificate of an open ACME order (RFC 8737). An SNI no certificate covers fails
//! the handshake; a connection that negotiated `acme-tls/1` is closed after the handshake.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::sync::{Arc, RwLock};
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
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::adp::adapters::Pep;
use crate::forwarded::TrustedProxies;

// CR-12, OP-159 m.3 (t)
pub mod kex;

/// Most TLS handshakes in progress at once (OP-36, PD).
pub const HANDSHAKES: usize = 256;

/// Longest a handshake may take (PD).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The client certificate chain presented on the mTLS listener, leaf first, DER (OP-155
/// m.3 (k), (m)): the handshake proved possession of the leaf's key and nothing else. Only TLS
/// that ends at access-server sets it.
#[derive(Clone, Debug)]
pub struct MtlsChain(pub Arc<[Vec<u8>]>);

/// The default port of the mTLS listener (OP-155 m.3 (m)).
pub const MTLS_PORT: u16 = 8443;

/// Most certificates a client presents on the mTLS listener (PD).
pub const MTLS_MAX_CHAIN: usize = 8;

/// Largest certificate a client presents on the mTLS listener (CR-10).
pub const MTLS_MAX_CERT: usize = 8 * 1024;

/// Request headers by which a proxy forwards a client certificate or its verification (RFC 9440
/// and the common proxy names); every listener drops them (OP-155 m.3 (k)).
pub const FORWARDED_CERT_HEADERS: &[&str] = &[
    "client-cert",
    "client-cert-chain",
    "ssl-client-cert",
    "x-client-cert",
    "x-client-dn",
    "x-client-verify",
    "x-ssl-client-cert",
    "x-ssl-client-dn",
    "x-ssl-client-i-dn",
    "x-ssl-client-s-dn",
    "x-ssl-client-verify",
    "x-forwarded-client-cert",
    "x-forwarded-tls-client-cert",
    "x-forwarded-tls-client-cert-info",
    "x-arr-clientcert",
    "x-amzn-mtls-clientcert",
    "x-amzn-mtls-clientcert-leaf",
];

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

/// Any client certificate, its possession proven by the handshake signature; trust is decided
/// by the route (OP-155 m.3 (m)).
#[derive(Debug)]
struct HandshakeProof(Arc<rustls::crypto::CryptoProvider>);

impl ClientCertVerifier for HandshakeProof {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // CR-10
        let oversized = intermediates.len() >= MTLS_MAX_CHAIN
            || core::iter::once(end_entity)
                .chain(intermediates)
                .any(|c| c.as_ref().len() > MTLS_MAX_CERT);
        if oversized {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
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
    /// A browser-facing certificate names ML-DSA (CR-12 m.5).
    #[error("certificate chain: ML-DSA is not served to browsers (CR-12 m.5)")]
    MlDsa,
}

/// Refuses a chain that names ML-DSA: public web PKI has no ML-DSA certificate, so a
/// browser-facing listener keeps classic ones (CR-12 m.5, OP-159 m.3 (t)).
fn classic(chain: &[CertificateDer<'_>]) -> Result<(), TlsError> {
    if chain.iter().any(|c| kex::names_ml_dsa(c.as_ref())) {
        return Err(TlsError::MlDsa);
    }
    Ok(())
}

/// The ALPN protocols of the public listener: HTTP, and `acme-tls/1` for TLS-ALPN-01
/// validations (RFC 8737 §6.2), which no ordinary client offers.
const PUBLIC_ALPN: [&[u8]; 3] = [
    b"h2",
    b"http/1.1",
    access_identity_domain::x509::ACME_TLS_ALPN,
];

/// A realm certificate for one custom domain: its chain (DER, leaf first) and PKCS#8 key.
pub struct DomainCert {
    /// The host.
    pub host: String,
    /// The chain, DER, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// The key, PKCS#8.
    pub key: zeroize::Zeroizing<Vec<u8>>,
}

/// An open challenge: its key authorization digest and the certificate that carries it.
type Challenge = ([u8; 32], Arc<CertifiedKey>);

/// The public listener's certificates by SNI (OP-156 m.3 (i)).
pub struct Sni {
    provider: Arc<rustls::crypto::CryptoProvider>,
    default: Arc<CertifiedKey>,
    default_leaf: CertificateDer<'static>,
    domains: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    challenges: RwLock<HashMap<String, Challenge>>,
}

impl core::fmt::Debug for Sni {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sni").finish_non_exhaustive()
    }
}

/// A certified key; `checked` also proves the key matches the leaf, which webpki cannot read
/// for a TLS-ALPN-01 certificate (its `acmeIdentifier` is critical) made with its key here.
fn certified(
    provider: &rustls::crypto::CryptoProvider,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    checked: bool,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let key = provider.key_provider.load_private_key(key)?;
    let ck = CertifiedKey::new(chain, key);
    if checked {
        ck.keys_match()?;
    }
    Ok(Arc::new(ck))
}

impl Sni {
    /// The resolver over the operator's PEM chain and key, which serves every name it covers.
    ///
    /// # Errors
    /// [`TlsError`].
    pub fn new(chain_pem: &[u8], key_pem: &[u8]) -> Result<Arc<Self>, TlsError> {
        let chain = CertificateDer::pem_slice_iter(chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Certificates(e.to_string()))?;
        let leaf = chain
            .first()
            .cloned()
            .ok_or_else(|| TlsError::Certificates("no certificate".to_owned()))?;
        // CR-12 m.5
        classic(&chain)?;
        let key =
            PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| TlsError::Key(e.to_string()))?;
        // CR-12
        let provider = Arc::new(aws_lc_rs::default_provider());
        let default = certified(&provider, chain, key, true)?;
        Ok(Arc::new(Self {
            provider,
            default,
            default_leaf: leaf,
            domains: RwLock::new(HashMap::new()),
            challenges: RwLock::new(HashMap::new()),
        }))
    }

    fn covered_by_default(&self, name: &str) -> bool {
        let Ok(server) = rustls_pki_types::ServerName::try_from(name) else {
            return false;
        };
        webpki::EndEntityCert::try_from(&self.default_leaf)
            .is_ok_and(|c| c.verify_is_valid_for_subject_name(&server).is_ok())
    }

    /// Replaces the realm certificates served: one per verified custom domain. A certificate
    /// whose key does not match its leaf is left out.
    pub fn set_domains(&self, certs: Vec<DomainCert>) {
        let mut map = HashMap::new();
        for c in certs {
            let chain: Vec<CertificateDer<'static>> =
                c.chain.into_iter().map(CertificateDer::from).collect();
            // CR-12 m.5
            if let Err(error) = classic(&chain) {
                tracing::error!(%error, "custom domain certificate refused");
                continue;
            }
            let key = PrivateKeyDer::Pkcs8(c.key.to_vec().into());
            match certified(&self.provider, chain, key, true) {
                Ok(ck) => {
                    map.insert(c.host.to_ascii_lowercase(), ck);
                }
                Err(error) => tracing::error!(%error, "custom domain certificate refused"),
            }
        }
        if let Ok(mut d) = self.domains.write() {
            *d = map;
        }
    }

    /// The custom domains served now.
    #[must_use]
    pub fn domains(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .domains
            .read()
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default();
        out.sort();
        out
    }

    /// Serves the TLS-ALPN-01 challenge certificate of `digest` for `host` (RFC 8737 §3),
    /// signed by a key made for it.
    ///
    /// # Errors
    /// [`TlsError`] when the key or certificate cannot be made.
    pub fn publish_challenge(&self, host: &str, digest: [u8; 32]) -> Result<(), TlsError> {
        let host = host.to_ascii_lowercase();
        if let Ok(c) = self.challenges.read()
            && c.get(&host).is_some_and(|(d, _)| *d == digest)
        {
            return Ok(());
        }
        let (key, pkcs8) = suiss_crypto::signer::SoftSigner::generate_p256()
            .map_err(|e| TlsError::Key(e.to_string()))?;
        let suiss_crypto::cose::PublicKey::P256(point) =
            suiss_crypto::signer::Signer::public_key(&key)
        else {
            return Err(TlsError::Key(String::from("p256")));
        };
        let mut serial = [0_u8; 16];
        serial.copy_from_slice(
            suiss_crypto::digest::sha256(&point)
                .get(..16)
                .unwrap_or(&[1; 16]),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or_default();
        let cert = access_identity_domain::x509::alpn_challenge(&key, &host, &digest, &serial, now)
            .map_err(|e| TlsError::Certificates(e.to_string()))?;
        let ck = certified(
            &self.provider,
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(pkcs8.expose().clone().into()),
            false,
        )?;
        if let Ok(mut c) = self.challenges.write() {
            c.insert(host, (digest, ck));
        }
        Ok(())
    }

    /// Stops serving the challenge of `host`.
    pub fn withdraw_challenge(&self, host: &str) {
        if let Ok(mut c) = self.challenges.write() {
            c.remove(&host.to_ascii_lowercase());
        }
    }

    /// Serves exactly the open challenges `open` (host, digest), as every node reads them.
    pub fn set_challenges(&self, open: &[(String, [u8; 32])]) {
        let keep: HashMap<String, [u8; 32]> = open.iter().cloned().collect();
        if let Ok(mut c) = self.challenges.write() {
            c.retain(|h, (d, _)| keep.get(h) == Some(d));
        }
        for (host, digest) in open {
            if let Err(error) = self.publish_challenge(host, *digest) {
                tracing::error!(%error, "TLS-ALPN-01 challenge not served");
            }
        }
    }
}

impl ResolvesServerCert for Sni {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().map(str::to_ascii_lowercase);
        let acme = hello.alpn().is_some_and(|mut protocols| {
            protocols.any(|p| p == access_identity_domain::x509::ACME_TLS_ALPN)
        });
        // RFC 8737 §3
        if acme {
            let c = self.challenges.read().ok()?;
            return c.get(&name?).map(|(_, ck)| ck.clone());
        }
        let Some(name) = name else {
            return Some(self.default.clone());
        };
        if self.covered_by_default(&name) {
            return Some(self.default.clone());
        }
        // OP-156 m.3 (i)
        self.domains.read().ok()?.get(&name).cloned()
    }
}

/// The public listener's TLS 1.3 configuration over `sni` (OP-156 m.3 (i)); with
/// `client_ca_pem` as [`server_config`].
///
/// # Errors
/// [`TlsError`].
pub fn sni_server_config(
    sni: Arc<Sni>,
    client_ca_pem: Option<&[u8]>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = sni.provider.clone();
    let build = |kx: Arc<rustls::crypto::CryptoProvider>,
                 resolver: Arc<Sni>|
     -> Result<ServerConfig, TlsError> {
        let builder = ServerConfig::builder_with_provider(kx)
            .with_protocol_versions(&[&rustls::version::TLS13])?;
        let builder = match client_ca_pem {
            None => builder.with_no_client_auth(),
            Some(pem) => builder.with_client_cert_verifier(pep_or_svid(pem, provider.clone())?),
        };
        let mut config = builder.with_cert_resolver(resolver);
        config.alpn_protocols = PUBLIC_ALPN.iter().map(|p| p.to_vec()).collect();
        // OP-36
        config.max_early_data_size = 0;
        Ok(config)
    };
    let twin = build(kex::pq_only(&provider), sni.clone())?;
    let config = Arc::new(build(provider.clone(), sni)?);
    // CR-12 m.3, OP-159 m.3 (t)
    kex::pair(&config, twin);
    Ok(config)
}

fn pep_or_svid(
    pem: &[u8],
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
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
    Ok(Arc::new(PepOrSvid(verifier)))
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
    // CR-12 m.5
    classic(&chain)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| TlsError::Key(e.to_string()))?;
    // CR-12
    let provider = Arc::new(aws_lc_rs::default_provider());
    let build = |kx: Arc<rustls::crypto::CryptoProvider>| -> Result<ServerConfig, TlsError> {
        let builder = ServerConfig::builder_with_provider(kx)
            .with_protocol_versions(&[&rustls::version::TLS13])?;
        let builder = match client_ca_pem {
            None => builder.with_no_client_auth(),
            Some(pem) => builder.with_client_cert_verifier(pep_or_svid(pem, provider.clone())?),
        };
        let mut config = builder.with_single_cert(chain.clone(), key.clone_key())?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // OP-36
        config.max_early_data_size = 0;
        Ok(config)
    };
    let config = Arc::new(build(provider.clone())?);
    // CR-12 m.3, OP-159 m.3 (t)
    kex::pair(&config, build(kex::pq_only(&provider))?);
    Ok(config)
}

/// The mTLS listener's TLS 1.3 configuration for a PEM chain and key (OP-155 m.3 (m)): it asks
/// every client for a certificate, requires none, and accepts any chain whose possession the
/// handshake proves.
///
/// # Errors
/// [`TlsError`].
pub fn mtls_server_config(chain_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, TlsError> {
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Certificates(e.to_string()))?;
    if chain.is_empty() {
        return Err(TlsError::Certificates("no certificate".to_owned()));
    }
    // CR-12 m.5
    classic(&chain)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| TlsError::Key(e.to_string()))?;
    // CR-12
    let provider = Arc::new(aws_lc_rs::default_provider());
    let build = |kx: Arc<rustls::crypto::CryptoProvider>| -> Result<ServerConfig, TlsError> {
        let mut config = ServerConfig::builder_with_provider(kx)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(Arc::new(HandshakeProof(provider.clone())))
            .with_single_cert(chain.clone(), key.clone_key())?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // OP-36
        config.max_early_data_size = 0;
        Ok(config)
    };
    let config = Arc::new(build(provider.clone())?);
    // CR-12 m.3, OP-159 m.3 (t)
    kex::pair(&config, build(kex::pq_only(&provider))?);
    Ok(config)
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
    serve_behind(listener, config, app, TrustedProxies::default(), shutdown).await
}

/// [`serve`] behind `proxies`: a request from one of them carries the client address its
/// `X-Forwarded-For` names as [`crate::login::Peer`] (§17.9.6, OP-158 m.3 (v)).
///
/// # Errors
/// The listener's accept error.
pub async fn serve_behind(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    proxies: TrustedProxies,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    serve_as(
        listener,
        config,
        app,
        (Listener::Public, Arc::new(proxies)),
        shutdown,
    )
    .await
}

/// Serves `app` on the mTLS listener until `shutdown` resolves (OP-155 m.3 (m)): each request
/// carries the connection's [`MtlsChain`] when one was presented, and its `Host` port is that
/// of the public listener (`public_port`; none for 443), so the realm resolves as on the public
/// listener.
///
/// # Errors
/// The listener's accept error.
pub async fn serve_mtls(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    public_port: Option<u16>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    serve_as(
        listener,
        config,
        app,
        (
            Listener::Mtls { public_port },
            Arc::new(TrustedProxies::default()),
        ),
        shutdown,
    )
    .await
}

/// Which listener a connection reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Listener {
    /// The public, management or internal listener.
    Public,
    /// The mTLS listener.
    Mtls {
        /// The public listener's port; none for 443.
        public_port: Option<u16>,
    },
}

/// The `Host` value on the public listener for `host` reached on the mTLS listener.
#[must_use]
pub fn public_authority(host: &str, public_port: Option<u16>) -> String {
    let name = match host.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty()
                && !port.is_empty()
                && port.bytes().all(|c| c.is_ascii_digit())
                && (!name.contains(':') || name.ends_with(']')) =>
        {
            name
        }
        _ => host,
    };
    match public_port {
        Some(p) => format!("{name}:{p}"),
        None => String::from(name),
    }
}

/// Drops forwarded certificate headers (OP-155 m.3 (k)), names the client address (from
/// `X-Forwarded-For` only behind a trusted proxy, §17.9.6) and drops that header, and, on the
/// mTLS listener, gives the request the public listener's `Host`.
fn inbound(
    mut req: axum::extract::Request,
    listener: Listener,
    peer: std::net::IpAddr,
    proxies: &TrustedProxies,
) -> axum::extract::Request {
    for name in FORWARDED_CERT_HEADERS {
        req.headers_mut().remove(*name);
    }
    let client = proxies.client(peer, req.headers());
    req.headers_mut().remove(crate::forwarded::X_FORWARDED_FOR);
    req.extensions_mut().insert(crate::login::Peer(client));
    if let Listener::Mtls { public_port } = listener {
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(String::from)
            .or_else(|| req.uri().authority().map(|a| a.as_str().to_owned()));
        if let Some(h) = host
            && let Ok(v) = axum::http::HeaderValue::from_str(&public_authority(&h, public_port))
        {
            req.headers_mut().insert(axum::http::header::HOST, v);
        }
    }
    req
}

async fn serve_as(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    (mode, proxies): (Listener, Arc<TrustedProxies>),
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let handshakes = Arc::new(Semaphore::new(HANDSHAKES));
    let label = match mode {
        Listener::Public => "public",
        Listener::Mtls { .. } => "mtls",
    };
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
        let config = config.clone();
        let app = app.clone();
        let proxies = proxies.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let capture = kex::Capture::default();
            let handshake = handshake(tcp, &config, capture.clone());
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(error)) => {
                    // CR-12 m.3, OP-159 m.3 (t)
                    kex::count(label, None, capture.offer().as_ref(), kex::Outcome::Failed);
                    tracing::debug!(%peer, %error, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    kex::count(label, None, capture.offer().as_ref(), kex::Outcome::Failed);
                    tracing::debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            drop(permit);
            let mut tls = tls;
            tls.get_mut().0.stop();
            // CR-12 m.3, OP-159 m.3 (t)
            {
                let conn = tls.get_ref().1;
                let outcome = match conn.handshake_kind() {
                    Some(rustls::HandshakeKind::FullWithHelloRetryRequest) => kex::Outcome::Retry,
                    _ => kex::Outcome::Ok,
                };
                let group = conn
                    .negotiated_key_exchange_group()
                    .map(|g| u16::from(g.name()));
                kex::count(label, group, None, outcome);
            }
            // RFC 8737 §3
            if tls.get_ref().1.alpn_protocol() == Some(access_identity_domain::x509::ACME_TLS_ALPN)
            {
                return;
            }
            let ip = peer.ip();
            let app = app.layer(tower::util::MapRequestLayer::new(move |r| {
                inbound(r, mode, ip, &proxies)
            }));
            let app = if matches!(mode, Listener::Mtls { .. }) {
                // OP-155 m.3 (m)
                match mtls_chain(tls.get_ref().1) {
                    Some(chain) => app.layer(Extension(chain)),
                    None => app,
                }
            } else {
                with_verified(app, tls.get_ref().1)
            };
            let service = TowerToHyperService::new(app);
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

/// One TLS handshake on `tcp`: the `ClientHello` is read first, then the handshake finishes with
/// the post-quantum twin of `config` when the client lists the hybrid group (CR-12 m.2, m.3).
async fn handshake(
    tcp: tokio::net::TcpStream,
    config: &Arc<ServerConfig>,
    capture: kex::Capture,
) -> io::Result<tokio_rustls::server::TlsStream<kex::Recording<tokio::net::TcpStream>>> {
    let io = kex::Recording::new(tcp, capture);
    let start =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io).await?;
    let config = kex::for_hello(config, start.client_hello().named_groups());
    start.into_stream(config).await
}

/// The chain a client presented on the mTLS listener.
fn mtls_chain(conn: &rustls::ServerConnection) -> Option<MtlsChain> {
    let chain = conn.peer_certificates()?;
    chain.first()?;
    Some(MtlsChain(
        chain.iter().map(|c| c.as_ref().to_vec()).collect(),
    ))
}

/// `app` with what the verified client certificate of a public listener connection names: an
/// X.509-SVID chain, a gateway or a PEP.
fn with_verified(app: Router, conn: &rustls::ServerConnection) -> Router {
    let app = match svid_chain(conn) {
        Some(chain) => app.layer(Extension(chain)),
        None => app,
    };
    // OP-155 m.3 (c)
    let app = match gateway(conn) {
        Some(gateway) => app.layer(Extension(gateway)),
        None => app,
    };
    match pep(conn) {
        Some(pep) => app.layer(Extension(pep)),
        None => app,
    }
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
