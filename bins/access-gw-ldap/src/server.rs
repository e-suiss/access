//! The LDAP listeners (§10.6.3, OP-155 m.3 (n)): LDAPS by default; a cleartext listener that
//! offers `StartTLS` only when the operator turns it on. TLS 1.3 only (CR-12). A client
//! certificate is asked for and never required; the handshake proves the client holds its key,
//! and access-server decides whether the certificate signs anyone in (SASL EXTERNAL).

use std::sync::Arc;
use std::time::Duration;

use access_edge_core::EdgeCore;
use access_edge_core::governor::Governor;
use bytes::BytesMut;
use ldap3_proto::proto::LdapMsg;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, aws_lc_rs, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Decoder as _, Encoder as _};

use crate::ber::{self, BerError};
use crate::session::{Next, Session};

/// Most certificates of a client chain.
pub const MAX_CHAIN: usize = 8;

/// Largest client certificate.
pub const MAX_CERT: usize = 8 * 1024;

/// Longest a connection may stay silent.
pub const IDLE: Duration = Duration::from_secs(300);

/// Longest a TLS handshake may take.
pub const HANDSHAKE: Duration = Duration::from_secs(10);

/// Why the TLS configuration was refused; the gateway does not start.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The PEM input holds no usable certificate or key.
    #[error("{0}")]
    Pem(&'static str),
    /// rustls refused the configuration.
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
}

#[derive(Debug)]
struct AnyClient(Arc<CryptoProvider>);

impl ClientCertVerifier for AnyClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let too_big = end_entity.len() > MAX_CERT
            || intermediates.len() >= MAX_CHAIN
            || intermediates.iter().any(|c| c.len() > MAX_CERT);
        if too_big {
            return Err(rustls::Error::General(String::from(
                "client chain too large",
            )));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The TLS acceptor over the gateway's certificate chain and key, PEM.
///
/// # Errors
/// [`TlsError`].
pub fn acceptor(chain_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor, TlsError> {
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::Pem("certificate chain"))?;
    if chain.is_empty() {
        return Err(TlsError::Pem("no server certificate"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsError::Pem("private key"))?;
    let provider = Arc::new(aws_lc_rs::default_provider());
    // CR-12
    let config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AnyClient(provider)))
        .with_single_cert(chain, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// What one listener serves.
#[derive(Clone)]
pub struct Listener {
    /// The edge core every connection uses.
    pub core: Arc<EdgeCore>,
    /// The TLS acceptor.
    pub tls: TlsAcceptor,
    /// Connections per second and burst per client address.
    pub governor: Arc<Governor>,
}

/// Serves LDAPS on `listener` until it fails.
pub async fn ldaps(listener: TcpListener, l: Listener) {
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            continue;
        };
        if !admitted(&l, peer.ip()) {
            continue;
        }
        let l = l.clone();
        tokio::spawn(async move {
            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE, l.tls.accept(tcp)).await else {
                return;
            };
            let chain = chain_of(tls.get_ref().1.peer_certificates());
            let mut session = Session::new(&l.core, false, true, chain);
            let mut buf = BytesMut::new();
            let mut tls = tls;
            let _ = serve(&mut tls, &mut session, &mut buf).await;
        });
    }
}

/// Serves cleartext LDAP that offers `StartTLS` on `listener` until it fails.
pub async fn starttls(listener: TcpListener, l: Listener) {
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            continue;
        };
        if !admitted(&l, peer.ip()) {
            continue;
        }
        let l = l.clone();
        tokio::spawn(async move {
            let mut tcp = tcp;
            let mut session = Session::new(&l.core, true, false, Vec::new());
            let mut buf = BytesMut::new();
            if serve(&mut tcp, &mut session, &mut buf).await != Next::StartTls || !buf.is_empty() {
                return;
            }
            let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE, l.tls.accept(tcp)).await else {
                return;
            };
            session.secured(chain_of(tls.get_ref().1.peer_certificates()));
            let _ = serve(&mut tls, &mut session, &mut buf).await;
        });
    }
}

fn admitted(l: &Listener, ip: std::net::IpAddr) -> bool {
    let key = match ip {
        std::net::IpAddr::V4(v) => v.octets().to_vec(),
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    l.governor.admit(&key, now)
}

fn chain_of(certs: Option<&[CertificateDer<'_>]>) -> Vec<Vec<u8>> {
    certs
        .unwrap_or_default()
        .iter()
        .take(MAX_CHAIN)
        .map(|c| c.as_ref().to_vec())
        .collect()
}

/// Reads one message: the header first, then exactly its body, then the BER walk, then the
/// codec. `None` at a clean end of stream.
async fn read<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut BytesMut,
) -> Result<Option<LdapMsg>, BerError> {
    let mut chunk = [0_u8; 4096];
    let total = loop {
        if let Some(n) = ber::frame_len(buf)? {
            break n;
        }
        match tokio::time::timeout(IDLE, s.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => return Ok(None),
            Ok(Ok(n)) => buf.extend_from_slice(chunk.get(..n).ok_or(BerError::Malformed)?),
            Ok(Err(_)) => return Err(BerError::Malformed),
        }
    };
    while buf.len() < total {
        let want = total.saturating_sub(buf.len()).min(chunk.len());
        let into = chunk.get_mut(..want).ok_or(BerError::Malformed)?;
        match tokio::time::timeout(IDLE, s.read(into)).await {
            Ok(Ok(0)) | Err(_) => return Ok(None),
            Ok(Ok(n)) => buf.extend_from_slice(chunk.get(..n).ok_or(BerError::Malformed)?),
            Ok(Err(_)) => return Err(BerError::Malformed),
        }
    }
    let mut one = buf.split_to(total);
    ber::check(&one)?;
    let mut codec = ldap3_proto::LdapCodec::new(Some(ber::MAX_MESSAGE), Some(ber::MAX_DEPTH));
    match codec.decode(&mut one) {
        Ok(Some(msg)) => Ok(Some(msg)),
        _ => Err(BerError::Malformed),
    }
}

async fn write<S: AsyncWrite + Unpin>(s: &mut S, msgs: Vec<LdapMsg>) -> bool {
    let mut codec = ldap3_proto::LdapCodec::default();
    let mut out = BytesMut::new();
    for m in msgs {
        if codec.encode(m, &mut out).is_err() {
            return false;
        }
    }
    s.write_all(&out).await.is_ok() && s.flush().await.is_ok()
}

/// Serves one connection until it closes, fails or asks for `StartTLS`.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    session: &mut Session<'_>,
    buf: &mut BytesMut,
) -> Next {
    loop {
        let msg = match read(s, buf).await {
            Ok(Some(m)) => m,
            Ok(None) => return Next::Close,
            Err(_) => {
                session.refused_ber().await;
                return Next::Close;
            }
        };
        let (answers, next) = session.handle(msg).await;
        if !write(s, answers).await {
            return Next::Close;
        }
        if next != Next::Continue {
            return next;
        }
    }
}
