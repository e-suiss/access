//! The `RadSec` listener (RFC 6614 with RFC 9765 RADIUS/1.1; §10.6.5, IDP-18, OP-155 m.3 (f)).
//! TLS 1.3 only, ALPN `radius/1.1` only, and a client certificate is required: its SHA-256 must
//! be registered with this gateway (`idp.gateway.radius_client_register`), or the connection is
//! closed unanswered. There is no UDP listener: RADIUS over UDP is never answered.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_edge_core::channel::ChannelError;
use access_edge_core::governor::Governor;
use access_edge_core::{EdgeCore, EdgeError};
use access_internal_api::edge::Call;
use access_internal_api::edge::radius::{Authenticate, Authenticated, Mechanism};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, aws_lc_rs, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::packet::{
    self, ACCESS_ACCEPT, ACCESS_REJECT, HEADER, MAX_PACKET, Request, Verdict, answer,
};

/// The only application protocol offered (RFC 9765).
pub const ALPN: &[u8] = b"radius/1.1";

/// Largest client certificate.
pub const MAX_CERT: usize = 8 * 1024;

/// Most certificates of a client chain.
pub const MAX_CHAIN: usize = 8;

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
struct RegisteredClient(Arc<CryptoProvider>);

impl ClientCertVerifier for RegisteredClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
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

/// The TLS acceptor over the gateway's certificate chain and key, PEM. The handshake proves the
/// client holds its certificate's key; access-server decides whether that certificate is a
/// registered client.
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
    let mut config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(RegisteredClient(provider)))
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// What the listener serves.
#[derive(Clone)]
pub struct Listener {
    /// The edge core every connection uses.
    pub core: Arc<EdgeCore>,
    /// The TLS acceptor.
    pub tls: TlsAcceptor,
    /// Connections per second and burst per client address.
    pub governor: Arc<Governor>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Serves `RadSec` on `listener` until it fails.
pub async fn radsec(listener: TcpListener, l: Listener) {
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            continue;
        };
        let key = match peer.ip() {
            std::net::IpAddr::V4(v) => v.octets().to_vec(),
            std::net::IpAddr::V6(v) => v.octets().to_vec(),
        };
        if !l.governor.admit(&key, now_ms()) {
            continue;
        }
        let l = l.clone();
        tokio::spawn(async move {
            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE, l.tls.accept(tcp)).await else {
                return;
            };
            let (_, conn) = tls.get_ref();
            if conn.alpn_protocol() != Some(ALPN) {
                return;
            }
            let Some(leaf) = conn.peer_certificates().and_then(<[_]>::first) else {
                return;
            };
            let client = suiss_crypto::digest::sha256(leaf.as_ref());
            let session = Session {
                core: &l.core,
                client,
            };
            if !session.registered().await {
                return;
            }
            let mut tls = tls;
            session.serve(&mut tls).await;
        });
    }
}

/// One `RadSec` connection of a registered client.
pub struct Session<'a> {
    core: &'a EdgeCore,
    client: [u8; 32],
}

impl Session<'_> {
    /// Writes the audit event `name` as the realm's log names it (`edge.<event>.<outcome>`).
    async fn audit(&self, name: &str) {
        let Some((event, outcome)) = name
            .strip_prefix("edge.")
            .and_then(|rest| rest.rsplit_once('.'))
        else {
            return;
        };
        if self.core.audit(event, outcome, None).await.is_err() {
            crate::log("audit unavailable");
        }
    }

    async fn ask(
        &self,
        mechanism: Mechanism,
        pap: Option<(String, Vec<u8>)>,
    ) -> Result<Authenticated, EdgeError> {
        let (name, secret) = pap.map_or((None, None), |(n, s)| (Some(n), Some(s)));
        let q = Authenticate {
            realm: String::from(self.core.realm(None)?),
            mechanism,
            client: self.client,
            name,
            secret,
        };
        let body = self.core.raw(Call::Authenticate, &q.encode()).await?;
        Authenticated::decode(&body).map_err(|_| EdgeError::Malformed)
    }

    /// Whether access-server knows the client; an unregistered client is audited and closed.
    async fn registered(&self) -> bool {
        match self.ask(Mechanism::Client, None).await {
            Ok(_) => true,
            Err(EdgeError::Channel(ChannelError::Refused { code, .. }))
                if code == "edge-radius-client" =>
            {
                self.audit("edge.radius.client.refused").await;
                false
            }
            Err(_) => false,
        }
    }

    /// The answer to one packet; `None` sends nothing.
    pub async fn handle(&self, packet: &[u8]) -> Option<[u8; HEADER]> {
        let Ok(request) = Request::parse(packet) else {
            self.audit("edge.radius.packet.refused").await;
            return None;
        };
        let token = request.token;
        match request.verdict() {
            Verdict::Status => Some(answer(ACCESS_ACCEPT, token)),
            Verdict::Drop => {
                self.audit("edge.radius.packet.refused").await;
                None
            }
            Verdict::MsChap => {
                self.audit("edge.radius.mschap.refused").await;
                Some(answer(ACCESS_REJECT, token))
            }
            Verdict::OtherMethod => {
                self.audit("edge.radius.method.refused").await;
                Some(answer(ACCESS_REJECT, token))
            }
            Verdict::Pap { name, password } => Some(self.pap(name, password, token).await),
        }
    }

    async fn pap(&self, name: String, password: Vec<u8>, token: [u8; 4]) -> [u8; HEADER] {
        let reject = answer(ACCESS_REJECT, token);
        let Ok(Authenticated {
            subject: Some(subject),
        }) = self.ask(Mechanism::Pap, Some((name, password))).await
        else {
            return reject;
        };
        // IDP-18, P-ID-5
        match self
            .core
            .issue(None, subject, "password", now_ms(), Some(self.client))
            .await
        {
            Ok(_) => answer(ACCESS_ACCEPT, token),
            Err(_) => reject,
        }
    }

    /// Serves packets until the connection closes, fails or stays silent.
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(&self, s: &mut S) {
        let mut buf = vec![0_u8; MAX_PACKET];
        loop {
            let Some(head) = buf.get_mut(..4) else {
                return;
            };
            if !matches!(
                tokio::time::timeout(IDLE, s.read_exact(head)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let Some(n) = buf
                .get(..4)
                .and_then(|h| <[u8; 4]>::try_from(h).ok())
                .and_then(|h| packet::length(h).ok())
            else {
                self.audit("edge.radius.packet.refused").await;
                return;
            };
            let Some(body) = buf.get_mut(4..n) else {
                return;
            };
            if !matches!(
                tokio::time::timeout(IDLE, s.read_exact(body)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let Some(packet) = buf.get(..n) else {
                return;
            };
            if let Some(out) = self.handle(packet).await
                && (s.write_all(&out).await.is_err() || s.flush().await.is_err())
            {
                return;
            }
        }
    }
}
