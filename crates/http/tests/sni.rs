//! OP-156 m.3 (i), RFC 8737: the public listener picks its certificate by SNI. The operator's
//! certificate serves the names it covers, a realm's certificate its verified custom domain, and
//! the TLS-ALPN-01 challenge certificate only a client offering `acme-tls/1`; any other name
//! fails the handshake.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use access_http::tls::{DomainCert, Sni, serve, sni_server_config};
use axum::Router;
use axum::routing::get;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

struct Ca {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    der: CertificateDer<'static>,
}

fn ca() -> Ca {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let key = rcgen::KeyPair::generate().unwrap();
    let der = p.self_signed(&key).unwrap().der().clone();
    Ca {
        issuer: rcgen::Issuer::new(p, key),
        der,
    }
}

fn leaf(ca: &Ca, names: &[&str]) -> (String, String, Vec<u8>, Vec<u8>) {
    let p =
        rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
            .unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca.issuer).unwrap();
    (
        cert.pem(),
        key.serialize_pem(),
        cert.der().to_vec(),
        key.serialize_der(),
    )
}

async fn start(sni: Arc<Sni>) -> SocketAddr {
    let config = sni_server_config(sni, None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/", get(|| async { "ok" }));
    tokio::spawn(serve(listener, config, app, std::future::pending()));
    addr
}

fn roots(ca: &Ca) -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(ca.der.clone()).unwrap();
    r
}

async fn get_root(addr: SocketAddr, host: &str, roots: RootCertStore) -> Option<String> {
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
        .await
        .ok()?;
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await.unwrap();
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Accepts any certificate whose key signed the handshake, as an ACME validation does.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let point = access_identity_domain::x509::read_leaf(cert.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?
            .public_point;
        let spki = access_identity_domain::der::p256_spki(&point);
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &rustls::pki_types::SubjectPublicKeyInfoDer::from(spki),
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The leaf a TLS-ALPN-01 validation of `host` sees, and whether the server then closed.
async fn alpn(addr: SocketAddr, host: &str) -> Option<(Vec<u8>, bool)> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
        .await
        .ok()?;
    let (_, conn) = tls.get_ref();
    assert_eq!(conn.alpn_protocol(), Some(b"acme-tls/1".as_slice()));
    let cert = conn.peer_certificates()?.first()?.as_ref().to_vec();
    let mut buf = [0_u8; 16];
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    );
    Some((cert, closed))
}

// OP-156 m.3 (i)
#[tokio::test]
async fn the_operator_certificate_serves_its_names_and_an_unknown_name_is_refused() {
    let operator = ca();
    let (chain, key, _, _) = leaf(&operator, &["*.suiss.test", "suiss.test"]);
    let sni = Sni::new(chain.as_bytes(), key.as_bytes()).unwrap();
    let addr = start(sni.clone()).await;
    let ok = get_root(addr, "acme.suiss.test", roots(&operator))
        .await
        .unwrap();
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(
        get_root(addr, "login.acme.example", roots(&operator))
            .await
            .is_none()
    );

    let customer = ca();
    let (_, _, der, pkcs8) = leaf(&customer, &["login.acme.example"]);
    sni.set_domains(vec![DomainCert {
        host: String::from("login.acme.example"),
        chain: vec![der],
        key: zeroize::Zeroizing::new(pkcs8),
    }]);
    assert_eq!(sni.domains(), ["login.acme.example"]);
    let ok = get_root(addr, "login.acme.example", roots(&customer))
        .await
        .unwrap();
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(
        get_root(addr, "other.acme.example", roots(&customer))
            .await
            .is_none()
    );
    sni.set_domains(Vec::new());
    assert!(
        get_root(addr, "login.acme.example", roots(&customer))
            .await
            .is_none()
    );
}

// RFC 8737 §3, OP-156 m.3 (i)
#[tokio::test]
async fn only_an_acme_tls_client_gets_the_challenge_certificate_and_the_connection_closes() {
    let operator = ca();
    let (chain, key, _, _) = leaf(&operator, &["*.suiss.test"]);
    let sni = Sni::new(chain.as_bytes(), key.as_bytes()).unwrap();
    let addr = start(sni.clone()).await;
    assert!(alpn(addr, "login.acme.example").await.is_none());
    let digest = [0x42; 32];
    sni.set_challenges(&[(String::from("login.acme.example"), digest)]);
    let (cert, closed) = alpn(addr, "login.acme.example").await.unwrap();
    let read = access_identity_domain::x509::read_leaf(&cert).unwrap();
    assert_eq!(read.dns_names, ["login.acme.example"]);
    assert_eq!(read.acme_identifier, Some(digest));
    assert!(closed);
    assert!(
        get_root(addr, "login.acme.example", roots(&operator))
            .await
            .is_none()
    );
    sni.set_challenges(&[]);
    assert!(alpn(addr, "login.acme.example").await.is_none());
}
