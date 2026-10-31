//! CR-12, OP-36: the TLS listener accepts TLS 1.3 with the hybrid key exchange and nothing else.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;

use access_http::adp::adapters::Pep;
use access_http::tls::{TlsError, serve, server_config};
use axum::routing::get;
use axum::{Extension, Router};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

struct Server {
    addr: std::net::SocketAddr,
    roots: RootCertStore,
    stop: tokio::sync::oneshot::Sender<()>,
}

async fn start() -> Server {
    start_with(None).await
}

async fn start_with(client_ca: Option<&[u8]>) -> Server {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let config = server_config(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
        client_ca,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new().route("/", get(|| async { "ok" })).route(
        "/pep",
        get(|pep: Option<Extension<Pep>>| async move {
            pep.map_or_else(|| "none".to_owned(), |Extension(Pep(p))| p)
        }),
    );
    tokio::spawn(serve(listener, config, app, async {
        let _ = stopped.await;
    }));
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    Server { addr, roots, stop }
}

fn client(
    roots: RootCertStore,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TlsConnector {
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

// CR-12: TLS 1.3 with X25519MLKEM768, and the application answers over it
#[tokio::test]
async fn tls_13_with_the_hybrid_group() {
    let s = start().await;
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let mut tls = client(s.roots.clone(), &[&rustls::version::TLS13])
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let (_, conn) = tls.get_ref();
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        conn.negotiated_key_exchange_group().unwrap().name(),
        rustls::NamedGroup::X25519MLKEM768
    );
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("ok"), "{text}");
    let _ = s.stop.send(());
}

// CR-12: a client that offers only TLS 1.2 gets no connection
#[tokio::test]
async fn tls_12_is_refused() {
    let s = start().await;
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let result = client(s.roots.clone(), &[&rustls::version::TLS12])
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await;
    assert!(result.is_err());
    let _ = s.stop.send(());
}

// OP-52: an unusable chain or key stops the server from starting
#[test]
fn bad_pem_is_refused() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let key = cert.signing_key.serialize_pem();
    assert!(matches!(
        server_config(b"", key.as_bytes(), None),
        Err(TlsError::Certificates(_))
    ));
    assert!(matches!(
        server_config(cert.cert.pem().as_bytes(), b"not a key", None),
        Err(TlsError::Key(_))
    ));
    let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    assert!(
        server_config(
            cert.cert.pem().as_bytes(),
            other.signing_key.serialize_pem().as_bytes(),
            None
        )
        .is_err()
    );
}

struct Ca {
    pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

fn ca() -> Ca {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let pem = params.self_signed(&key).unwrap().pem();
    Ca {
        pem,
        issuer: rcgen::Issuer::new(params, key),
    }
}

fn client_cert(ca: &Ca) -> (rustls::pki_types::CertificateDer<'static>, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::new(vec!["pep.example".to_owned()]).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    (cert.der().clone(), key)
}

async fn get_pep(
    s: &Server,
    client: Option<(&rustls::pki_types::CertificateDer<'static>, &rcgen::KeyPair)>,
) -> Option<String> {
    let builder = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(s.roots.clone());
    let config = match client {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![cert.clone()],
                rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap(),
    };
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .ok()?;
    tls.write_all(b"GET /pep HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .ok()?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.ok()?;
    let text = String::from_utf8_lossy(&response).into_owned();
    Some(text.rsplit("\r\n").next().unwrap().to_owned())
}

// OP-141 m.18 (b), L1-ADP-2: a verified client certificate names the PEP by its thumbprint;
// no certificate is still a connection, without a PEP; a foreign one is refused
#[tokio::test]
async fn a_client_certificate_names_the_pep() {
    let trusted = ca();
    let s = start_with(Some(trusted.pem.as_bytes())).await;
    let (cert, key) = client_cert(&trusted);
    let want = access_kernel::json::b64url_encode(&suiss_crypto::digest::sha256(cert.as_ref()));
    assert_eq!(get_pep(&s, Some((&cert, &key))).await, Some(want));
    assert_eq!(get_pep(&s, None).await.as_deref(), Some("none"));
    let (foreign, foreign_key) = client_cert(&ca());
    assert_eq!(get_pep(&s, Some((&foreign, &foreign_key))).await, None);
    let _ = s.stop.send(());
}

// OP-52: an unusable client CA bundle stops the server from starting
#[test]
fn bad_client_ca_is_refused() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let key = cert.signing_key.serialize_pem();
    assert!(matches!(
        server_config(cert.cert.pem().as_bytes(), key.as_bytes(), Some(b"")),
        Err(TlsError::ClientCa(_))
    ));
}
