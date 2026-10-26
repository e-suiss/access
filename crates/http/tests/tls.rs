//! CR-12, OP-36: the TLS listener accepts TLS 1.3 with the hybrid key exchange and nothing else.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;

use access_http::tls::{TlsError, serve, server_config};
use axum::Router;
use axum::routing::get;
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
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let config = server_config(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new().route("/", get(|| async { "ok" }));
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
        server_config(b"", key.as_bytes()),
        Err(TlsError::Certificates(_))
    ));
    assert!(matches!(
        server_config(cert.cert.pem().as_bytes(), b"not a key"),
        Err(TlsError::Key(_))
    ));
    let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    assert!(
        server_config(
            cert.cert.pem().as_bytes(),
            other.signing_key.serialize_pem().as_bytes()
        )
        .is_err()
    );
}
