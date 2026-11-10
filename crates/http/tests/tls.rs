//! CR-12, OP-36: the TLS listener accepts TLS 1.3 with the hybrid key exchange and nothing else.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;

use access_http::adp::adapters::Pep;
use access_http::tls::{ClientChain, TlsError, serve, server_config};
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
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .route(
            "/pep",
            get(|pep: Option<Extension<Pep>>| async move {
                pep.map_or_else(|| "none".to_owned(), |Extension(Pep(p))| p)
            }),
        )
        .route(
            "/chain",
            get(|chain: Option<Extension<ClientChain>>| async move {
                chain.map_or_else(|| "none".to_owned(), |Extension(c)| c.0.len().to_string())
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

// CR-12
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

// CR-12
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

// OP-52
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
    fetch(s, client, "/pep").await
}

async fn fetch(
    s: &Server,
    client: Option<(&rustls::pki_types::CertificateDer<'static>, &rcgen::KeyPair)>,
    path: &str,
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
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .ok()?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.ok()?;
    let text = String::from_utf8_lossy(&response).into_owned();
    Some(text.rsplit("\r\n").next().unwrap().to_owned())
}

// OP-141 m.18 (b), L1-ADP-2
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

// OP-52
#[test]
fn bad_client_ca_is_refused() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let key = cert.signing_key.serialize_pem();
    assert!(matches!(
        server_config(cert.cert.pem().as_bytes(), key.as_bytes(), Some(b"")),
        Err(TlsError::ClientCa(_))
    ));
}

fn svid(ca: &Ca, uri: &str) -> (rustls::pki_types::CertificateDer<'static>, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    (cert.der().clone(), key)
}

// OP-154 m.3 (r), §11.15, AG-30, OP-141 m.18 (b), Ek B 4133, 4447
#[tokio::test]
async fn an_x509_svid_reaches_the_authorization_server_and_names_no_pep() {
    let operator = ca();
    let s = start_with(Some(operator.pem.as_bytes())).await;
    let trust_domain = ca();
    let (cert, key) = svid(&trust_domain, "spiffe://acme.example/agent/mail/w1");
    assert_eq!(
        fetch(&s, Some((&cert, &key)), "/chain").await.as_deref(),
        Some("1")
    );
    assert_eq!(
        fetch(&s, Some((&cert, &key)), "/pep").await.as_deref(),
        Some("none")
    );
    let (pep, pep_key) = client_cert(&operator);
    assert_eq!(
        fetch(&s, Some((&pep, &pep_key)), "/chain").await.as_deref(),
        Some("none")
    );
    let (two, two_key) = {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![
            rcgen::SanType::URI("spiffe://acme.example/a".try_into().unwrap()),
            rcgen::SanType::URI("spiffe://acme.example/b".try_into().unwrap()),
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let k = rcgen::KeyPair::generate().unwrap();
        (
            params
                .signed_by(&k, &trust_domain.issuer)
                .unwrap()
                .der()
                .clone(),
            k,
        )
    };
    assert_eq!(fetch(&s, Some((&two, &two_key)), "/chain").await, None);
    let _ = s.stop.send(());
}

async fn start_mtls(public_port: Option<u16>) -> Server {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let config = access_http::tls::mtls_server_config(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(access_http::tls::serve_mtls(
        listener,
        config,
        echo(),
        public_port,
        async {
            let _ = stopped.await;
        },
    ));
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    Server { addr, roots, stop }
}

fn echo() -> Router {
    Router::new()
        .route(
            "/mtls",
            get(
                |chain: Option<Extension<access_http::tls::MtlsChain>>| async move {
                    chain.map_or_else(|| "none".to_owned(), |Extension(c)| c.0.len().to_string())
                },
            ),
        )
        .route(
            "/pep",
            get(|pep: Option<Extension<Pep>>| async move {
                pep.map_or_else(|| "none".to_owned(), |Extension(Pep(p))| p)
            }),
        )
        .route(
            "/host",
            get(|h: axum::http::HeaderMap| async move {
                h.get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("none")
                    .to_owned()
            }),
        )
        .route(
            "/forwarded",
            get(|h: axum::http::HeaderMap| async move {
                access_http::tls::FORWARDED_CERT_HEADERS
                    .iter()
                    .filter(|n| h.contains_key(**n))
                    .count()
                    .to_string()
            }),
        )
}

async fn request(
    s: &Server,
    client: Option<(&rustls::pki_types::CertificateDer<'static>, &rcgen::KeyPair)>,
    head: &str,
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
    tls.write_all(head.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.ok()?;
    let text = String::from_utf8_lossy(&response).into_owned();
    Some(text.rsplit("\r\n").next().unwrap().to_owned())
}

// OP-155 m.3 (m), §10.2.5, Ek B 4673
#[tokio::test]
async fn the_mtls_listener_asks_for_any_certificate_and_names_no_pep() {
    let s = start_mtls(None).await;
    let (cert, key) = client_cert(&ca());
    let get = |p: &str| format!("GET {p} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(
        request(&s, Some((&cert, &key)), &get("/mtls"))
            .await
            .as_deref(),
        Some("1")
    );
    assert_eq!(
        request(&s, Some((&cert, &key)), &get("/pep"))
            .await
            .as_deref(),
        Some("none")
    );
    assert_eq!(
        request(&s, None, &get("/mtls")).await.as_deref(),
        Some("none")
    );
    let _ = s.stop.send(());
}

// OP-155 m.3 (m), §17.9.6
#[tokio::test]
async fn the_mtls_listener_gives_the_request_the_public_host() {
    let s = start_mtls(None).await;
    let head = "GET /host HTTP/1.1\r\nHost: acme.example:8443\r\nConnection: close\r\n\r\n";
    assert_eq!(
        request(&s, None, head).await.as_deref(),
        Some("acme.example")
    );
    let _ = s.stop.send(());
    let s = start_mtls(Some(4443)).await;
    assert_eq!(
        request(&s, None, head).await.as_deref(),
        Some("acme.example:4443")
    );
    let _ = s.stop.send(());
    assert_eq!(
        access_http::tls::public_authority("[::1]:8443", None),
        "[::1]"
    );
    assert_eq!(
        access_http::tls::public_authority("acme.example", Some(8080)),
        "acme.example:8080"
    );
}

// OP-155 m.3 (k)
#[tokio::test]
async fn a_forwarded_certificate_header_never_reaches_a_route() {
    let forwarded: String = access_http::tls::FORWARDED_CERT_HEADERS
        .iter()
        .map(|n| format!("{n}: MIIB\r\n"))
        .collect();
    let head = format!(
        "GET /forwarded HTTP/1.1\r\nHost: localhost\r\n{forwarded}Connection: close\r\n\r\n"
    );
    let s = start_mtls(None).await;
    assert_eq!(request(&s, None, &head).await.as_deref(), Some("0"));
    let _ = s.stop.send(());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let config = server_config(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
        None,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve(listener, config, echo(), async {
        let _ = stopped.await;
    }));
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let public = Server { addr, roots, stop };
    assert_eq!(request(&public, None, &head).await.as_deref(), Some("0"));
    let _ = public.stop.send(());
}
