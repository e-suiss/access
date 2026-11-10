//! OP-156 m.3 (i), RFC 8555, RFC 8737: Access's own ACME client against Pebble, the ACME test
//! server, over its HTTPS adapter. Pebble validates TLS-ALPN-01 against the real SNI listener on
//! port 5001, issues the certificate, and the listener then serves it for the custom domain.
//! CI only (`scripts/ci/pebble-env.sh`); the in-process twin covers the same flow locally.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;
use std::time::Duration;

use access_http::tls::{DomainCert, Sni, serve, sni_server_config};
use access_identity_domain::adapters::https::AcmeHttps;
use access_identity_domain::app::acme::Client;
use access_identity_domain::ports::{AcmeHttp as _, Challenges, TokioPause, Unavailable};
use access_identity_domain::testing::SoftAccount;
use axum::Router;
use axum::routing::get;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const HOST: &str = "login.acme-pebble.example";

struct Listener(Arc<Sni>);

impl Challenges for Listener {
    async fn publish(&self, host: &str, digest: [u8; 32]) -> Result<(), Unavailable> {
        tokio::task::yield_now().await;
        self.0
            .publish_challenge(host, digest)
            .map_err(|e| Unavailable(e.to_string()))
    }

    async fn withdraw(&self, host: &str) -> Result<(), Unavailable> {
        tokio::task::yield_now().await;
        self.0.withdraw_challenge(host);
        Ok(())
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name}: run scripts/ci/pebble-env.sh up"))
}

fn tls_to(ca: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca) {
        roots.add(c.unwrap()).unwrap();
    }
    Arc::new(
        ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

// OP-156 m.3 (i), RFC 8555, RFC 8737
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CI only: Pebble (scripts/ci/pebble-env.sh)"]
async fn pebble_issues_a_certificate_over_tls_alpn_and_the_listener_serves_it() {
    let directory = env("ACCESS_TEST_PEBBLE_DIRECTORY");
    let ca = std::fs::read(env("ACCESS_TEST_PEBBLE_CA")).unwrap();
    let operator = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let sni = Sni::new(
        operator.cert.pem().as_bytes(),
        operator.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let listener = TcpListener::bind("0.0.0.0:5001").await.unwrap();
    let app = Router::new().route("/", get(|| async { "custom" }));
    tokio::spawn(serve(
        listener,
        sni_server_config(sni.clone(), None).unwrap(),
        app,
        std::future::pending(),
    ));

    let http = AcmeHttps::new(&directory, tls_to(&ca), Duration::from_secs(30)).unwrap();
    let key = SoftAccount::generate();
    let client = Client {
        http: &http,
        key: &key,
        pause: &TokioPause,
        directory: &directory,
        contact: Some("mailto:ops@acme-pebble.example"),
    };
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let issued = tokio::time::timeout(
        Duration::from_secs(120),
        client.issue(HOST, now, &Listener(sni.clone())),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(issued.leaf.dns_names, [HOST]);
    let chain = access_identity_domain::x509::pem_chain(&issued.chain_pem, 4).unwrap();

    let management = AcmeHttps::new(
        &format!("{}/roots/0", env("ACCESS_TEST_PEBBLE_MANAGEMENT")),
        tls_to(&ca),
        Duration::from_secs(30),
    )
    .unwrap();
    let root = management
        .get(
            &format!("{}/roots/0", env("ACCESS_TEST_PEBBLE_MANAGEMENT")),
            64 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(root.status, 200);

    sni.set_domains(vec![DomainCert {
        host: String::from(HOST),
        chain,
        key: zeroize::Zeroizing::new(issued.key_pkcs8.expose().clone()),
    }]);
    let config = tls_to(&root.body);
    let tcp = TcpStream::connect("127.0.0.1:5001").await.unwrap();
    let mut tls = TlsConnector::from(config)
        .connect(ServerName::try_from(HOST).unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.starts_with("HTTP/1.1 200") && text.ends_with("custom"),
        "{text}"
    );
}
