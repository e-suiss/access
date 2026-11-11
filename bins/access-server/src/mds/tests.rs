//! OP-148, OP-146 m.4 (d), OP-158 m.3 (y): the refresh job against a local HTTPS twin of the
//! metadata service and real PostgreSQL.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use access_identity_oauth::adapters::outbound::{DeclaredTarget, Outbound};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_RSA_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

/// 2026-11-01 00:00:00 UTC.
const NOW: u64 = 1_793_491_200;

fn b64url(data: &[u8]) -> String {
    access_kernel::json::b64url_encode(data)
}

fn b64(data: &[u8]) -> String {
    let mut s: String = b64url(data)
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    s
}

/// A metadata signer with a runtime root (no key is committed).
struct Signer {
    root: Vec<u8>,
    leaf: Vec<u8>,
    key: RsaKeyPair,
}

impl Signer {
    fn new() -> Self {
        let root_key = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();
        let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
        root.distinguished_name
            .push(DnType::CommonName, "Test MDS Root");
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root.self_signed(&root_key).unwrap();
        let issuer = rcgen::Issuer::new(root, root_key);
        let leaf_key = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();
        let mut leaf = CertificateParams::new(vec!["mds.test".to_owned()]).unwrap();
        leaf.distinguished_name.push(DnType::CommonName, "mds.test");
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
        Self {
            root: root_cert.der().to_vec(),
            leaf: leaf_cert.der().to_vec(),
            key: RsaKeyPair::from_pkcs8(&leaf_key.serialize_der()).unwrap(),
        }
    }

    fn blob(&self, serial: u64, next_update: &str) -> Vec<u8> {
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "x5c": [b64(&self.leaf)] });
        let payload = serde_json::json!({
            "legalHeader": "test",
            "no": serial,
            "nextUpdate": next_update,
            "entries": [],
        });
        let input = format!(
            "{}.{}",
            b64url(header.to_string().as_bytes()),
            b64url(payload.to_string().as_bytes())
        );
        let mut sig = vec![0; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut sig,
            )
            .unwrap();
        format!("{input}.{}", b64url(&sig)).into_bytes()
    }
}

/// A local HTTPS twin of the metadata service answering `serving` to every request.
struct Twin {
    url: String,
    tls: Arc<rustls::ClientConfig>,
    serving: Arc<Mutex<Vec<u8>>>,
    hits: Arc<AtomicUsize>,
}

impl Twin {
    async fn start() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let der: CertificateDer<'static> = cert.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let serving = Arc::new(Mutex::new(Vec::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let (body, count) = (serving.clone(), hits.clone());
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    continue;
                };
                let mut buf = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                count.fetch_add(1, Ordering::SeqCst);
                let blob = body.lock().unwrap().clone();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/jwt\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    blob.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&blob).await;
                let _ = s.shutdown().await;
            }
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            url: format!("https://localhost:{port}/"),
            tls: Arc::new(tls),
            serving,
            hits,
        }
    }

    fn serve(&self, blob: Vec<u8>) {
        *self.serving.lock().unwrap() = blob;
    }

    fn outbound(&self) -> Outbound {
        Outbound::new(self.tls.clone(), Duration::from_secs(5)).declaring(vec![
            DeclaredTarget::new(&self.url, Some(self.tls.clone())).unwrap(),
        ])
    }
}

// OP-148, OP-146, OP-158
#[tokio::test(flavor = "multi_thread")]
async fn the_blob_is_fetched_verified_cached_and_never_rolled_back() {
    let db = access_store::testing::fresh().await.unwrap();
    let signer = Signer::new();
    let twin = Twin::start().await;
    let outbound = twin.outbound();
    twin.serve(signer.blob(7, "2026-12-01"));

    let first = Metadata::new(twin.url.clone(), signer.root.clone());
    assert_eq!(
        first.refresh(&db.app, &outbound, NOW).await.unwrap(),
        Refreshed::Fetched(7)
    );
    assert_eq!(twin.hits.load(Ordering::SeqCst), 1);
    assert_eq!(first.current(NOW).await.unwrap().serial, 7);
    // OP-41
    let audited = access_store::operational::operational_rows(&db.checkpointer, 100)
        .await
        .unwrap();
    assert!(
        audited
            .iter()
            .any(|r| r.event_type == "mds.refreshed" && r.target == "fido-mds:7")
    );
    assert_eq!(
        first.refresh(&db.app, &outbound, NOW).await.unwrap(),
        Refreshed::Held(7)
    );
    assert_eq!(
        twin.hits.load(Ordering::SeqCst),
        1,
        "a fresh blob is not fetched again"
    );

    let restarted = Metadata::new(twin.url.clone(), signer.root.clone());
    assert_eq!(
        restarted.refresh(&db.app, &outbound, NOW).await.unwrap(),
        Refreshed::FromCache(7)
    );
    assert_eq!(
        twin.hits.load(Ordering::SeqCst),
        1,
        "a restart starts from the cache"
    );

    let due = NOW + 31 * 86_400;
    twin.serve(signer.blob(6, "2027-01-15"));
    assert!(matches!(
        restarted.refresh(&db.app, &outbound, due).await,
        Err(WebAuthnError::Mds(MdsError::Rollback))
    ));
    assert_eq!(
        access_store::mds::latest(&db.app, &first.source)
            .await
            .unwrap()
            .unwrap()
            .0,
        7
    );

    let other = Signer::new();
    twin.serve(other.blob(8, "2027-01-15"));
    assert!(restarted.refresh(&db.app, &outbound, due).await.is_err());
    twin.serve(signer.blob(8, "2027-01-15"));
    assert_eq!(
        restarted.refresh(&db.app, &outbound, due).await.unwrap(),
        Refreshed::Fetched(8)
    );
    assert!(
        !access_store::mds::record(&db.app, &first.source, 7, 0, b"x")
            .await
            .unwrap()
    );
    assert_eq!(
        first.refresh(&db.app, &outbound, due).await.unwrap(),
        Refreshed::FromCache(8)
    );

    let expired = NOW + 400 * 86_400;
    let late = Metadata::new(twin.url.clone(), signer.root.clone());
    twin.serve(Vec::new());
    assert!(late.refresh(&db.app, &outbound, expired).await.is_err());
    assert!(
        late.current(expired).await.is_none(),
        "an expired blob is not used"
    );
}
