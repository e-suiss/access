//! A custom domain end to end (OP-156 m.3 (i), Ek B 5392): registered through the admin REST
//! surface and committed by the real decision point, verified by the DNS pass, certified by the
//! in-process ACME twin whose TLS-ALPN-01 validation reaches the real public listener, then served
//! by SNI with the realm's Frontend API on the customer's host. An unverified or lapsed domain is
//! not served and an unknown SNI fails the handshake.

use std::net::SocketAddr;

use access_http::tls::{Sni, serve, sni_server_config};
use access_identity_domain::adapters::seal::KeySeal;
use access_identity_domain::testing::{
    AcmeTwin, FakeDns, NoPause, SoftAccount, TWIN_DIRECTORY, Validation, twin_roots,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::custom_domains::{AcmeSetup, Deps, Keks, Listener, refresh, tick};

const HOST: &str = "login.acme.example";

/// Accepts any certificate whose key signed the handshake, as an ACME validation does (RFC 8737).
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
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &rustls::pki_types::SubjectPublicKeyInfoDer::from(
                access_identity_domain::der::p256_spki(&point),
            ),
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The TLS-ALPN-01 validation of `host` against `addr` (RFC 8737 §3).
async fn alpn_valid(addr: SocketAddr, host: String, digest: [u8; 32]) -> bool {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
        return false;
    };
    let connected = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(host.clone()).unwrap(), tcp),
    )
    .await;
    let Ok(Ok(tls)) = connected else {
        return false;
    };
    let Some(leaf) = tls.get_ref().1.peer_certificates().and_then(|c| c.first()) else {
        return false;
    };
    access_identity_domain::x509::read_leaf(leaf.as_ref())
        .is_ok_and(|l| l.dns_names == [host.clone()] && l.acme_identifier == Some(digest))
}

/// `GET path` on `addr` with SNI and `Host` `host`, trusting `roots`; `None` when the handshake
/// fails.
async fn get_at(
    addr: SocketAddr,
    host: &str,
    path: &str,
    roots: rustls::RootCertStore,
) -> Option<String> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
        .await
        .ok()?;
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// The realm's public hosted surface (the Frontend API and hosted sign-in) over the SNI listener.
async fn public_listener(c: &Console, sni: Arc<Sni>) -> SocketAddr {
    use access_http::login::router as login_router;
    use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::app::local::LocalLimiter;
    use access_identity_account::app::login::LoginGate;
    use access_identity_account::domain::password::Argon2Params;
    use access_identity_account::domain::throttle::ThrottlePolicy;
    use access_identity_oauth::app::Discovery as RealmDiscovery;
    use access_identity_session::domain::session::SessionPolicy;
    use access_identity_ui::adapters::Outbox;
    use access_identity_ui::app::Hosted;

    let hosted = Arc::new(Hosted {
        kits: crate::login::HsmKits::new(
            crate::login::RealmKeks::new(Arc::clone(&c.w.keys)),
            c.w.db.router.clone(),
            c.w.db.app.clone(),
            SessionPolicy::DEFAULT,
        ),
        db: c.w.db.app.clone(),
        products: c.w.db.reader.clone(),
        clock: SystemClock,
        messages: Outbox,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(HasherConfig::sized(
            Argon2Params::CANONICAL,
            cores(),
            cgroup_memory_budget(),
        )),
        redirect_to: String::from("/"),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        risk: access_identity_session::app::RiskServices::without_sources(),
        signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
    });
    let app = login_router(
        RealmDiscovery::new(
            PgDirectory::new(c.w.db.router.clone()),
            SignerKeys::new(c.w.identity_signer.clone()),
        ),
        hosted,
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        sni_server_config(sni, None).unwrap(),
        app,
        std::future::pending(),
    ));
    addr
}

fn wall_s() -> i64 {
    i64::try_from(now() / 1000).unwrap()
}

// OP-156 m.3 (i), Ek B 5392, RFC 8737, TN-20
#[tokio::test(flavor = "multi_thread")]
async fn a_custom_domain_serves_the_frontend_api_with_its_own_acme_certificate() {
    let c = console("custom-domain", false).await;
    let written = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/domains",
            ("registerDomain", None),
            serde_json::json!({ "host": HOST }),
            None,
        )
        .await;
    assert!(written.status.is_success(), "{:?}", written.body);
    let (status, page, _) = c.rest_read("/admin/v1/realms/acme/domains").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let d = &page["items"][0];
    assert_eq!(d["host"], HOST);
    assert_eq!(d["status"], "pending");
    assert_eq!(d["served"], false);
    assert_eq!(d["txt_name"], format!("_access-challenge.{HOST}"));
    let challenge = d["txt_value"].as_str().unwrap().to_owned();
    let target = d["cname_target"].as_str().unwrap().to_owned();

    let tls = test_tls("access.test");
    let sni = Sni::new(tls.server_cert.as_bytes(), tls.server_key.as_bytes()).unwrap();
    let addr = public_listener(&c, sni.clone()).await;
    let probe: access_identity_domain::testing::Probe =
        Arc::new(move |host, digest| Box::pin(alpn_valid(addr, host, digest)));
    let twin = AcmeTwin::new(Validation::Alpn(probe));
    let roots = twin_roots(&twin);
    let acme = AcmeSetup {
        http: twin,
        key: SoftAccount::generate(),
        pause: NoPause,
        directory: String::from(TWIN_DIRECTORY),
        contact: None,
    };
    let keys = KeySeal(Keks(crate::login::RealmKeks::new(Arc::clone(&c.w.keys))));
    let dns = FakeDns::default();
    let pools = (&c.w.db.app, &c.w.db.router);
    let listener = Listener(sni.clone());
    let deps = || Deps {
        dns: &dns,
        acme: Some(&acme),
        challenges: &listener,
        keys: &keys,
    };

    // OP-156 m.3 (i)
    let t0 = wall_s();
    tick(pools, deps(), "q4-test", t0).await.unwrap();
    refresh(pools, &sni, &keys, t0).await.unwrap();
    assert!(
        get_at(addr, HOST, "/v1/login/branding", roots.clone())
            .await
            .is_none()
    );

    dns.publish(HOST, &challenge, &target);
    let out = tick(pools, deps(), "q4-test", t0 + 301).await.unwrap();
    assert_eq!((out.verified, out.issued), (1, 1), "{out:?}");
    refresh(pools, &sni, &keys, t0 + 301).await.unwrap();
    assert_eq!(sni.domains(), [HOST]);
    let served = get_at(addr, HOST, "/v1/login/branding", roots.clone())
        .await
        .unwrap();
    assert!(served.starts_with("HTTP/1.1 200"), "{served}");
    let (_, page, _) = c.rest_read("/admin/v1/realms/acme/domains").await;
    assert_eq!(page["items"][0]["served"], true);
    assert!(page["items"][0]["certificate_expires_at"].is_string());

    // TN-20
    assert!(
        get_at(
            addr,
            "other.acme.example",
            "/v1/login/branding",
            roots.clone()
        )
        .await
        .is_none()
    );

    // OP-156 m.3 (i)
    dns.remove_challenge(HOST);
    let later = t0 + 301 + 86_400;
    let out = tick(pools, deps(), "q4-test", later).await.unwrap();
    assert_eq!(out.lapsed, 1);
    refresh(pools, &sni, &keys, later).await.unwrap();
    assert_eq!(sni.domains(), Vec::<String>::new());
    assert!(
        get_at(addr, HOST, "/v1/login/branding", roots)
            .await
            .is_none()
    );
}
