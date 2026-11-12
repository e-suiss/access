//! WebAuthn attestation on the hosted account surface (§10.2.4, OP-159 m.3 (ll), HL-19): a realm
//! with the `direct` policy verifies each statement against the FIDO metadata held and the CRLs
//! of its chain, which the server fetches from a local HTTPS twin through the guarded outbound
//! client and caches in PostgreSQL; a revoked or unreadable chain refuses the registration, the
//! `none` policy never reads attestation, and no passkey carries an ML-DSA algorithm. Chains,
//! CRLs and TPM structures are built at test time.

#![allow(clippy::similar_names, reason = "test code")]

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use access_identity_oauth::adapters::outbound::{DeclaredTarget, Outbound};
use access_identity_ui::adapters::CachedAttestationSources;
use access_identity_webauthn::adapters::{MemoryMdsCache, SystemClock};
use access_identity_webauthn::domain::mds::verify_blob;
use access_identity_webauthn::domain::policy::AttestationPolicy;
use access_identity_webauthn::ports::MdsCache as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::support::attest::{Credential, Flaw, Pki, packed, tpm};
use super::support::{Attestation, MdsSigner, aaguid_text, mds_payload, std_b64};
use super::*;

const MODEL: [u8; 16] = [0x6b; 16];

/// A local HTTPS twin of CRL distribution points: each path answers its bytes, any other 404.
struct CrlTwin {
    base: String,
    tls: Arc<rustls::ClientConfig>,
    serving: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    hits: Arc<AtomicUsize>,
}

impl CrlTwin {
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
        let serving: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
        let hits = Arc::new(AtomicUsize::new(0));
        let (table, count) = (serving.clone(), hits.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    continue;
                };
                let mut buf = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                count.fetch_add(1, Ordering::SeqCst);
                let line = String::from_utf8_lossy(&buf);
                let path = line.split(' ').nth(1).unwrap_or("").to_owned();
                let body = table.lock().unwrap().get(&path).cloned();
                let (status, body) = match body {
                    Some(b) => ("200 OK", b),
                    None => ("404 Not Found", Vec::new()),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/pkix-crl\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
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
            base: format!("https://localhost:{port}/"),
            tls: Arc::new(tls),
            serving,
            hits,
        }
    }

    fn serve(&self, url: &str, body: Vec<u8>) {
        let path = url.strip_prefix(self.base.as_str()).unwrap();
        self.serving
            .lock()
            .unwrap()
            .insert(format!("/{path}"), body);
    }

    fn outbound(&self) -> Outbound {
        Outbound::new(self.tls.clone(), Duration::from_secs(5)).declaring(vec![
            DeclaredTarget::new(&self.base, Some(self.tls.clone())).unwrap(),
        ])
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Fresh metadata naming every root in `roots` for [`MODEL`].
fn metadata(roots: &[&[u8]]) -> access_identity_webauthn::domain::mds::MdsBlob {
    let signer = MdsSigner::new();
    let entry = serde_json::json!({
        "aaguid": aaguid_text(MODEL),
        "metadataStatement": {
            "description": "Acme Key",
            "attestationRootCertificates": roots.iter().map(|r| std_b64(r)).collect::<Vec<_>>(),
        },
        "statusReports": [{"status": "FIDO_CERTIFIED_L1", "effectiveDate": "2026-01-01"}],
    });
    let blob = signer.blob(&mds_payload(11, "2027-03-01", vec![entry]));
    verify_blob(&blob, &signer.root_der, 1_800_000_000).unwrap()
}

/// Registers a passkey of `key` attested with `attestation`; the account answer.
async fn enrol(b: &mut Web, key: Key, attestation: Attestation, credential: u8) -> Answer {
    let reg = b
        .post("/v1/account/passkeys", Some(json!({ "name": "key" })))
        .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    let r = reg.json();
    let challenge = b64url_decode(r["options"]["challenge"].as_str().unwrap()).unwrap();
    let mut a = Authenticator::new(key);
    a.aaguid = MODEL;
    a.credential_id = vec![credential; 32];
    a.attestation = attestation;
    let (cdj, att) = a.register(RP_ID, ORIGIN, &challenge);
    let id = b64url_encode(&a.credential_id);
    let credential = json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&cdj),
            "attestationObject": b64url_encode(&att),
            "transports": ["usb"],
        },
        "clientExtensionResults": {},
    });
    let path = format!(
        "/v1/account/passkeys/{}",
        r["registration"].as_str().unwrap()
    );
    b.post(&path, Some(json!({ "credential": credential })))
        .await
}

impl Env {
    async fn audited(&self) -> Vec<(String, String)> {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let rows = t.list_audit(200).await.unwrap();
        t.commit().await.unwrap();
        rows.into_iter().map(|r| (r.event_type, r.target)).collect()
    }
}

// OP-159 m.3 (ll), §10.2.4, MD-8
#[tokio::test(flavor = "multi_thread")]
async fn direct_attestation_is_verified_with_fetched_crls_at_registration() {
    let twin = CrlTwin::start().await;
    let good = Arc::new(Pki::at(&twin.base));
    let revoked = Arc::new(Pki::at(&format!("{}revoked/", twin.base)));
    let unreadable = Arc::new(Pki::at(&format!("{}gone/", twin.base)));
    for (url, crl) in good.crls() {
        twin.serve(&url, crl);
    }
    twin.serve(&revoked.root_url, revoked.root_crl(true));
    twin.serve(
        &revoked.intermediate_url,
        revoked.intermediate_crl((2027, 6, 1)),
    );
    let held = Arc::new(MemoryMdsCache::default());
    held.replace(metadata(&[
        &good.root_der,
        &revoked.root_der,
        &unreadable.root_der,
    ]))
    .await
    .unwrap();
    let outbound = twin.outbound();
    let e = env_tweaked(
        (71, "lg-att", AuthPolicy::DEFAULT, false),
        RealmSignin::default(),
        access_identity_ui::app::signup::Signup::without_providers().unwrap(),
        None,
        |kit, db| {
            kit.webauthn.attestation = AttestationPolicy::Direct {
                aaguids: vec![access_identity_webauthn::domain::ids::Aaguid(MODEL)],
                enterprise: false,
            };
            kit.attestation = Arc::new(CachedAttestationSources {
                metadata: held.clone(),
                db: db.app.clone(),
                outbound,
                clock: SystemClock,
            });
        },
    )
    .await;
    e.account("ann@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("ann@example.com").await.step(), "complete");

    let ok = enrol(&mut b, Key::es256(), packed(&good, MODEL, Flaw::None), 0xa1).await;
    assert_eq!(
        ok.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&ok.body)
    );
    assert_eq!(twin.hits(), 2);
    for url in [&good.root_url, &good.intermediate_url] {
        let source = access_crypto::webauthn::sha256(url.as_bytes());
        assert!(
            access_store::attestation_crl::latest(&e.db.app, &source)
                .await
                .unwrap()
                .is_some(),
            "{url}"
        );
    }
    let credential = Credential::new();
    let cached = enrol(
        &mut b,
        credential.key(-7),
        tpm(&good, MODEL, &credential, Flaw::None),
        0xa2,
    )
    .await;
    assert_eq!(cached.status, StatusCode::CREATED);
    assert_eq!(twin.hits(), 2, "a current cached CRL is not fetched again");

    let refused = enrol(
        &mut b,
        Key::es256(),
        packed(&revoked, MODEL, Flaw::None),
        0xa3,
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.json()["code"], "attestation-format");

    let unknown = enrol(
        &mut b,
        Key::es256(),
        packed(&unreadable, MODEL, Flaw::None),
        0xa4,
    )
    .await;
    assert_eq!(unknown.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(unknown.json()["code"], "attestation-revocation-unknown");

    let broken = enrol(
        &mut b,
        Key::es256(),
        packed(&good, MODEL, Flaw::Binding),
        0xa5,
    )
    .await;
    assert_eq!(broken.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(broken.json()["code"], "attestation-format");

    let audited = e.audited().await;
    let count = |event: &str, target: Option<&str>| {
        audited
            .iter()
            .filter(|(ev, t)| ev == event && target.is_none_or(|x| t == x))
            .count()
    };
    assert_eq!(count("attestation.verified", None), 2);
    assert_eq!(count("credential.passkey.registered", None), 2);
    assert_eq!(
        count("attestation.rejected", Some("webauthn-attestation-revoked")),
        1
    );
    assert_eq!(
        count(
            "attestation.rejected",
            Some("webauthn-attestation-revocation-unknown")
        ),
        1
    );
    assert_eq!(
        count(
            "attestation.rejected",
            Some("webauthn-attestation-statement")
        ),
        1
    );
}

// OP-159 m.3 (ll), §10.2.4
#[tokio::test(flavor = "multi_thread")]
async fn the_none_policy_reads_no_attestation() {
    let twin = CrlTwin::start().await;
    let gone = Arc::new(Pki::at(&twin.base));
    let outbound = twin.outbound();
    let e = env_tweaked(
        (72, "lg-att-none", AuthPolicy::DEFAULT, false),
        RealmSignin::default(),
        access_identity_ui::app::signup::Signup::without_providers().unwrap(),
        None,
        |kit, db| {
            kit.attestation = Arc::new(CachedAttestationSources {
                metadata: Arc::new(MemoryMdsCache::default()),
                db: db.app.clone(),
                outbound,
                clock: SystemClock,
            });
        },
    )
    .await;
    e.account("bob@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("bob@example.com").await.step(), "complete");
    let ok = enrol(&mut b, Key::es256(), packed(&gone, MODEL, Flaw::None), 0xb1).await;
    assert_eq!(ok.status, StatusCode::CREATED);
    assert_eq!(twin.hits(), 0);
    assert!(
        !e.audited()
            .await
            .iter()
            .any(|(ev, _)| ev.starts_with("attestation."))
    );
}

// HL-19, CR-43
#[tokio::test(flavor = "multi_thread")]
async fn hl_19_an_ml_dsa_passkey_is_refused() {
    let e = env(73, "lg-pq", AuthPolicy::DEFAULT).await;
    e.account("cem@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("cem@example.com").await.step(), "complete");
    for alg in access_identity_webauthn::domain::cose::ML_DSA {
        let refused = enrol(&mut b, Key::p256(alg), Attestation::None, 0xc1).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{alg}");
        assert_eq!(refused.json()["code"], "passkey-not-registered");
    }
    let classic = enrol(&mut b, Key::es256(), Attestation::None, 0xc2).await;
    assert_eq!(classic.status, StatusCode::CREATED);
}
