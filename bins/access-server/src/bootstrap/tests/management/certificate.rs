//! Certificate, PIV and CAC sign-in on the real server path (§10.2.5, MD-8, OP-155 m.3 (k), (m),
//! OP-153 m.3 (gg)): `putCertificateLogin` commits `idp.realm.certificate_login`; a browser then
//! presents its client certificate to the real mTLS listener, which hands the chain to the
//! hosted login over the real store. A CA without the domain's Acceptance signs nobody in;
//! revoked, unreachable and stale statuses refuse; a mapped PIV policy signs in at AAL3 and
//! queues the realm issuer's `authentication` Claim with method `x509`. The OCSP responder is
//! the one part served in process.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::Actor;
use access_identity_account::app::accounts::{change_status, create};
use access_identity_account::domain::claims::{ClaimOrder, OUTBOX_PREFIX};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_oauth::ports::Directory as _;
use access_identity_ui::app::Hosted;
use access_identity_ui::app::certificate::Certificates;
use access_identity_ui::ports::Kits as _;
use access_identity_x509::app::Revocation;
use access_identity_x509::ports::{CaTrust, Fetch, Fetched, Held, Request as Fetch_, Unreachable};
use access_identity_x509::testing::{Ca, Issued, LeafSpec, OcspAnswer, Status as S};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

const OCSP: &str = "http://ocsp.acme.example/";
const PIV_AUTH: &str = "2.16.840.1.101.3.2.1.3.13";
const EMAIL: &str = "ada@acme.example";
const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

/// The authority plane's CA Acceptances, or every CA once `scripted`: a root-established
/// Acceptance waits out the CT3 time lock this realm keeps (the real path is
/// `idp::tests::certificate`).
struct ScriptedCa {
    plane: TestPlane,
    scripted: AtomicBool,
}

impl CaTrust for ScriptedCa {
    fn accepted(&self, domain: [u8; 32], issuer: [u8; 16]) -> Held<'_> {
        if self.scripted.load(Ordering::SeqCst) {
            return Box::pin(async { Ok(true) });
        }
        access_identity_x509::ports::CaTrust::accepted(&self.plane, domain, issuer)
    }
}

/// OCSP responders served in process; a URL without an answer is unreachable.
#[derive(Default)]
struct Responders(Mutex<HashMap<String, Vec<u8>>>);

impl Fetch for Responders {
    fn fetch<'a>(&'a self, request: Fetch_<'a>) -> Fetched<'a> {
        let url = match request {
            Fetch_::Ocsp { url, .. } | Fetch_::Crl { url } => url,
        };
        let found = self.0.lock().unwrap().get(url).cloned();
        Box::pin(async move { found.ok_or(Unreachable) })
    }
}

struct Listener {
    addr: std::net::SocketAddr,
    roots: rustls::RootCertStore,
    stop: tokio::sync::oneshot::Sender<()>,
}

fn hosted(
    c: &Console,
) -> Arc<
    Hosted<
        crate::login::HsmKits,
        access_identity_account::adapters::system::SystemClock,
        access_identity_ui::adapters::Outbox,
    >,
> {
    use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::app::local::LocalLimiter;
    use access_identity_account::app::login::LoginGate;
    use access_identity_account::domain::password::Argon2Params;
    use access_identity_account::domain::throttle::ThrottlePolicy;
    use access_identity_session::domain::session::SessionPolicy;
    let w = &c.w;
    Arc::new(Hosted {
        kits: crate::login::HsmKits::new(
            crate::login::RealmKeks::new(Arc::clone(&w.keys)),
            w.db.router.clone(),
            w.db.app.clone(),
            SessionPolicy::DEFAULT,
        ),
        db: w.db.app.clone(),
        products: w.db.reader.clone(),
        clock: SystemClock,
        messages: access_identity_ui::adapters::Outbox,
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
    })
}

/// The certificate route on a real mTLS listener, as `main` mounts it.
async fn listen(c: &Console, certs: Certificates) -> Listener {
    let router = access_http::login::certificate_router(
        access_identity_oauth::app::Discovery::new(
            PgDirectory::new(c.w.db.router.clone()),
            SignerKeys::new(c.w.identity_signer.clone()),
        ),
        hosted(c),
        certs,
    );
    let server = rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).unwrap();
    let config = access_http::tls::mtls_server_config(
        server.cert.pem().as_bytes(),
        server.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(access_http::tls::serve_mtls(
        listener,
        config,
        router,
        None,
        async {
            let _ = stopped.await;
        },
    ));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server.cert.der().clone()).unwrap();
    Listener { addr, roots, stop }
}

struct Answer {
    status: u16,
    head: String,
    body: serde_json::Value,
}

/// `GET /realms/acme/login/certificate` over TLS, presenting `leaf` when given.
async fn sign_in(l: &Listener, leaf: Option<&Issued>) -> Answer {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(l.roots.clone());
    let config = match leaf {
        None => builder.with_no_client_auth(),
        Some(i) => builder
            .with_client_auth_cert(
                vec![rustls::pki_types::CertificateDer::from(i.der.clone())],
                rustls::pki_types::PrivateKeyDer::try_from(i.key.serialize_der()).unwrap(),
            )
            .unwrap(),
    };
    let tcp = tokio::net::TcpStream::connect(l.addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(rustls::pki_types::ServerName::try_from(HOST).unwrap(), tcp)
        .await
        .unwrap();
    let head = format!(
        "GET /realms/acme/login/certificate HTTP/1.1\r\nHost: {HOST}:{}\r\n\
         Sec-Fetch-Site: same-site\r\nConnection: close\r\n\r\n",
        l.addr.port()
    );
    tls.write_all(head.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tls.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = body
        .find('{')
        .and_then(|i| body.get(i..))
        .and_then(|b| b.rfind('}').and_then(|j| b.get(..=j)))
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(serde_json::Value::Null);
    Answer {
        status,
        head: head.to_owned(),
        body,
    }
}

/// An active account of the realm with `email` as its identifier.
async fn account(c: &Console, email: &str) -> [u8; 16] {
    let h = hosted(c);
    let entry = PgDirectory::new(c.w.db.router.clone())
        .by_slug("acme")
        .await
        .unwrap()
        .unwrap();
    let kit = h.kits.kit(&entry).await.unwrap();
    let pg = PgAccounts::sealed(c.w.db.app.clone(), kit.vault());
    let realm = kit.realm();
    let id = Identifier::new(IdentifierKind::Email, email).unwrap();
    let s = create(&pg, &realm, &[id], &ADMIN).await.unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&pg, &realm, s, to, &ADMIN).await.unwrap();
    }
    s
}

/// The `authentication` Claims queued for `subject`.
async fn authentications(c: &Console, subject: [u8; 16]) -> Vec<ClaimOrder> {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let rows = t
        .outbox_payloads(&format!("{OUTBOX_PREFIX}authentication"))
        .await
        .unwrap();
    t.commit().await.unwrap();
    rows.iter()
        .map(|p| ClaimOrder::from_bytes(p).unwrap())
        .filter(|o| o.subject == subject)
        .collect()
}

// §10.2.5, MD-8, OP-155 m.3 (k), (m), Ek B 4663, 4671, 4672
#[tokio::test]
async fn a_certificate_signs_in_only_through_an_accepted_ca_with_a_current_status() {
    let c = console("mgmt-certificate", true).await;
    let at = now() / 1000;
    let ca = Ca::root_at("Acme Issuing CA", at);
    let leaf = |serial: u8, policies: &'static [&'static str]| {
        ca.leaf(&LeafSpec {
            email: Some(EMAIL),
            policies,
            ocsp: Some(OCSP),
            serial,
            ..LeafSpec::default()
        })
    };
    let (piv, soft, revoked, stale) = (
        leaf(2, &[PIV_AUTH]),
        leaf(3, &[]),
        leaf(4, &[PIV_AUTH]),
        leaf(5, &[PIV_AUTH]),
    );
    let subject = account(&c, EMAIL).await;
    let responders = Arc::new(Responders::default());
    let trust = Arc::new(ScriptedCa {
        plane: c.w.plane.clone(),
        scripted: AtomicBool::new(false),
    });
    let l = listen(
        &c,
        Certificates {
            revocation: Arc::new(Revocation::new(responders.clone())),
            trust: trust.clone(),
        },
    )
    .await;

    // OP-155 m.3 (m)
    let a = sign_in(&l, Some(&piv)).await;
    assert_eq!(
        (a.status, &a.body["code"]),
        (404, &serde_json::json!("no-such-provider"))
    );
    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/certificate-login",
            ("putCertificateLogin", None),
            serde_json::json!({
                "enabled": true,
                "rule": "san_email",
                "anchors": [b64url_encode(&[0x30, 0x00])],
                "piv_policies": [PIV_AUTH],
            }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::BAD_REQUEST, "{}", w.body);
    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/certificate-login",
            ("putCertificateLogin", None),
            serde_json::json!({
                "enabled": true,
                "rule": "san_email",
                "anchors": [b64url_encode(&ca.der)],
                "piv_policies": [PIV_AUTH],
            }),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);

    // OP-155 m.3 (k)
    let a = sign_in(&l, None).await;
    assert_eq!(
        (a.status, &a.body["code"]),
        (401, &serde_json::json!("certificate-refused"))
    );

    // §10.2.5
    responders.0.lock().unwrap().insert(
        String::from(OCSP),
        ca.ocsp(&piv.der, &OcspAnswer::current_at(S::Good, at), None),
    );
    let a = sign_in(&l, Some(&piv)).await;
    assert_eq!(
        (a.status, &a.body["code"]),
        (401, &serde_json::json!("certificate-refused"))
    );
    assert_eq!(authentications(&c, subject).await.len(), 0);
    trust.scripted.store(true, Ordering::SeqCst);

    // MD-8
    let a = sign_in(&l, Some(&stale)).await;
    assert_eq!(
        (a.status, &a.body["code"]),
        (401, &serde_json::json!("certificate-status-unknown"))
    );
    // MD-8
    let old = OcspAnswer {
        this_update: at - 2 * 86_400,
        next_update: Some(at - 86_400),
        ..OcspAnswer::current_at(S::Good, at)
    };
    responders
        .0
        .lock()
        .unwrap()
        .insert(String::from(OCSP), ca.ocsp(&stale.der, &old, None));
    let a = sign_in(&l, Some(&stale)).await;
    assert_eq!(
        (a.status, &a.body["code"]),
        (401, &serde_json::json!("certificate-status-unknown"))
    );
    // MD-8
    responders.0.lock().unwrap().insert(
        String::from(OCSP),
        ca.ocsp(&revoked.der, &OcspAnswer::current_at(S::Revoked, at), None),
    );
    let a = sign_in(&l, Some(&revoked)).await;
    assert_eq!(
        (a.status, &a.body["code"]),
        (401, &serde_json::json!("certificate-refused"))
    );
    assert_eq!(authentications(&c, subject).await.len(), 0);

    // OP-155 m.3 (m), §10.3.1
    responders.0.lock().unwrap().insert(
        String::from(OCSP),
        ca.ocsp(&piv.der, &OcspAnswer::current_at(S::Good, at), None),
    );
    let a = sign_in(&l, Some(&piv)).await;
    assert_eq!(a.status, 303, "{}", a.head);
    assert!(
        a.head.to_ascii_lowercase().contains("set-cookie"),
        "{}",
        a.head
    );
    let claims = authentications(&c, subject).await;
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].assurance["aal"], 3);
    assert_eq!(claims[0].assurance["hardware_bound"], 1);
    assert_eq!(claims[0].assurance["phishing_resistant"], 1);
    let access_identity_account::domain::claims::Content::Body {
        body: access_kernel::claim::body::Body::Authentication(auth),
        ..
    } = &claims[0].content
    else {
        panic!("{:?}", claims[0].content);
    };
    assert_eq!(auth.method, access_kernel::claim::body::AuthMethod::X509);
    assert_eq!(
        auth.evidence,
        Some(access_kernel::digest::Digest(suiss_crypto::digest::sha256(
            &piv.der
        )))
    );

    // OP-155 m.3 (m)
    responders.0.lock().unwrap().insert(
        String::from(OCSP),
        ca.ocsp(&soft.der, &OcspAnswer::current_at(S::Good, at), None),
    );
    let a = sign_in(&l, Some(&soft)).await;
    assert_eq!(a.status, 303, "{}", a.head);
    let _ = l.stop.send(());
}

// OP-155 m.3 (m), RFC 8705 §5, §10.4.3, Ek B 4673
#[tokio::test]
async fn mtls_aliases_are_advertised_once_the_realm_publishes_them() {
    use access_identity_oauth::app::Reply;
    use access_identity_oauth::domain::metadata::Document;
    let c = console("mgmt-mtls-aliases", true).await;
    let discovery = access_identity_oauth::app::Discovery::new(
        PgDirectory::new(c.w.db.router.clone()).with_facts(c.w.db.app.clone()),
        SignerKeys::new(c.w.identity_signer.clone()),
    )
    .with_mtls(8443);
    let aliases = || async {
        let Reply::Metadata(doc) = discovery
            .serve(Document::AuthorizationServer, HOST, Some("acme"))
            .await
        else {
            panic!("no metadata");
        };
        serde_json::from_str::<serde_json::Value>(&doc).unwrap()["mtls_endpoint_aliases"].clone()
    };
    assert_eq!(aliases().await, serde_json::Value::Null);
    for published in [true, false] {
        let w = c
            .rest_write(
                &Method::PUT,
                "/admin/v1/realms/acme/settings/mtls-aliases",
                ("putMtlsAliases", None),
                serde_json::json!({ "published": published }),
                None,
            )
            .await;
        assert!(w.status.is_success(), "{} {}", w.status, w.body);
        let a = aliases().await;
        if published {
            assert_eq!(
                a["token_endpoint"],
                "https://access.test:8443/realms/acme/token"
            );
            assert_eq!(
                a["introspection_endpoint"],
                "https://access.test:8443/realms/acme/introspect"
            );
        } else {
            assert_eq!(a, serde_json::Value::Null);
        }
    }
}
