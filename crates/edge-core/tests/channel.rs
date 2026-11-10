//! OP-155 m.3 (c), IDP-26, IDI-11, P-ID-5, §13.2: a gateway's edge core against access-server's
//! real router over mutual TLS 1.3, on a real PostgreSQL. Certificates are made at run time.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_edge_core::channel::{Channel, ChannelConfig, ChannelError};
use access_edge_core::{EdgeCore, EdgeError};
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::accounts::create;
use access_identity_account::app::vault::Vault;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_edge::adapters::{
    PgRegistry, keytab_emergency, keytab_policy, register, retire,
};
use access_identity_edge::app::kerberos::Kerberos;
use access_identity_edge::app::{Edge, Vaults};
use access_internal_api::edge::kerberos::{self as krb, Authenticated};
use access_internal_api::edge::{Call, GatewayKind, IssueClaim};
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use rustls_pki_types::pem::PemObject as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const SPARE: u8 = 8;
const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

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

/// A client certificate whose single SAN URI is `uri`, PEM chain and key, and its SHA-256.
fn leaf(ca: &Ca, uri: &str) -> (String, String, [u8; 32]) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    let digest = suiss_crypto::digest::sha256(cert.der());
    (cert.pem(), key.serialize_pem(), digest)
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

async fn domain(db: &TestDb, t: TenantId, seed: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let (lease, mut head) = acquire_lease(&db.sequencer, &d, "a", Duration::from_secs(10))
        .await
        .unwrap();
    for i in 1..=SPARE {
        let pos = head.pos.checked_add(1).unwrap();
        let leaf = [i; 32];
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: leaf,
                envelope: vec![0xa1, i],
            }],
            head: next.clone(),
            nonces: vec![NonceRow {
                nonce: vec![i; 16],
                actor: vec![1],
                intent_digest: [9; 32],
                decision_pos: pos,
                outcome: String::from("allow"),
                render_digest: None,
                tier: None,
            }],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

#[derive(Clone)]
struct TestVaults(Vault);

impl Vaults for TestVaults {
    fn vault(&self, _: TenantId, _: RealmId) -> Option<Vault> {
        Some(self.0.clone())
    }
}

struct World {
    db: TestDb,
    tenant: TenantId,
    corp: RealmId,
    domain: DomainId,
    vault: Vault,
    kek: SoftKek,
    ids: IdKey,
    next: std::sync::atomic::AtomicU64,
    ca: Ca,
    server_roots: String,
    addr: std::net::SocketAddr,
}

impl World {
    async fn bound(&self, tx: &mut TenantTx, action: &str) -> access_store::idp::Bound {
        let p = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let nonce = [u8::try_from(p).unwrap(); 16];
        bind(
            tx,
            &Decision {
                domain: &self.domain,
                position: p,
                nonce: &nonce,
                intent: [9; 32],
                change: [5; 32],
                action,
            },
        )
        .await
        .unwrap()
        .unwrap()
    }

    async fn register(&self, kind: GatewayKind, name: &str, cert: [u8; 32]) {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.corp)
            .await
            .unwrap();
        let b = self.bound(&mut tx, "idp.gateway.register").await;
        register(&mut tx, &b, kind, name, &cert).await.unwrap();
        tx.commit().await.unwrap();
    }

    async fn retire(&self, kind: GatewayKind, name: &str) {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.corp)
            .await
            .unwrap();
        let b = self.bound(&mut tx, "idp.gateway.retire").await;
        assert!(retire(&mut tx, &b, kind, name).await.unwrap());
        tx.commit().await.unwrap();
    }

    fn realm(&self) -> Realm<'_> {
        Realm {
            tenant: self.tenant,
            realm: self.corp,
            kek: &self.kek,
            ids: &self.ids,
        }
    }

    /// An active account with e-mail `who`.
    async fn active(&self, who: &str) -> [u8; 16] {
        let pg = PgAccounts::sealed(self.db.app.clone(), self.vault.clone());
        let id = Identifier::new(IdentifierKind::Email, who).unwrap();
        let s = create(&pg, &self.realm(), &[id], &ADMIN).await.unwrap();
        let mut tx = pg.begin(self.tenant, self.corp).await.unwrap();
        assert!(
            tx.set_status(s, AccountStatus::Staged, AccountStatus::PendingUserAction)
                .await
                .unwrap()
        );
        assert!(
            tx.set_status(s, AccountStatus::PendingUserAction, AccountStatus::Active)
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        s
    }

    /// An active account with user name `user`.
    async fn person(&self, user: &str) -> [u8; 16] {
        let pg = PgAccounts::sealed(self.db.app.clone(), self.vault.clone());
        let id = Identifier::new(IdentifierKind::Username, user).unwrap();
        let s = create(&pg, &self.realm(), &[id], &ADMIN).await.unwrap();
        let mut tx = pg.begin(self.tenant, self.corp).await.unwrap();
        tx.set_status(s, AccountStatus::Staged, AccountStatus::PendingUserAction)
            .await
            .unwrap();
        tx.set_status(s, AccountStatus::PendingUserAction, AccountStatus::Active)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        s
    }

    async fn keytab(&self, name: &str, spn: &str, emergency: Option<u32>) {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.corp)
            .await
            .unwrap();
        if let Some(kvno) = emergency {
            let b = self.bound(&mut tx, "idp.gateway.keytab_emergency").await;
            keytab_emergency(&mut tx, &b, name, kvno).await.unwrap();
        } else {
            let b = self.bound(&mut tx, "idp.gateway.keytab_policy").await;
            keytab_policy(&mut tx, &b, name, spn, 30).await.unwrap();
        }
        tx.commit().await.unwrap();
    }

    fn channel(&self, chain: &str, key: &str) -> Channel {
        Channel::new(&ChannelConfig {
            addr: self.addr.to_string(),
            server_name: String::from("localhost"),
            roots_pem: self.server_roots.clone().into_bytes(),
            chain_pem: chain.as_bytes().to_vec(),
            key_pem: key.as_bytes().to_vec(),
        })
        .unwrap()
    }

    async fn rows(&self) -> (Vec<String>, Vec<String>) {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.corp)
            .await
            .unwrap();
        let audit = tx
            .list_audit(1_000)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.event_type)
            .collect();
        let outbox = tx.outbox_kinds().await.unwrap();
        tx.commit().await.unwrap();
        (audit, outbox)
    }
}

async fn world(seed: u8) -> World {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, tenant, seed).await;
    let other = domain(&db, tenant, seed.wrapping_add(1)).await;
    let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    let corp = create_realm(&mut tx, &d, "corp", "pool-default")
        .await
        .unwrap();
    create_realm(&mut tx, &other, "other", "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let vault = Vault::in_memory(
        Arc::new(SoftKek::new("realm-kek:1", [seed; 32])),
        [seed; 32],
    );
    let ca = ca();
    let server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let config = access_http::tls::server_config(
        server.cert.pem().as_bytes(),
        server.signing_key.serialize_pem().as_bytes(),
        Some(ca.pem.as_bytes()),
    )
    .unwrap();
    let edge = Edge::new(
        PgRegistry(db.router.clone()),
        TestVaults(vault.clone()),
        db.app.clone(),
    );
    let kerberos = Kerberos::new(TestVaults(vault.clone()), db.app.clone());
    let protocols = access_http::edge::Protocols {
        kerberos: Some(Arc::new(kerberos)),
        ..access_http::edge::Protocols::default()
    };
    let app = access_http::harden(
        access_http::edge::router_protocols(edge, protocols).merge(access_http::ingest::router(
            access_internal_api::claims::Unserved,
        )),
        access_http::Limits::default(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(access_http::tls::serve(
        listener,
        config,
        app,
        std::future::pending(),
    ));
    World {
        db,
        tenant,
        corp,
        domain: d,
        vault,
        kek: SoftKek::new("realm-kek:1", [seed; 32]),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        next: std::sync::atomic::AtomicU64::new(1),
        ca,
        server_roots: server.cert.pem(),
        addr,
    }
}

fn refused(e: &EdgeError) -> (u16, &str) {
    match e {
        EdgeError::Channel(ChannelError::Refused { status, code }) => (*status, code.as_str()),
        other => panic!("{other:?}"),
    }
}

// IDP-26, OP-155 m.3 (c), §10.6
#[tokio::test]
async fn a_registered_gateway_reaches_its_realm_through_the_edge_channel() {
    let w = world(61).await;
    let (chain, key, cert) = leaf(&w.ca, "urn:suiss:access:gw:ldap:corp-ldap");
    w.register(GatewayKind::Ldap, "corp-ldap", cert).await;
    let alice = w.active("alice@corp.example").await;
    let core = EdgeCore::connect(w.channel(&chain, &key)).await.unwrap();
    assert_eq!(core.gateway().uri(), "urn:suiss:access:gw:ldap:corp-ldap");
    assert_eq!(core.realm(None).unwrap(), "corp");
    assert_eq!(
        core.subject("ALICE@corp.example").await.unwrap(),
        Some(alice)
    );
    assert_eq!(core.subject("nobody@corp.example").await.unwrap(), None);
    // P-ID-5
    let issued = core
        .issue(Some("corp"), alice, "ldap-bind", now_ms(), Some([3; 32]))
        .await
        .unwrap();
    assert!(issued.queued);
    core.audit("ldap.bind", "ok", Some(alice)).await.unwrap();
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.claim_requested")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("edge.ldap.bind.ok")),
        "{audit:?}"
    );
    assert!(
        outbox.iter().any(|k| k.ends_with("authentication")),
        "{outbox:?}"
    );
    let metrics = core.health().render();
    assert!(
        metrics.contains("call=\"issue_claim\",outcome=\"ok\"} 1"),
        "{metrics}"
    );
}

// §13.2, IDP-26
#[tokio::test]
async fn a_gateway_is_held_to_its_realm_and_method_class() {
    let w = world(63).await;
    let (chain, key, cert) = leaf(&w.ca, "urn:suiss:access:gw:ldap:corp-ldap");
    w.register(GatewayKind::Ldap, "corp-ldap", cert).await;
    let alice = w.active("alice@corp.example").await;
    let core = EdgeCore::connect(w.channel(&chain, &key)).await.unwrap();
    assert_eq!(
        core.issue(Some("other"), alice, "ldap-bind", now_ms(), None)
            .await,
        Err(EdgeError::Realm)
    );
    let ask = |realm: &str, method: &str, subject: [u8; 16], at: u64| {
        IssueClaim {
            realm: String::from(realm),
            subject,
            method: String::from(method),
            auth_time: at,
            evidence: None,
        }
        .encode()
    };
    let other = core
        .raw(
            Call::IssueClaim,
            &ask("other", "ldap-bind", alice, now_ms()),
        )
        .await
        .unwrap_err();
    assert_eq!(refused(&other), (403, "edge-realm"));
    for method in ["kerberos", "webauthn", "saml", "password"] {
        let e = core
            .raw(Call::IssueClaim, &ask("corp", method, alice, now_ms()))
            .await
            .unwrap_err();
        assert_eq!(refused(&e), (403, "edge-method"), "{method}");
    }
    let stale = core
        .raw(
            Call::IssueClaim,
            &ask("corp", "ldap-bind", alice, now_ms() - 10 * 60 * 1000),
        )
        .await
        .unwrap_err();
    assert_eq!(refused(&stale), (403, "edge-auth-time"));
    let nobody = core
        .raw(
            Call::IssueClaim,
            &ask("corp", "ldap-bind", [7; 16], now_ms()),
        )
        .await
        .unwrap_err();
    assert_eq!(refused(&nobody), (403, "edge-subject"));
    let (_, outbox) = w.rows().await;
    assert!(
        !outbox.iter().any(|k| k.ends_with("authentication")),
        "{outbox:?}"
    );
}

// IDP-26
#[tokio::test]
async fn only_a_live_registered_certificate_is_a_gateway() {
    let w = world(65).await;
    let (chain, key, cert) = leaf(&w.ca, "urn:suiss:access:gw:ldap:corp-ldap");
    let unknown = EdgeCore::connect(w.channel(&chain, &key))
        .await
        .unwrap_err();
    assert_eq!(refused(&unknown), (403, "edge-gateway-unknown"));
    w.register(GatewayKind::Ldap, "corp-ldap", cert).await;
    assert!(EdgeCore::connect(w.channel(&chain, &key)).await.is_ok());
    let (other_chain, other_key, _) = leaf(&w.ca, "urn:suiss:access:gw:ldap:corp-ldap");
    let copied_name = EdgeCore::connect(w.channel(&other_chain, &other_key))
        .await
        .unwrap_err();
    assert_eq!(refused(&copied_name), (403, "edge-gateway-unknown"));
    let (kerberos_chain, kerberos_key, _) = leaf(&w.ca, "urn:suiss:access:gw:kerberos:corp-ldap");
    let other_kind = EdgeCore::connect(w.channel(&kerberos_chain, &kerberos_key))
        .await
        .unwrap_err();
    assert_eq!(refused(&other_kind), (403, "edge-gateway-unknown"));
    w.retire(GatewayKind::Ldap, "corp-ldap").await;
    let retired = EdgeCore::connect(w.channel(&chain, &key))
        .await
        .unwrap_err();
    assert_eq!(refused(&retired), (403, "edge-gateway-unknown"));
}

// IDI-11, P-ID-5, IDP-26
#[tokio::test]
async fn a_gateway_certificate_reaches_no_route_but_the_edge_calls() {
    let w = world(67).await;
    let (chain, key, cert) = leaf(&w.ca, "urn:suiss:access:gw:radius:corp-radius");
    w.register(GatewayKind::Radius, "corp-radius", cert).await;
    let roots = {
        let mut r = rustls::RootCertStore::empty();
        for c in rustls_pki_types::CertificateDer::pem_slice_iter(w.server_roots.as_bytes()) {
            r.add(c.unwrap()).unwrap();
        }
        r
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(
        rustls_pki_types::CertificateDer::pem_slice_iter(chain.as_bytes())
            .map(Result::unwrap)
            .collect(),
        rustls_pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
    )
    .unwrap();
    for (method, path) in [
        ("POST", "/access/v1/claims:ingest"),
        ("POST", "/access/v1/exercises"),
        ("GET", "/realms/corp/.well-known/openid-configuration"),
        ("POST", "/edge/v2/issue_claim"),
    ] {
        let tcp = tokio::net::TcpStream::connect(w.addr).await.unwrap();
        let mut s = tokio_rustls::TlsConnector::from(Arc::new(tls.clone()))
            .connect(
                rustls_pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        s.write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nIdempotency-Key: k\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut answer = Vec::new();
        s.read_to_end(&mut answer).await.unwrap();
        let text = String::from_utf8_lossy(&answer);
        assert!(text.starts_with("HTTP/1.1 403"), "{path}: {text}");
        assert!(text.contains("edge-route-forbidden"), "{path}: {text}");
    }
    let core = EdgeCore::connect(w.channel(&chain, &key)).await.unwrap();
    let not_yet = core.raw(Call::Authenticate, &[0xa0]).await.unwrap_err();
    assert_eq!(refused(&not_yet), (501, "edge-call-not-served"));
}

const SPN: &str = "HTTP/access.corp.example@CORP.EXAMPLE";

async fn accept(
    core: &EdgeCore,
    principal: &str,
    spn: &str,
    kvno: u32,
    etype: i32,
) -> Result<Authenticated, EdgeError> {
    let q = krb::Authenticate {
        realm: String::from("corp"),
        principal: String::from(principal),
        spn: String::from(spn),
        kvno,
        etype,
    };
    let body = core.raw(Call::Authenticate, &q.encode()).await?;
    Ok(Authenticated::decode(&body).unwrap())
}

// IDP-17, OP-155 m.3 (o), §10.6.4
#[tokio::test]
async fn kerberos_acceptances_are_held_to_the_keytab_policy() {
    let w = world(57).await;
    let ada = w.person("ada").await;
    let (chain, key, cert) = leaf(&w.ca, "urn:suiss:access:gw:kerberos:corp-krb");
    w.register(GatewayKind::Kerberos, "corp-krb", cert).await;
    let core = EdgeCore::connect(w.channel(&chain, &key)).await.unwrap();
    let none = accept(&core, "ada@CORP.EXAMPLE", SPN, 3, krb::AES256_SHA1).await;
    assert_eq!(refused(&none.unwrap_err()), (403, "edge-keytab"));
    w.keytab("corp-krb", SPN, None).await;
    let ok = accept(&core, "ada@CORP.EXAMPLE", SPN, 3, krb::AES256_SHA1)
        .await
        .unwrap();
    assert_eq!(ok.subject, Some(ada));
    core.issue(None, ada, "kerberos", now_ms(), None)
        .await
        .unwrap();
    let other_spn = accept(
        &core,
        "ada@CORP.EXAMPLE",
        "HTTP/other.corp.example@CORP.EXAMPLE",
        3,
        krb::AES256_SHA1,
    )
    .await;
    assert_eq!(refused(&other_spn.unwrap_err()), (403, "edge-spn"));
    let rc4 = accept(&core, "ada@CORP.EXAMPLE", SPN, 3, 23).await;
    assert_eq!(refused(&rc4.unwrap_err()), (403, "edge-enctype"));
    for stranger in [
        "ada@OTHER.EXAMPLE",
        "HTTP/host@CORP.EXAMPLE",
        "nobody@CORP.EXAMPLE",
    ] {
        let a = accept(&core, stranger, SPN, 3, krb::AES256_SHA384)
            .await
            .unwrap();
        assert_eq!(a.subject, None, "{stranger}");
    }
    w.keytab("corp-krb", SPN, Some(5)).await;
    let old = accept(&core, "ada@CORP.EXAMPLE", SPN, 3, krb::AES256_SHA1).await;
    assert_eq!(refused(&old.unwrap_err()), (403, "edge-kvno"));
    let new = accept(&core, "ada@CORP.EXAMPLE", SPN, 5, krb::AES256_SHA1)
        .await
        .unwrap();
    assert_eq!(new.subject, Some(ada));
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("login.kerberos.succeeded")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("login.kerberos.failed")),
        "{audit:?}"
    );
    assert!(
        outbox.iter().any(|k| k.ends_with("authentication")),
        "{outbox:?}"
    );
}

// §13.2, OP-155 m.3 (o)
#[tokio::test]
async fn only_a_kerberos_gateway_reports_kerberos_acceptances() {
    let w = world(58).await;
    w.person("ada").await;
    let (chain, key, cert) = leaf(&w.ca, "urn:suiss:access:gw:ldap:corp-ldap");
    w.register(GatewayKind::Ldap, "corp-ldap", cert).await;
    let core = EdgeCore::connect(w.channel(&chain, &key)).await.unwrap();
    let r = accept(&core, "ada@CORP.EXAMPLE", SPN, 3, krb::AES256_SHA1).await;
    assert!(r.is_err());
}

#[cfg(target_os = "linux")]
mod kerberos_gateway {
    //! OP-155 m.3 (o), (q), IDP-17, RR-28: the Kerberos gateway binary and the parser worker
    //! supervisor as real processes, access-server's real edge router on a real PostgreSQL, an MIT
    //! KDC (`scripts/ci/edge-env.sh`) and `curl --negotiate` as the browser. CI's `kerberos` job
    //! builds the excluded gateway workspace and runs this as root (the lockdown needs it).

    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use super::{SPN, leaf, world};
    use access_internal_api::edge::GatewayKind;

    const LOGIN: &str = "https://corp.example/realms/corp/login";

    struct Running(Vec<Child>);

    impl Drop for Running {
        fn drop(&mut self) {
            for c in &mut self.0 {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
    }

    fn write(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn run_as() -> (String, String) {
        (
            std::env::var("SUDO_UID").unwrap_or_else(|_| String::from("65534")),
            std::env::var("SUDO_GID").unwrap_or_else(|_| String::from("65534")),
        )
    }

    async fn listening(port: u16) {
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the gateway did not listen");
    }

    fn curl(dir: &Path, host: &str, port: u16, extra: &[&str]) -> (String, String) {
        let url = format!("https://{host}:{port}/negotiate");
        let resolve = format!("{host}:{port}:127.0.0.1");
        let out = Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code} %{redirect_url}",
            ])
            .args(["--cacert", dir.join("gw-ca.pem").to_str().unwrap()])
            .args(["--resolve", &resolve])
            .args(extra)
            .arg(&url)
            .env("KRB5_CONFIG", dir.join("krb5.conf"))
            .env(
                "KRB5CCNAME",
                format!("FILE:{}", dir.join("ccache").display()),
            )
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (code, rest) = text.split_once(' ').unwrap_or((&text, ""));
        (code.to_owned(), rest.to_owned())
    }

    /// Every file under `dir` whose bytes contain `needle`.
    fn holding(dir: &Path, needle: &[u8], out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                holding(&p, needle, out);
            } else if std::fs::read(&p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle))
            {
                out.push(p);
            }
        }
    }

    // IDP-17, OP-155 m.3 (o), §10.6.4, RR-28
    #[tokio::test]
    #[ignore = "needs root, the MIT KDC and the gateway binary; CI job kerberos"]
    async fn spnego_signs_in_falls_back_and_never_writes_the_keytab() {
        let w = world(59).await;
        w.person("ada").await;
        let (chain, key, cert) = leaf(&w.ca, "urn:suiss:access:gw:kerberos:corp-krb");
        w.register(GatewayKind::Kerberos, "corp-krb", cert).await;
        w.keytab("corp-krb", SPN, None).await;
        let (uid, gid) = run_as();
        let dir = std::env::temp_dir().join(format!("access-gw-kerberos-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("rcache")).unwrap();
        let realm = env("ACCESS_TEST_KRB5_REALM");
        let kdc = env("ACCESS_TEST_KDC");
        let keytab = PathBuf::from(env("ACCESS_TEST_KEYTAB_DIR")).join("http.keytab");
        write(
            &dir,
            "krb5.conf",
            format!(
                "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n rdns = false\n permitted_enctypes = aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96\n[realms]\n {realm} = {{\n  kdc = {kdc}\n }}\n"
            )
            .as_bytes(),
        );
        let gw =
            rcgen::generate_simple_self_signed(vec!["access.corp.example".to_owned()]).unwrap();
        write(&dir, "gw-ca.pem", gw.cert.pem().as_bytes());
        write(&dir, "gw.pem", gw.cert.pem().as_bytes());
        write(
            &dir,
            "gw-key.pem",
            gw.signing_key.serialize_pem().as_bytes(),
        );
        write(&dir, "server-roots.pem", w.server_roots.as_bytes());
        write(&dir, "channel.pem", chain.as_bytes());
        write(&dir, "channel-key.pem", key.as_bytes());
        let chown = Command::new("chown")
            .args(["-R", &format!("{uid}:{gid}"), dir.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(chown.success());
        let socket = dir.join("parser.sock");
        let parser = Command::new(env("ACCESS_TEST_PARSER_BIN"))
            .env_clear()
            .env("ACCESS_PARSER_SOCKET", &socket)
            .env("ACCESS_PARSER_CALLERS", &uid)
            .env("ACCESS_PARSER_WORKERS", "1")
            .env("ACCESS_PARSER_RUN_AS", format!("{uid}:{gid}"))
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut running = Running(vec![parser]);
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let gateway = Command::new(env("ACCESS_TEST_GW_KERBEROS_BIN"))
            .env_clear()
            .env("ACCESS_GW_KERBEROS_LISTEN", format!("127.0.0.1:{port}"))
            .env("ACCESS_GW_KERBEROS_TLS_CERT", dir.join("gw.pem"))
            .env("ACCESS_GW_KERBEROS_TLS_KEY", dir.join("gw-key.pem"))
            .env("ACCESS_GW_KERBEROS_SPN", SPN)
            .env("ACCESS_GW_KERBEROS_KEYTAB", &keytab)
            .env("ACCESS_GW_KERBEROS_LOGIN", LOGIN)
            .env("ACCESS_GW_KERBEROS_PARSER_SOCKET", &socket)
            .env("ACCESS_GW_KERBEROS_PARSER_UID", &uid)
            .env("ACCESS_GW_KERBEROS_KRB5_CONF", dir.join("krb5.conf"))
            .env("ACCESS_GW_KERBEROS_RCACHE_DIR", dir.join("rcache"))
            .env("ACCESS_GW_KERBEROS_SERVER", w.addr.to_string())
            .env("ACCESS_GW_KERBEROS_SERVER_NAME", "localhost")
            .env(
                "ACCESS_GW_KERBEROS_SERVER_ROOTS",
                dir.join("server-roots.pem"),
            )
            .env("ACCESS_GW_KERBEROS_CHANNEL_CERT", dir.join("channel.pem"))
            .env(
                "ACCESS_GW_KERBEROS_CHANNEL_KEY",
                dir.join("channel-key.pem"),
            )
            .env("ACCESS_GW_KERBEROS_RUN_AS", format!("{uid}:{gid}"))
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        running.0.push(gateway);
        listening(port).await;
        let kinit = Command::new("kinit")
            .arg(format!("ada@{realm}"))
            .env("KRB5_CONFIG", dir.join("krb5.conf"))
            .env(
                "KRB5CCNAME",
                format!("FILE:{}", dir.join("ccache").display()),
            )
            .stdin(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write as _;
                c.stdin
                    .take()
                    .unwrap()
                    .write_all(b"ci-only-not-a-secret\n")?;
                c.wait()
            })
            .unwrap();
        assert!(kinit.success());
        let (no_token, _) = curl(&dir, "access.corp.example", port, &[]);
        assert_eq!(no_token, "401");
        let (code, to) = tokio::task::spawn_blocking({
            let dir = dir.clone();
            move || {
                curl(
                    &dir,
                    "access.corp.example",
                    port,
                    &["--negotiate", "-u", ":"],
                )
            }
        })
        .await
        .unwrap();
        assert_eq!((code.as_str(), to.as_str()), ("303", LOGIN));
        let (wrong, to) = tokio::task::spawn_blocking({
            let dir = dir.clone();
            move || {
                curl(
                    &dir,
                    "other.corp.example",
                    port,
                    &["--negotiate", "-u", ":"],
                )
            }
        })
        .await
        .unwrap();
        assert_eq!((wrong.as_str(), to.as_str()), ("303", LOGIN));
        for header in [
            "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw==",
            "Authorization: Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw==",
        ] {
            let (ntlm, to) = curl(&dir, "access.corp.example", port, &["-H", header]);
            assert_eq!((ntlm.as_str(), to.as_str()), ("303", LOGIN), "{header}");
        }
        let (audit, outbox) = w.rows().await;
        assert!(
            audit.contains(&String::from("login.kerberos.succeeded")),
            "{audit:?}"
        );
        assert!(
            audit.contains(&String::from("edge.kerberos.ntlm.refused")),
            "{audit:?}"
        );
        assert!(
            audit.contains(&String::from("edge.kerberos.token.refused")),
            "{audit:?}"
        );
        assert!(
            outbox.iter().any(|k| k.ends_with("authentication")),
            "{outbox:?}"
        );
        let bytes = std::fs::read(&keytab).unwrap();
        let entries = access_edge_core::keytab::read(&bytes, SPN).unwrap();
        let mut found = Vec::new();
        for e in &entries {
            let key = &bytes[e.key.clone()];
            for place in [dir.clone(), std::env::temp_dir(), PathBuf::from("/var/tmp")] {
                holding(&place, key, &mut found);
            }
        }
        found.retain(|p| p != &keytab);
        assert!(found.is_empty(), "the keytab's key reached disk: {found:?}");
        drop(running);
    }
}
