//! The RADIUS gateway's test world: access-server's real edge router over mutual TLS 1.3 on a
//! real PostgreSQL, the gateway's real `RadSec` listener, and a `RadSec` client that speaks
//! RADIUS/1.1. Keys, certificates and app passwords are made at run time.

#![allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::expect_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;
use std::time::Duration;

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_edge_core::EdgeCore;
use access_edge_core::channel::{Channel, ChannelConfig};
use access_edge_core::governor::Governor;
use access_gw_radius::server::{self, Listener};
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::app::accounts::create;
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::ldap::{self as credentials, Context};
use access_identity_account::app::vault::Vault;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_edge::adapters::{PgRegistry, radius_client_register, register};
use access_identity_edge::app::radius::Radius;
use access_identity_edge::app::{Edge, Vaults};
use access_internal_api::edge::GatewayKind;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

pub const SPARE: u8 = 12;
pub const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

pub struct EdgeCa {
    pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

pub fn edge_ca() -> EdgeCa {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let pem = params.self_signed(&key).unwrap().pem();
    EdgeCa {
        pem,
        issuer: rcgen::Issuer::new(params, key),
    }
}

pub fn gateway_leaf(ca: &EdgeCa, uri: &str) -> (String, String, [u8; 32]) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    let digest = suiss_crypto::digest::sha256(cert.der());
    (cert.pem(), key.serialize_pem(), digest)
}

/// A `RadSec` client's certificate and key, made at run time.
pub struct Nas {
    pub der: Vec<u8>,
    pub key: Vec<u8>,
    pub digest: [u8; 32],
}

pub fn nas(name: &str) -> Nas {
    let c = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    Nas {
        der: c.cert.der().to_vec(),
        key: c.signing_key.serialize_der(),
        digest: suiss_crypto::digest::sha256(c.cert.der()),
    }
}

pub async fn domain(db: &TestDb, t: TenantId, seed: u8) -> DomainId {
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
pub struct TestVaults(Vault);

impl Vaults for TestVaults {
    fn vault(&self, _: TenantId, _: RealmId) -> Option<Vault> {
        Some(self.0.clone())
    }
}

pub struct World {
    pub db: TestDb,
    pub tenant: TenantId,
    pub corp: RealmId,
    pub domain: DomainId,
    pub vault: Vault,
    pub kek: SoftKek,
    pub ids: IdKey,
    pub next: std::sync::atomic::AtomicU64,
    pub hasher: Hasher,
    pub radsec: std::net::SocketAddr,
    pub roots: rustls::RootCertStore,
    pub nas: Nas,
}

impl World {
    pub async fn bound(&self, tx: &mut TenantTx, action: &str) -> access_store::idp::Bound {
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

    pub fn realm(&self) -> Realm<'_> {
        Realm {
            tenant: self.tenant,
            realm: self.corp,
            kek: &self.kek,
            ids: &self.ids,
        }
    }

    pub async fn tx(&self) -> access_identity_account::adapters::pg::PgTx {
        PgAccounts::sealed(self.db.app.clone(), self.vault.clone())
            .begin(self.tenant, self.corp)
            .await
            .unwrap()
    }

    /// An active account with username `user` and e-mail `user@corp.example`.
    pub async fn person(&self, user: &str) -> [u8; 16] {
        let pg = PgAccounts::sealed(self.db.app.clone(), self.vault.clone());
        let ids = [
            Identifier::new(IdentifierKind::Username, user).unwrap(),
            Identifier::new(IdentifierKind::Email, &format!("{user}@corp.example")).unwrap(),
        ];
        let s = create(&pg, &self.realm(), &ids, &ADMIN).await.unwrap();
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

    /// A directory app password of `subject`, as the account surface issues it.
    pub async fn app_password(&self, subject: [u8; 16]) -> String {
        let realm = self.realm();
        let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock);
        let mut tx = self.tx().await;
        let at_ms = tx.server_time().await.unwrap();
        let cx = Context {
            actor: "usr_test",
            correlation: "req_test",
            at_ms,
        };
        let issued = credentials::issue(
            &mut tx,
            &self.hasher,
            &SystemEntropy,
            &notifier,
            subject,
            "VPN",
            cx,
        )
        .await
        .unwrap()
        .unwrap();
        tx.commit().await.unwrap();
        issued.token.expose().clone()
    }

    pub async fn rows(&self) -> (Vec<String>, Vec<String>) {
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

    /// A `RadSec` connection with `client`'s certificate, offering `alpn`.
    pub async fn connect(
        &self,
        client: &Nas,
        alpn: &[&[u8]],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(self.roots.clone())
        .with_client_auth_cert(
            vec![CertificateDer::from(client.der.clone())],
            PrivateKeyDer::try_from(client.key.clone()).unwrap(),
        )
        .unwrap();
        config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        let tcp = TcpStream::connect(self.radsec).await?;
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
    }
}

pub const USER_NAME: u8 = 1;
pub const USER_PASSWORD: u8 = 2;
pub const VENDOR_SPECIFIC: u8 = 26;

/// A RADIUS/1.1 packet with `token` and `attrs`.
pub fn packet(code: u8, token: [u8; 4], attrs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut p = vec![code, 0, 0, 0];
    p.extend_from_slice(&token);
    p.extend_from_slice(&[0; 12]);
    for (k, v) in attrs {
        p.push(*k);
        p.push(u8::try_from(v.len() + 2).unwrap());
        p.extend_from_slice(v);
    }
    let n = u16::try_from(p.len()).unwrap().to_be_bytes();
    p[2] = n[0];
    p[3] = n[1];
    p
}

/// Sends `p` and reads one answer; `None` when the gateway closes or stays silent.
pub async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    s: &mut S,
    p: &[u8],
) -> Option<Vec<u8>> {
    s.write_all(p).await.ok()?;
    s.flush().await.ok()?;
    let mut head = [0_u8; 20];
    tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut head))
        .await
        .ok()?
        .ok()?;
    let n = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let mut rest = vec![0_u8; n - 20];
    s.read_exact(&mut rest).await.ok()?;
    let mut out = head.to_vec();
    out.extend_from_slice(&rest);
    Some(out)
}

pub async fn world(seed: u8) -> World {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, tenant, seed).await;
    let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    let corp = create_realm(&mut tx, &d, "corp", "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let vault = Vault::in_memory(
        Arc::new(SoftKek::new("realm-kek:1", [seed; 32])),
        [seed; 32],
    );
    let ca = edge_ca();
    let server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let config = access_http::tls::server_config(
        server.cert.pem().as_bytes(),
        server.signing_key.serialize_pem().as_bytes(),
        Some(ca.pem.as_bytes()),
    )
    .unwrap();
    let hasher = || Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 2, None));
    let radius = Radius::new(
        TestVaults(vault.clone()),
        db.app.clone(),
        Arc::new(hasher()),
    );
    let edge = Edge::new(
        PgRegistry(db.router.clone()),
        TestVaults(vault.clone()),
        db.app.clone(),
    );
    let app = access_http::harden(
        access_http::edge::router_protocols(
            edge,
            access_http::edge::Protocols {
                radius: Some(Arc::new(radius)),
                ..access_http::edge::Protocols::default()
            },
        ),
        access_http::Limits::default(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = listener.local_addr().unwrap();
    tokio::spawn(access_http::tls::serve(
        listener,
        config,
        app,
        std::future::pending(),
    ));
    let mut w = World {
        db,
        tenant,
        corp,
        domain: d,
        vault,
        kek: SoftKek::new("realm-kek:1", [seed; 32]),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        next: std::sync::atomic::AtomicU64::new(1),
        hasher: hasher(),
        radsec: edge_addr,
        roots: rustls::RootCertStore::empty(),
        nas: nas("vpn-1.corp.example"),
    };
    let (chain, key, cert) = gateway_leaf(&ca, "urn:suiss:access:gw:radius:corp-radius");
    let mut tx = TenantTx::begin(&w.db.app, w.tenant, w.corp).await.unwrap();
    let b = w.bound(&mut tx, "idp.gateway.register").await;
    register(&mut tx, &b, GatewayKind::Radius, "corp-radius", &cert)
        .await
        .unwrap();
    let b = w.bound(&mut tx, "idp.gateway.radius_client_register").await;
    radius_client_register(&mut tx, &b, "corp-radius", "vpn-1", &w.nas.digest)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let channel = Channel::new(&ChannelConfig {
        addr: edge_addr.to_string(),
        server_name: String::from("localhost"),
        roots_pem: server.cert.pem().into_bytes(),
        chain_pem: chain.into_bytes(),
        key_pem: key.into_bytes(),
    })
    .unwrap();
    let core = Arc::new(EdgeCore::connect(channel).await.unwrap());
    let gw =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .unwrap();
    let tls = server::acceptor(
        gw.cert.pem().as_bytes(),
        gw.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let listener = Listener {
        core,
        tls,
        governor: Arc::new(Governor::new(1000, 1000)),
    };
    let radsec = TcpListener::bind("127.0.0.1:0").await.unwrap();
    w.radsec = radsec.local_addr().unwrap();
    tokio::spawn(server::radsec(radsec, listener));
    w.roots.add(gw.cert.der().clone()).unwrap();
    w
}
