//! The LDAP gateway's test world: access-server's real edge router over mutual TLS 1.3 on a
//! real PostgreSQL, the gateway's real listeners, and an LDAP client with the same codec.

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
    clippy::similar_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_edge_core::EdgeCore;
use access_edge_core::channel::{Channel, ChannelConfig};
use access_edge_core::governor::Governor;
use access_gw_ldap::server::{self, Listener};
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
use access_identity_edge::adapters::{PgRegistry, register};
use access_identity_edge::app::ldap::{Certificates, Ldap};
use access_identity_edge::app::{Edge, Vaults};
use access_identity_x509::app::Revocation;
use access_identity_x509::ports::{CaTrust, Fetch, Fetched, Held, Request, Unreachable};
use access_identity_x509::testing::Issued;
use access_internal_api::edge::GatewayKind;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use bytes::BytesMut;
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapFilter, LdapMsg, LdapOp, LdapResultCode,
    LdapSearchRequest, LdapSearchScope,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Decoder as _, Encoder as _};

pub const SPARE: u8 = 12;
pub const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};
pub const OCSP: &str = "http://ocsp.corp.example/";

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

pub fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
            beside: vec![],
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

pub struct EveryCa;

impl CaTrust for EveryCa {
    fn accepted(&self, _: [u8; 32], _: [u8; 16]) -> Held<'_> {
        Box::pin(async { Ok(true) })
    }
}

#[derive(Default)]
pub struct Responders(pub Mutex<HashMap<String, Vec<u8>>>);

impl Fetch for Responders {
    fn fetch<'a>(&'a self, request: Request<'a>) -> Fetched<'a> {
        let url = match request {
            Request::Ocsp { url, .. } | Request::Crl { url } => url,
        };
        let found = self.0.lock().unwrap().get(url).cloned();
        Box::pin(async move { found.ok_or(Unreachable) })
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
    pub responders: Arc<Responders>,
    pub ldaps: std::net::SocketAddr,
    pub starttls: std::net::SocketAddr,
    pub roots: rustls::RootCertStore,
    pub ca_pem: String,
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
    pub async fn app_password(&self, subject: [u8; 16]) -> ([u8; 16], String) {
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
            "Mail client",
            cx,
        )
        .await
        .unwrap()
        .unwrap();
        tx.commit().await.unwrap();
        (issued.id, issued.token.expose().clone())
    }

    pub async fn revoke(&self, subject: [u8; 16], id: [u8; 16]) {
        let realm = self.realm();
        let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock);
        let mut tx = self.tx().await;
        let at_ms = tx.server_time().await.unwrap();
        let cx = Context {
            actor: "usr_test",
            correlation: "req_test",
            at_ms,
        };
        credentials::revoke(&mut tx, &notifier, subject, id, cx)
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
    }

    pub async fn group(&self, name: &str, members: &[[u8; 16]]) {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.corp)
            .await
            .unwrap();
        let b = self.bound(&mut tx, "idp.group.create").await;
        access_store::idp::realm::insert_group(
            &mut tx,
            &b,
            &access_store::idp::realm::GroupRow {
                name: String::from(name),
                display_name: String::from("Staff"),
                membership_issuer: String::from("admin"),
                active: true,
                position: 0,
            },
        )
        .await
        .unwrap();
        let b = self.bound(&mut tx, "idp.group.members_add").await;
        access_store::idp::realm::add_members(&mut tx, &b, name, members)
            .await
            .unwrap();
        tx.commit().await.unwrap();
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

    pub async fn epoch(&self, subject: [u8; 16]) -> i64 {
        let mut tx = self.tx().await;
        let s = tx.subject(subject, false).await.unwrap().unwrap();
        tx.commit().await.unwrap();
        s.session_epoch
    }
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
    let responders = Arc::new(Responders::default());
    let hasher = || Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 2, None));
    let ldap = Ldap::new(
        TestVaults(vault.clone()),
        db.app.clone(),
        (
            Arc::new(hasher()),
            Arc::new(SystemEntropy),
            Arc::new(SystemClock),
        ),
        Arc::new(IdKey::new(Secret::new([seed.wrapping_add(1); 32]))),
        Some(Certificates {
            revocation: Arc::new(Revocation::new(responders.clone())),
            trust: Arc::new(EveryCa),
        }),
    );
    let edge = Edge::new(
        PgRegistry(db.router.clone()),
        TestVaults(vault.clone()),
        db.app.clone(),
    );
    let app = access_http::harden(
        access_http::edge::router_with_ldap(edge, None, Some(Arc::new(ldap))),
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
        responders,
        ldaps: edge_addr,
        starttls: edge_addr,
        roots: rustls::RootCertStore::empty(),
        ca_pem: String::new(),
    };
    let (chain, key, cert) = gateway_leaf(&ca, "urn:suiss:access:gw:ldap:corp-ldap");
    let mut tx = TenantTx::begin(&w.db.app, w.tenant, w.corp).await.unwrap();
    let b = w.bound(&mut tx, "idp.gateway.register").await;
    register(&mut tx, &b, GatewayKind::Ldap, "corp-ldap", &cert)
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
    let ldaps = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    w.ldaps = ldaps.local_addr().unwrap();
    w.starttls = plain.local_addr().unwrap();
    tokio::spawn(server::ldaps(ldaps, listener.clone()));
    tokio::spawn(server::starttls(plain, listener));
    w.roots.add(gw.cert.der().clone()).unwrap();
    w.ca_pem = gw.cert.pem();
    w
}

pub struct Client<S> {
    pub s: S,
    pub buf: BytesMut,
    pub id: i32,
}

pub fn tls_config(w: &World, leaf: Option<&Issued>) -> Arc<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(w.roots.clone());
    Arc::new(match leaf {
        None => builder.with_no_client_auth(),
        Some(i) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(i.der.clone())],
                PrivateKeyDer::try_from(i.key.serialize_der()).unwrap(),
            )
            .unwrap(),
    })
}

pub async fn ldaps(
    w: &World,
    leaf: Option<&Issued>,
) -> Client<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(w.ldaps).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(tls_config(w, leaf))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    Client {
        s: tls,
        buf: BytesMut::new(),
        id: 0,
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    pub async fn send(&mut self, op: LdapOp, ctrl: Vec<LdapControl>) -> i32 {
        self.id += 1;
        let mut out = BytesMut::new();
        ldap3_proto::LdapCodec::default()
            .encode(
                LdapMsg {
                    msgid: self.id,
                    op,
                    ctrl,
                },
                &mut out,
            )
            .unwrap();
        self.s.write_all(&out).await.unwrap();
        self.id
    }

    pub async fn recv(&mut self) -> Option<LdapMsg> {
        let mut codec = ldap3_proto::LdapCodec::new(Some(4 * 1024 * 1024), None);
        loop {
            if let Ok(Some(m)) = codec.decode(&mut self.buf) {
                return Some(m);
            }
            let mut chunk = [0_u8; 8192];
            let n = tokio::time::timeout(Duration::from_secs(20), self.s.read(&mut chunk))
                .await
                .ok()?
                .ok()?;
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Sends `op` and reads until its final answer: the entries and the final message.
    pub async fn call(&mut self, op: LdapOp, ctrl: Vec<LdapControl>) -> (Vec<LdapMsg>, LdapMsg) {
        self.send(op, ctrl).await;
        let mut entries = Vec::new();
        loop {
            let m = self.recv().await.expect("an answer");
            if matches!(m.op, LdapOp::SearchResultEntry(_)) {
                entries.push(m);
            } else {
                return (entries, m);
            }
        }
    }

    pub async fn bind(&mut self, dn: &str, password: &str) -> LdapResultCode {
        let (_, m) = self
            .call(
                LdapOp::BindRequest(LdapBindRequest {
                    dn: String::from(dn),
                    cred: LdapBindCred::Simple(String::from(password)),
                }),
                Vec::new(),
            )
            .await;
        match m.op {
            LdapOp::BindResponse(r) => r.res.code,
            other => panic!("{other:?}"),
        }
    }

    pub async fn search(
        &mut self,
        base: &str,
        scope: LdapSearchScope,
        filter: LdapFilter,
        attrs: &[&str],
        ctrl: Vec<LdapControl>,
    ) -> (Vec<ldap3_proto::proto::LdapSearchResultEntry>, LdapMsg) {
        let (entries, done) = self
            .call(
                LdapOp::SearchRequest(LdapSearchRequest {
                    base: String::from(base),
                    scope,
                    aliases: LdapDerefAliases::Never,
                    sizelimit: 0,
                    timelimit: 0,
                    typesonly: false,
                    filter,
                    attrs: attrs.iter().map(|a| String::from(*a)).collect(),
                }),
                ctrl,
            )
            .await;
        let entries = entries
            .into_iter()
            .map(|m| match m.op {
                LdapOp::SearchResultEntry(e) => e,
                _ => unreachable_entry(),
            })
            .collect();
        (entries, done)
    }
}

pub fn unreachable_entry() -> ldap3_proto::proto::LdapSearchResultEntry {
    panic!("not an entry")
}

pub fn code(m: &LdapMsg) -> LdapResultCode {
    match &m.op {
        LdapOp::SearchResultDone(r)
        | LdapOp::AddResponse(r)
        | LdapOp::DelResponse(r)
        | LdapOp::ModifyDNResponse(r)
        | LdapOp::ModifyResponse(r)
        | LdapOp::CompareResult(r) => r.code.clone(),
        LdapOp::BindResponse(b) => b.res.code.clone(),
        LdapOp::ExtendedResponse(x) => x.res.code.clone(),
        other => panic!("{other:?}"),
    }
}

pub fn eq(a: &str, v: &str) -> LdapFilter {
    LdapFilter::Equality(String::from(a), String::from(v))
}

pub fn values(e: &ldap3_proto::proto::LdapSearchResultEntry, name: &str) -> Vec<String> {
    e.attributes
        .iter()
        .filter(|a| a.atype.eq_ignore_ascii_case(name))
        .flat_map(|a| a.vals.iter().map(|v| String::from_utf8(v.clone()).unwrap()))
        .collect()
}

pub fn paged(m: &LdapMsg) -> Option<Vec<u8>> {
    m.ctrl.iter().find_map(|c| match c {
        LdapControl::SimplePagedResults { cookie, .. } => Some(cookie.clone()),
        _ => None,
    })
}
