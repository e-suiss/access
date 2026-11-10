//! OP-155 m.3 (n), §10.6.3, IDP-16, IDI-11, OP-153 m.3 (gg): the LDAP gateway against
//! access-server's real edge router over mutual TLS 1.3, on a real PostgreSQL. An LDAP client
//! speaks to the gateway's real listeners with the same codec. Keys, certificates and app
//! passwords are made at run time.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::expect_used,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::assert_is_empty,
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
use access_identity_x509::testing::{Ca, Issued, LeafSpec, OcspAnswer, Status};
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
    LdapAddRequest, LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapExtendedRequest,
    LdapFilter, LdapMatchingRuleAssertion, LdapModifyDNRequest, LdapMsg, LdapOp,
    LdapPasswordModifyRequest, LdapResultCode, LdapSearchRequest, LdapSearchScope, OID_WHOAMI,
    SaslCredentials,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Decoder as _, Encoder as _};

const SPARE: u8 = 12;
const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};
const OCSP: &str = "http://ocsp.corp.example/";

struct EdgeCa {
    pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

fn edge_ca() -> EdgeCa {
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

fn gateway_leaf(ca: &EdgeCa, uri: &str) -> (String, String, [u8; 32]) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    let digest = suiss_crypto::digest::sha256(cert.der());
    (cert.pem(), key.serialize_pem(), digest)
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

struct EveryCa;

impl CaTrust for EveryCa {
    fn accepted(&self, _: [u8; 32], _: [u8; 16]) -> Held<'_> {
        Box::pin(async { Ok(true) })
    }
}

#[derive(Default)]
struct Responders(Mutex<HashMap<String, Vec<u8>>>);

impl Fetch for Responders {
    fn fetch<'a>(&'a self, request: Request<'a>) -> Fetched<'a> {
        let url = match request {
            Request::Ocsp { url, .. } | Request::Crl { url } => url,
        };
        let found = self.0.lock().unwrap().get(url).cloned();
        Box::pin(async move { found.ok_or(Unreachable) })
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
    hasher: Hasher,
    responders: Arc<Responders>,
    ldaps: std::net::SocketAddr,
    starttls: std::net::SocketAddr,
    roots: rustls::RootCertStore,
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

    fn realm(&self) -> Realm<'_> {
        Realm {
            tenant: self.tenant,
            realm: self.corp,
            kek: &self.kek,
            ids: &self.ids,
        }
    }

    async fn tx(&self) -> access_identity_account::adapters::pg::PgTx {
        PgAccounts::sealed(self.db.app.clone(), self.vault.clone())
            .begin(self.tenant, self.corp)
            .await
            .unwrap()
    }

    /// An active account with username `user` and e-mail `user@corp.example`.
    async fn person(&self, user: &str) -> [u8; 16] {
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
    async fn app_password(&self, subject: [u8; 16]) -> ([u8; 16], String) {
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

    async fn revoke(&self, subject: [u8; 16], id: [u8; 16]) {
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

    async fn group(&self, name: &str, members: &[[u8; 16]]) {
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

    async fn epoch(&self, subject: [u8; 16]) -> i64 {
        let mut tx = self.tx().await;
        let s = tx.subject(subject, false).await.unwrap().unwrap();
        tx.commit().await.unwrap();
        s.session_epoch
    }
}

async fn world(seed: u8) -> World {
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
        access_http::edge::router_with(edge, Some(Arc::new(ldap))),
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
    let gw = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
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
    w
}

struct Client<S> {
    s: S,
    buf: BytesMut,
    id: i32,
}

fn tls_config(w: &World, leaf: Option<&Issued>) -> Arc<rustls::ClientConfig> {
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

async fn ldaps(
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
    async fn send(&mut self, op: LdapOp, ctrl: Vec<LdapControl>) -> i32 {
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

    async fn recv(&mut self) -> Option<LdapMsg> {
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
    async fn call(&mut self, op: LdapOp, ctrl: Vec<LdapControl>) -> (Vec<LdapMsg>, LdapMsg) {
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

    async fn bind(&mut self, dn: &str, password: &str) -> LdapResultCode {
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

    async fn search(
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

fn unreachable_entry() -> ldap3_proto::proto::LdapSearchResultEntry {
    panic!("not an entry")
}

fn code(m: &LdapMsg) -> LdapResultCode {
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

fn eq(a: &str, v: &str) -> LdapFilter {
    LdapFilter::Equality(String::from(a), String::from(v))
}

fn values(e: &ldap3_proto::proto::LdapSearchResultEntry, name: &str) -> Vec<String> {
    e.attributes
        .iter()
        .filter(|a| a.atype.eq_ignore_ascii_case(name))
        .flat_map(|a| a.vals.iter().map(|v| String::from_utf8(v.clone()).unwrap()))
        .collect()
}

fn paged(m: &LdapMsg) -> Option<Vec<u8>> {
    m.ctrl.iter().find_map(|c| match c {
        LdapControl::SimplePagedResults { cookie, .. } => Some(cookie.clone()),
        _ => None,
    })
}

// §10.6.3, IDP-16, OP-155 m.3 (n): only the LDAP credential binds, as dn=token or under the
// holder's DN; the realm issuer queues the ldap-bind authentication Claim; the tree, memberOf
// and the in-chain rule
#[tokio::test]
async fn an_app_password_binds_and_reads_the_directory_tree() {
    let w = world(81).await;
    let ada = w.person("ada").await;
    let bob = w.person("bob").await;
    w.group("staff", &[ada]).await;
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    let (_, who) = c
        .call(
            LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: String::from(OID_WHOAMI),
                value: None,
            }),
            Vec::new(),
        )
        .await;
    let LdapOp::ExtendedResponse(x) = &who.op else {
        panic!("{who:?}")
    };
    assert_eq!(
        x.value.as_deref(),
        Some(b"dn:uid=ada,ou=people,o=corp".as_slice())
    );
    let (people, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::Subtree,
            eq("objectClass", "posixAccount"),
            &["uid", "uidNumber", "memberOf", "mail"],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::Success);
    assert_eq!(people.len(), 2);
    let a = people
        .iter()
        .find(|e| e.dn == "uid=ada,ou=people,o=corp")
        .unwrap();
    assert_eq!(values(a, "mail"), vec![String::from("ada@corp.example")]);
    assert_eq!(
        values(a, "memberOf"),
        vec![String::from("cn=staff,ou=groups,o=corp")]
    );
    let n: u32 = values(a, "uidNumber")[0].parse().unwrap();
    assert!(n >= 65_536);
    let (groups, _) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            LdapFilter::And(vec![
                eq("objectClass", "groupOfNames"),
                eq("objectClass", "posixGroup"),
            ]),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(groups.len(), 1);
    assert_eq!(
        values(&groups[0], "member"),
        vec![String::from("uid=ada,ou=people,o=corp")]
    );
    let chain = LdapFilter::Extensible(LdapMatchingRuleAssertion {
        matching_rule: Some(String::from("1.2.840.113556.1.4.1941")),
        type_: Some(String::from("memberOf")),
        match_value: String::from("CN=Staff,OU=Groups,O=Corp"),
        dn_attributes: false,
    });
    let (hits, _) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            chain,
            &["uid"],
            Vec::new(),
        )
        .await;
    assert_eq!(hits.len(), 1);
    assert_eq!(values(&hits[0], "uid"), vec![String::from("ada")]);
    // IDP-16
    let mut d = ldaps(&w, None).await;
    assert_eq!(
        d.bind("uid=ada,ou=people,o=corp", &token).await,
        LdapResultCode::Success
    );
    assert_eq!(
        d.bind("uid=bob,ou=people,o=corp", &token).await,
        LdapResultCode::InvalidCredentials
    );
    let _ = bob;
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("login.ldap.succeeded")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("login.ldap.failed")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("credential.ldap.issued")),
        "{audit:?}"
    );
    assert!(
        outbox.iter().any(|k| k.ends_with("authentication")),
        "{outbox:?}"
    );
    assert!(
        outbox
            .iter()
            .any(|k| k == "relay.message.ldap_credential_changed.v1"),
        "{outbox:?}"
    );
}

// IDP-16, §10.6.3: a primary password never binds; only the LDAP credential class does
#[tokio::test]
async fn a_primary_password_never_binds() {
    let w = world(82).await;
    let ada = w.person("ada").await;
    let primary = String::from("correct horse battery staple 1");
    {
        let mut tx = w.tx().await;
        let phc = w
            .hasher
            .hash(
                &access_identity_account::domain::password::Password::new(&primary).unwrap(),
                [3; 16],
            )
            .await
            .unwrap();
        access_identity_account::app::accounts::store_password(
            &mut tx,
            &w.realm(),
            ada,
            phc.expose(),
            &ADMIN,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let mut c = ldaps(&w, None).await;
    assert_eq!(
        c.bind("uid=ada,ou=people,o=corp", &primary).await,
        LdapResultCode::InvalidCredentials
    );
    assert_eq!(
        c.bind("dn=token", &primary).await,
        LdapResultCode::InvalidCredentials
    );
    let (_, done) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::InsufficentAccessRights);
}

// §10.6.3, Ek B 4975, 5049: unauthenticated binds are refused, anonymous reads only the root DSE,
// and neither DIGEST-MD5 nor SCRAM is offered
#[tokio::test]
async fn anonymous_reads_only_the_root_dse() {
    let w = world(83).await;
    w.person("ada").await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("", "").await, LdapResultCode::Success);
    let (dse, done) = c
        .search(
            "",
            LdapSearchScope::Base,
            LdapFilter::Present(String::from("objectClass")),
            &["+"],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::Success);
    assert_eq!(
        values(&dse[0], "namingContexts"),
        vec![String::from("o=corp")]
    );
    assert_eq!(
        values(&dse[0], "supportedSASLMechanisms"),
        vec![String::from("EXTERNAL")]
    );
    assert!(values(&dse[0], "supportedControl").contains(&String::from("1.2.840.113556.1.4.319")));
    let (none, done) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &[],
            Vec::new(),
        )
        .await;
    assert!(none.is_empty());
    assert_eq!(code(&done), LdapResultCode::InsufficentAccessRights);
    let (_, done) = c
        .search(
            "cn=Subschema",
            LdapSearchScope::Base,
            LdapFilter::Present(String::from("objectClass")),
            &["+"],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::InsufficentAccessRights);
    assert_eq!(
        c.bind("uid=ada,ou=people,o=corp", "").await,
        LdapResultCode::UnwillingToPerform
    );
    for mechanism in ["DIGEST-MD5", "SCRAM-SHA-256", "PLAIN", "GSSAPI"] {
        let (_, m) = c
            .call(
                LdapOp::BindRequest(LdapBindRequest {
                    dn: String::new(),
                    cred: LdapBindCred::SASL(SaslCredentials {
                        mechanism: String::from(mechanism),
                        credentials: Vec::new(),
                    }),
                }),
                Vec::new(),
            )
            .await;
        assert_eq!(
            code(&m),
            LdapResultCode::AuthMethodNotSupported,
            "{mechanism}"
        );
    }
    let (_, m) = c
        .call(
            LdapOp::BindRequest(LdapBindRequest {
                dn: String::new(),
                cred: LdapBindCred::SASL(SaslCredentials {
                    mechanism: String::from("EXTERNAL"),
                    credentials: Vec::new(),
                }),
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::InappropriateAuthentication);
    let (audit, _) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.ldap.bind.refused")),
        "{audit:?}"
    );
}

// IDP-16, Ek B 5048: the directory is read-only; writes answer unwillingToPerform (53)
#[tokio::test]
async fn writes_answer_unwilling_to_perform() {
    let w = world(84).await;
    let ada = w.person("ada").await;
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    let (_, m) = c
        .call(
            LdapOp::AddRequest(LdapAddRequest {
                dn: String::from("uid=eve,ou=people,o=corp"),
                attributes: Vec::new(),
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::UnwillingToPerform);
    let (_, m) = c
        .call(
            LdapOp::DelRequest(String::from("uid=ada,ou=people,o=corp")),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::UnwillingToPerform);
    let (_, m) = c
        .call(
            LdapOp::ModifyDNRequest(LdapModifyDNRequest {
                dn: String::from("uid=ada,ou=people,o=corp"),
                newrdn: String::from("uid=eve"),
                deleteoldrdn: true,
                new_superior: None,
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::UnwillingToPerform);
    let (audit, _) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.ldap.write.refused")),
        "{audit:?}"
    );
}

// IDP-16, Ek B 4797: StartTLS is off on LDAPS; on the StartTLS listener a simple bind without TLS
// answers confidentialityRequired (13), and binds after StartTLS
#[tokio::test]
async fn a_plain_bind_without_tls_needs_confidentiality() {
    let w = world(85).await;
    let ada = w.person("ada").await;
    let (_, token) = w.app_password(ada).await;
    let tcp = TcpStream::connect(w.starttls).await.unwrap();
    let mut c = Client {
        s: tcp,
        buf: BytesMut::new(),
        id: 0,
    };
    assert_eq!(
        c.bind("dn=token", &token).await,
        LdapResultCode::ConfidentialityRequired
    );
    let (_, m) = c
        .call(
            LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: String::from("1.3.6.1.4.1.1466.20037"),
                value: None,
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::Success);
    let tls = tokio_rustls::TlsConnector::from(tls_config(&w, None))
        .connect(ServerName::try_from("localhost").unwrap(), c.s)
        .await
        .unwrap();
    let mut t = Client {
        s: tls,
        buf: BytesMut::new(),
        id: c.id,
    };
    assert_eq!(t.bind("dn=token", &token).await, LdapResultCode::Success);
    let mut s = ldaps(&w, None).await;
    let (_, m) = s
        .call(
            LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: String::from("1.3.6.1.4.1.1466.20037"),
                value: None,
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::OperationsError);
}

// §10.6.3, OP-155 m.3 (n): paged results with an HMAC'd opaque cookie; a tampered cookie is refused
#[tokio::test]
async fn paged_results_refuse_a_tampered_cookie() {
    let w = world(86).await;
    let ada = w.person("ada").await;
    for u in ["bob", "cem", "dia", "eli"] {
        w.person(u).await;
    }
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    let page = |cookie: Vec<u8>| vec![LdapControl::SimplePagedResults { size: 2, cookie }];
    let filter = || eq("objectClass", "person");
    let (first, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            filter(),
            &["uid"],
            page(Vec::new()),
        )
        .await;
    assert_eq!(first.len(), 2);
    let cookie = paged(&done).unwrap();
    assert!(!cookie.is_empty() && cookie.len() <= 256);
    let (second, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            filter(),
            &["uid"],
            page(cookie.clone()),
        )
        .await;
    assert_eq!(second.len(), 2);
    assert_ne!(first[0].dn, second[0].dn);
    let (third, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            filter(),
            &["uid"],
            page(paged(&done).unwrap()),
        )
        .await;
    assert_eq!(third.len(), 1);
    assert_eq!(paged(&done), Some(Vec::new()));
    let mut forged = cookie.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let (none, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            filter(),
            &["uid"],
            page(forged),
        )
        .await;
    assert!(none.is_empty());
    assert_eq!(code(&done), LdapResultCode::UnwillingToPerform);
    let (none, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            eq("uid", "bob"),
            &["uid"],
            page(cookie),
        )
        .await;
    assert!(none.is_empty());
    assert_eq!(code(&done), LdapResultCode::UnwillingToPerform);
}

// GHSA-qcxq-75wr-5cm8, OP-125, Ek B 5102: a deeply nested BER message is refused before decoding
// and without recursion; an oversized length closes the connection before its body is read
#[tokio::test]
async fn hostile_ber_is_refused_before_decoding() {
    let w = world(87).await;
    let mut inner = vec![0x04, 0x00];
    for _ in 0..5000 {
        let mut next = vec![0x30, 0x83];
        next.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_be_bytes()[1..]);
        next.extend_from_slice(&inner);
        inner = next;
    }
    let mut c = ldaps(&w, None).await;
    c.s.write_all(&inner).await.unwrap();
    assert!(c.recv().await.is_none());
    let mut d = ldaps(&w, None).await;
    d.s.write_all(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff])
        .await
        .unwrap();
    assert!(d.recv().await.is_none());
    let mut e = ldaps(&w, None).await;
    assert_eq!(e.bind("", "").await, LdapResultCode::Success);
    let (audit, _) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.ldap.ber.refused")),
        "{audit:?}"
    );
}

// §10.6.3, RFC 3062, Ek B 4799: a password modify changes only the LDAP credential just presented,
// with a notice, a session_epoch bump and a new authenticator-binding Claim (SEC18 cooling)
#[tokio::test]
async fn password_modify_replaces_only_the_ldap_credential() {
    let w = world(88).await;
    let ada = w.person("ada").await;
    let (_, token) = w.app_password(ada).await;
    let (_, other) = w.app_password(ada).await;
    let before = w.epoch(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    let modify = |old: Option<&str>, new: Option<&str>| {
        LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: None,
                old_password: old.map(String::from),
                new_password: new.map(String::from),
            }
            .into(),
        )
    };
    let (_, m) = c
        .call(modify(Some(&token), Some("chosen")), Vec::new())
        .await;
    assert_eq!(code(&m), LdapResultCode::UnwillingToPerform);
    let guess = format!("{}x", &token[..token.len() - 1]);
    let (_, m) = c.call(modify(Some(&guess), None), Vec::new()).await;
    assert_eq!(code(&m), LdapResultCode::InvalidCredentials);
    let (_, m) = c.call(modify(Some(&token), None), Vec::new()).await;
    assert_eq!(code(&m), LdapResultCode::Success);
    let LdapOp::ExtendedResponse(x) = &m.op else {
        panic!("{m:?}")
    };
    let fresh = ldap3_proto::proto::LdapPasswordModifyResponse::try_from(x)
        .unwrap()
        .gen_password
        .unwrap();
    assert_ne!(fresh, token);
    assert!(w.epoch(ada).await > before);
    let mut d = ldaps(&w, None).await;
    assert_eq!(
        d.bind("dn=token", &token).await,
        LdapResultCode::InvalidCredentials
    );
    assert_eq!(d.bind("dn=token", &fresh).await, LdapResultCode::Success);
    assert_eq!(d.bind("dn=token", &other).await, LdapResultCode::Success);
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("credential.ldap.rotated")),
        "{audit:?}"
    );
    assert!(
        outbox
            .iter()
            .filter(|k| k.ends_with("authenticator_binding"))
            .count()
            >= 3,
        "{outbox:?}"
    );
}

// §10.6.3, Ek B 4798: SASL EXTERNAL with a client certificate the realm's certificate sign-in
// accepts; revocation fails closed
#[tokio::test]
async fn sasl_external_binds_with_an_accepted_certificate() {
    let w = world(89).await;
    w.person("ada").await;
    let now = now_s();
    let root = Ca::root_at("Corp Root", now);
    let leaf = root.leaf(&LeafSpec {
        cn: "Ada",
        email: Some("ada@corp.example"),
        ocsp: Some(OCSP),
        ..LeafSpec::default()
    });
    {
        let mut tx = TenantTx::begin(&w.db.app, w.tenant, w.corp).await.unwrap();
        let b = w.bound(&mut tx, "idp.realm.certificate_login").await;
        tx.put_certificate_login(
            &b,
            &access_store::certificate::CertificateLoginRow {
                enabled: true,
                rule: String::from("san_email"),
                anchors: vec![root.der.clone()],
                piv_policies: Vec::new(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let external = || {
        LdapOp::BindRequest(LdapBindRequest {
            dn: String::new(),
            cred: LdapBindCred::SASL(SaslCredentials {
                mechanism: String::from("EXTERNAL"),
                credentials: Vec::new(),
            }),
        })
    };
    let mut c = ldaps(&w, Some(&leaf)).await;
    let (_, m) = c.call(external(), Vec::new()).await;
    assert_eq!(code(&m), LdapResultCode::InvalidCredentials);
    w.responders.0.lock().unwrap().insert(
        String::from(OCSP),
        root.ocsp(&leaf.der, &OcspAnswer::current_at(Status::Good, now), None),
    );
    let mut d = ldaps(&w, Some(&leaf)).await;
    let (_, m) = d.call(external(), Vec::new()).await;
    assert_eq!(code(&m), LdapResultCode::Success);
    let (hits, _) = d
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &["uid"],
            Vec::new(),
        )
        .await;
    assert_eq!(hits.len(), 1);
}

// §10.6.3: revoking an app password ends what its bind may read
#[tokio::test]
async fn a_revoked_app_password_reads_nothing() {
    let w = world(90).await;
    let ada = w.person("ada").await;
    let (id, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    w.revoke(ada, id).await;
    let (none, done) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &["uid"],
            Vec::new(),
        )
        .await;
    assert!(none.is_empty());
    assert_eq!(code(&done), LdapResultCode::InsufficentAccessRights);
    let mut d = ldaps(&w, None).await;
    assert_eq!(
        d.bind("dn=token", &token).await,
        LdapResultCode::InvalidCredentials
    );
}
