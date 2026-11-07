//! OP-151 m.3 (k), (l), TN-39…TN-43, CR-27, E30 on a real PostgreSQL: identity plane CAEP/RISC
//! SETs reach only receivers that already know the subject, the stream profile decides with or
//! instead, inbound SETs become Claims or a session end and never revoke a Grant, a replay does
//! nothing twice, delay is declared, and receivers acknowledge.

#![allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use access_crypto::jose::JwsAlg;
use access_crypto::opaque_id::IdKey;
use access_crypto::secret::Secret;
use access_identity_account::app::signal::emit_tenant;
use access_identity_account::domain::signal::SignalKind;
use access_identity_account::domain::signal::{Initiator, Signal, realm_key_compromise};
use access_identity_events::adapters::{KekSealer, RealmKek};
use access_identity_events::app::Db;
use access_identity_events::app::fanout::Fanout;
use access_identity_events::app::receiver::{Receiver, declare};
use access_identity_events::app::streams::{StreamError, Streams};
use access_identity_events::domain::inbound::{Reject, TransmitterConfig, subject_digest};
use access_identity_events::domain::mapping::signal_uri;
use access_identity_events::domain::stream::parse_stream;
use access_identity_events::ports::{Clock, TokenSigner, Unavailable};
use access_identity_oauth::adapters::oauth::OsRandom;
use access_identity_oauth::ports::dpop::ClockUnavailable;
use access_identity_oauth::ports::oauth::ClientKeys;
use access_identity_oauth::ports::{Directory, RealmEntry};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{ClientRow, Decision, bind, create_settings, insert_client};
use access_store::scope::DomainId;
use access_store::ssf::TransmitterRow;
use access_store::tenancy::{create_realm, create_tenant, set_issuer};
use access_store::testing::{TestDb, fresh};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::{Value as Json, json};
use suiss_crypto::envelope::{Kek, SoftKek};

const ISSUER: &str = "https://id.test/realms/shop";
const UPSTREAM: &str = "https://upstream.example";
const T0: u64 = 1_793_750_400_000;

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct OneKek(Arc<SoftKek>);

impl RealmKek for OneKek {
    fn kek(&self, _: TenantId, _: RealmId) -> Option<Arc<dyn Kek + Send + Sync>> {
        Some(self.0.clone())
    }
}

fn sealer() -> KekSealer<OneKek> {
    KekSealer(OneKek(Arc::new(SoftKek::new("realm-kek-1", [9; 32]))))
}

struct ClearSigner;

impl TokenSigner for ClearSigner {
    fn sign(
        &self,
        _: RealmId,
        alg: JwsAlg,
        typ: &str,
        payload: &[u8],
        _: u64,
    ) -> impl std::future::Future<Output = Result<String, Unavailable>> + Send {
        let header = format!(r#"{{"alg":"{}","typ":"{typ}"}}"#, alg.name());
        std::future::ready(Ok(format!(
            "{}.{}.c2ln",
            b64url_encode(header.as_bytes()),
            b64url_encode(payload)
        )))
    }

    fn jwks(
        &self,
        _: RealmId,
    ) -> impl std::future::Future<Output = Result<String, Unavailable>> + Send {
        std::future::ready(Ok(String::from("{}")))
    }
}

/// The upstream transmitter's published keys.
struct Keys(String);

impl ClientKeys for Keys {
    fn fetch(
        &self,
        _: &str,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Unavailable>> + Send {
        std::future::ready(Ok(self.0.clone().into_bytes()))
    }
}

/// The receiver is reached by its transmitter id only in these tests.
struct NoDirectory;

impl Directory for NoDirectory {
    fn by_host(
        &self,
        _: &str,
    ) -> impl std::future::Future<Output = Result<Option<RealmEntry>, Unavailable>> + Send {
        std::future::ready(Ok(None))
    }

    fn by_slug(
        &self,
        _: &str,
    ) -> impl std::future::Future<Output = Result<Option<RealmEntry>, Unavailable>> + Send {
        std::future::ready(Ok(None))
    }

    fn all(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<RealmEntry>, Unavailable>> + Send {
        std::future::ready(Ok(Vec::new()))
    }
}

struct World {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    clock: TestClock,
    subject: [u8; 16],
}

const CLIENT: &str = "cli_00000000000000000000000001";

impl World {
    async fn new() -> Self {
        let db = fresh().await.unwrap();
        let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
        let domain = DomainId::from_bytes([7; 32]);
        let genesis = LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 1,
            leaf_hash: [7; 32],
            envelope: vec![0xa0],
        };
        create_domain(&db.sequencer, &domain, *tenant.as_bytes(), &genesis, &[])
            .await
            .unwrap();
        let (lease, head) = acquire_lease(&db.sequencer, &domain, "a", Duration::from_secs(10))
            .await
            .unwrap();
        let next = HeadRow {
            pos: head.pos + 1,
            epoch: lease.epoch,
            leaf_hash: [1; 32],
            recorded_at: 2,
            frontier: vec![[1; 32]],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos: head.pos + 1,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: [1; 32],
                envelope: vec![0xa1, 1],
            }],
            head: next,
            nonces: vec![NonceRow {
                nonce: vec![1; 16],
                actor: vec![1],
                intent_digest: [9; 32],
                decision_pos: head.pos + 1,
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
        commit_batch(&db.sequencer, &domain, *tenant.as_bytes(), &batch)
            .await
            .unwrap();
        let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
        let realm = create_realm(&mut t, &domain, "shop", "pool-default")
            .await
            .unwrap();
        t.enter_realm(realm).await.unwrap();
        assert!(set_issuer(&mut t, ISSUER).await.unwrap());
        create_settings(&mut t).await.unwrap();
        let b = bind(
            &mut t,
            &Decision {
                domain: &domain,
                position: 1,
                nonce: &[1; 16],
                intent: [9; 32],
                change: [5; 32],
                action: "idp.client.register",
            },
        )
        .await
        .unwrap()
        .unwrap();
        insert_client(&mut t, &b, &client_row()).await.unwrap();
        let subject = t
            .insert_subject("active", "realm-kek:1", &[9; 40])
            .await
            .unwrap();
        t.commit().await.unwrap();
        Self {
            db,
            tenant,
            realm,
            clock: TestClock(Arc::new(AtomicU64::new(T0))),
            subject,
        }
    }

    fn pools(&self) -> Db {
        Db {
            app: self.db.app.clone(),
            reader: self.db.reader.clone(),
            ids: Arc::new(IdKey::new(Secret::new([4; 32]))),
        }
    }

    fn streams(&self) -> Streams<KekSealer<OneKek>, OsRandom> {
        Streams::new(self.pools(), sealer(), OsRandom)
    }

    async fn tx(&self) -> TenantTx {
        TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap()
    }

    /// A poll stream to `aud` for `events`, with `profile`; its bearer credential.
    async fn poll_stream(&self, aud: &str, events: &[String], profile: &str) -> String {
        let body = serde_json::to_vec(&json!({
            "delivery": {"method": "urn:ietf:rfc:8936"},
            "aud": aud,
            "events_requested": events,
            "profile": profile,
        }))
        .unwrap();
        let created = self
            .streams()
            .create(self.tenant, self.realm, &parse_stream(&body).unwrap())
            .await
            .unwrap();
        assert_eq!(created.stream["profile"], profile);
        created.token.unwrap().to_string()
    }

    /// The SET claims a poll returns now, acknowledged (RFC 8936 §2.4).
    async fn polled(&self, token: &str) -> Vec<Json> {
        let poll = |body: Vec<u8>| async move {
            self.streams()
                .poll(
                    &ClearSigner,
                    &self.clock,
                    self.tenant,
                    self.realm,
                    token,
                    &body,
                )
                .await
                .unwrap()
        };
        let v = poll(b"{}".to_vec()).await;
        let sets = v["sets"].as_object().unwrap();
        let ack: Vec<&String> = sets.keys().collect();
        poll(serde_json::to_vec(&json!({"ack": ack, "maxEvents": 0})).unwrap()).await;
        sets.values()
            .map(|t| {
                let p = t.as_str().unwrap().split('.').nth(1).unwrap();
                serde_json::from_slice(&b64url_decode(p).unwrap()).unwrap()
            })
            .collect()
    }

    async fn signal(&self, s: &Signal) {
        let mut t = self.tx().await;
        emit_tenant(&mut t, s).await.unwrap();
        t.commit().await.unwrap();
    }

    /// Steps the identity fan-out until `n` deliveries are queued. The outbox watermark is
    /// cluster-wide, so another test's open transaction delays an event, never loses it.
    async fn settle(&self, n: u32) {
        let fanout = Fanout::new(self.pools(), self.clock.clone());
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut total = 0;
        while total < n {
            total += fanout.identity_step().await.unwrap();
            assert!(std::time::Instant::now() < deadline, "{total} of {n}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn epoch(&self) -> i64 {
        let mut t = self.tx().await;
        let e = t
            .subject(self.subject, false)
            .await
            .unwrap()
            .unwrap()
            .session_epoch;
        t.commit().await.unwrap();
        e
    }

    async fn outbox_kinds(&self) -> Vec<String> {
        let mut t = self.tx().await;
        let kinds = t.outbox_kinds().await.unwrap();
        t.commit().await.unwrap();
        kinds
    }
}

fn client_row() -> ClientRow {
    ClientRow {
        client_uuid: [3; 16],
        client_id: String::from(CLIENT),
        display_name: String::from("RP"),
        auth_method: String::from("none"),
        jwks_uri: None,
        redirect_uris: vec![String::from("https://rp.example/cb")],
        active: true,
        secret_hash: None,
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        jwks: None,
        platform_product: None,
        service_key: None,
        event_receiver: None,
        require_par: false,
        public_sub: false,
        sector_identifier_uri: None,
    }
}

// TN-39, TN-41, MD-10, TI-RT10: a realm holds several streams; an identity plane signal reaches
// a receiver only through the pairwise sub it already has; the SET is iss_sub, one event, txn,
// no sub, no exp
#[tokio::test]
async fn signals_name_the_subject_by_the_receivers_own_sub() {
    let w = World::new().await;
    let uri = signal_uri(SignalKind::SessionRevoked);
    let compromise = signal_uri(SignalKind::CredentialCompromise);
    let rp = w
        .poll_stream(CLIENT, &[uri.clone(), compromise.clone()], "both")
        .await;
    let stranger = w
        .poll_stream("cli_unknown", &[uri.clone(), compromise.clone()], "both")
        .await;
    w.signal(&Signal::session_revoked(
        [1; 32],
        w.subject,
        Initiator::User,
        T0,
    ))
    .await;
    w.signal(&realm_key_compromise([9; 32], T0)).await;
    w.settle(2).await;
    let sets = w.polled(&rp).await;
    assert_eq!(
        sets.len(),
        1,
        "no pairwise sub yet: only the realm-wide signal"
    );
    assert!(sets[0]["events"].get(&compromise).is_some());
    let mut t = w.tx().await;
    let sub = t
        .pairwise(w.subject, [3; 16], &b64url_encode(&[6; 32]))
        .await
        .unwrap();
    t.commit().await.unwrap();
    w.signal(&Signal::session_revoked(
        [2; 32],
        w.subject,
        Initiator::User,
        T0,
    ))
    .await;
    w.settle(1).await;
    let sets = w.polled(&rp).await;
    assert_eq!(sets.len(), 1);
    let s = &sets[0];
    assert_eq!(
        s["sub_id"],
        json!({"format": "iss_sub", "iss": ISSUER, "sub": sub})
    );
    assert_eq!(s["events"].as_object().unwrap().len(), 1);
    assert!(s["events"][&uri]["event_timestamp"].is_u64());
    assert!(s.get("sub").is_none() && s.get("exp").is_none());
    assert!(s["txn"].is_string() && s["jti"] != json!(b64url_encode(&[2; 32])));
    let other = w.polled(&stranger).await;
    assert_eq!(other.len(), 1, "a stranger gets the realm-wide signal only");
    assert!(other[0]["events"].get(&uri).is_none());
}

// CR-27: a realm key compromise reaches every stream that asked, naming the realm issuer
#[tokio::test]
async fn a_realm_key_compromise_reaches_every_stream() {
    let w = World::new().await;
    let uri = signal_uri(SignalKind::CredentialCompromise);
    let a = w
        .poll_stream(CLIENT, std::slice::from_ref(&uri), "both")
        .await;
    let b = w
        .poll_stream("cli_other", std::slice::from_ref(&uri), "both")
        .await;
    w.signal(&realm_key_compromise([5; 32], T0)).await;
    w.settle(2).await;
    for token in [a, b] {
        let sets = w.polled(&token).await;
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0]["sub_id"], json!({"format": "uri", "uri": ISSUER}));
        assert_eq!(sets[0]["events"][&uri]["credential_type"], "x509");
    }
}

// TN-40, OP-151 m.3 (k): ES256 is the default; RS256 is refused with unsupported_alg
#[tokio::test]
async fn rs256_streams_are_refused() {
    let w = World::new().await;
    let body = |alg: &str| {
        serde_json::to_vec(&json!({
            "delivery": {"method": "urn:ietf:rfc:8936"},
            "aud": CLIENT,
            "events_requested": [signal_uri(SignalKind::SessionRevoked)],
            "alg": alg,
        }))
        .unwrap()
    };
    let rs = w
        .streams()
        .create(w.tenant, w.realm, &parse_stream(&body("RS256")).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(rs, StreamError::UnsupportedAlg));
    assert_eq!(rs.problem(), (400, "unsupported_alg"));
    let es = w
        .streams()
        .create(w.tenant, w.realm, &parse_stream(&body("ES256")).unwrap())
        .await
        .unwrap();
    assert_eq!(es.stream["alg"], "ES256");
    assert!(parse_stream(&body("HS256")).is_err());
}

fn ec() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap()
}

fn jwks(k: &EcdsaKeyPair) -> String {
    let p = k.public_key().as_ref();
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"k1","use":"sig","x":"{}","y":"{}"}}]}}"#,
        b64url_encode(&p[1..33]),
        b64url_encode(&p[33..])
    )
}

fn set(k: &EcdsaKeyPair, kind: SignalKind, jti: &str, body: &Json) -> Vec<u8> {
    let claims = json!({
        "iss": UPSTREAM,
        "aud": ISSUER,
        "iat": T0 / 1000,
        "jti": jti,
        "sub_id": {"format": "iss_sub", "iss": UPSTREAM, "sub": "up-1"},
        "events": {signal_uri(kind): body},
    });
    let input = format!(
        "{}.{}",
        b64url_encode(br#"{"alg":"ES256","kid":"k1","typ":"secevent+jwt"}"#),
        b64url_encode(&serde_json::to_vec(&claims).unwrap())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref())).into_bytes()
}

impl World {
    async fn transmitter(&self, link: bool) -> TransmitterRow {
        let cfg = TransmitterConfig::parse(&json!({
            "issuer": UPSTREAM,
            "jwks_uri": "https://upstream.example/jwks",
            "aud": ISSUER,
            "events": SignalKind::ALL.iter().map(|k| signal_uri(*k)).collect::<Vec<_>>(),
            "expected_interval_s": 3600,
        }))
        .unwrap();
        let mut t = self.tx().await;
        declare(&mut t, &sealer(), [8; 16], &cfg, None, Some([6; 32]))
            .await
            .unwrap();
        if link {
            t.link_upstream_subject(&subject_digest(UPSTREAM, "up-1"), self.subject)
                .await
                .unwrap();
        }
        let row = t.transmitter([8; 16]).await.unwrap().unwrap();
        t.commit().await.unwrap();
        row
    }

    fn receiver(
        &self,
        k: &EcdsaKeyPair,
    ) -> Receiver<NoDirectory, Keys, KekSealer<OneKek>, TestClock> {
        Receiver::new(
            NoDirectory,
            self.pools(),
            Keys(jwks(k)),
            sealer(),
            self.clock.clone(),
        )
    }
}

// §9.16.2 k.4, TN-42, OP-151 m.3 (l), MD-7, U38, EP-5: an inbound session-revoked ends the
// subject's sessions by the time it is taken (the declared processing time is the receipt
// itself) and steps its session_epoch; it is no Grant revocation and writes no authority
// state; a replayed jti does nothing twice
#[tokio::test]
async fn inbound_session_revoked_ends_sessions_and_revokes_no_grant() {
    let w = World::new().await;
    let k = ec();
    let row = w.transmitter(true).await;
    let r = w.receiver(&k);
    let before = w.epoch().await;
    let token = set(
        &k,
        SignalKind::SessionRevoked,
        "j1",
        &json!({"event_timestamp": 1}),
    );
    r.take(w.tenant, w.realm, &row, &token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(w.epoch().await, before + 1);
    r.take(w.tenant, w.realm, &row, &token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(w.epoch().await, before + 1, "a replay does nothing twice");
    let outbox = w.outbox_kinds().await;
    assert_eq!(outbox, vec![String::from("signal.session_revoked")]);
    let authority = access_store::authority::read_outbox(
        &w.db.app,
        &DomainId::from_bytes([7; 32]),
        (0, 0),
        100,
    )
    .await
    .unwrap();
    assert!(
        authority.is_empty(),
        "no inbound event writes authority state"
    );
}

// TN-42, CI-2, PI-9: inbound risk only narrows: a higher level is a risk_signal Claim order, a
// lower level, a compliant device and an unlinked subject do nothing
#[tokio::test]
async fn inbound_risk_is_a_narrowing_claim_only() {
    let w = World::new().await;
    let k = ec();
    let row = w.transmitter(true).await;
    let r = w.receiver(&k);
    let take = |kind, jti: &'static str, body: Json| {
        let token = set(&k, kind, jti, &body);
        let r = &r;
        let row = &row;
        let w = &w;
        async move {
            r.take(w.tenant, w.realm, row, &token)
                .await
                .unwrap()
                .unwrap();
        }
    };
    take(
        SignalKind::RiskLevelChange,
        "a",
        json!({"principal": "USER", "current_level": "LOW"}),
    )
    .await;
    take(
        SignalKind::DeviceComplianceChange,
        "b",
        json!({"previous_status": "not-compliant", "current_status": "compliant"}),
    )
    .await;
    assert_eq!(w.outbox_kinds().await, Vec::<String>::new());
    take(
        SignalKind::RiskLevelChange,
        "c",
        json!({"principal": "USER", "current_level": "HIGH"}),
    )
    .await;
    take(
        SignalKind::CredentialChange,
        "d",
        json!({"credential_type": "password", "change_type": "update"}),
    )
    .await;
    take(SignalKind::AccountDisabled, "e", json!({})).await;
    assert_eq!(
        w.outbox_kinds().await,
        vec![
            String::from("claim.risk_signal"),
            String::from("claim.risk_signal"),
            String::from("claim.account_status"),
        ]
    );
    let epoch = w.epoch().await;
    let unlinked = World::new().await;
    let row2 = unlinked.transmitter(false).await;
    let token = set(&k, SignalKind::SessionRevoked, "f", &json!({}));
    unlinked
        .receiver(&k)
        .take(unlinked.tenant, unlinked.realm, &row2, &token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unlinked.outbox_kinds().await, Vec::<String>::new());
    assert_eq!(w.epoch().await, epoch);
}

// RFC 8935 §2.3: a SET under another key is refused with invalid_key and takes nothing
#[tokio::test]
async fn inbound_sets_under_other_keys_are_refused() {
    let w = World::new().await;
    let row = w.transmitter(true).await;
    let token = set(&ec(), SignalKind::SessionRevoked, "x", &json!({}));
    let refused = w
        .receiver(&ec())
        .take(w.tenant, w.realm, &row, &token)
        .await
        .unwrap();
    assert_eq!(refused, Err(Reject::Key));
    assert_eq!(w.outbox_kinds().await, Vec::<String>::new());
}

// §8.13, L18, INV-24: a silent transmitter is declared delayed; nothing else changes
#[tokio::test]
async fn a_silent_transmitter_is_delayed() {
    let w = World::new().await;
    let k = ec();
    let row = w.transmitter(true).await;
    let r = w.receiver(&k);
    let token = set(&k, SignalKind::SessionPresented, "p", &json!({}));
    r.take(w.tenant, w.realm, &row, &token)
        .await
        .unwrap()
        .unwrap();
    let h = r.health(w.tenant, w.realm).await.unwrap();
    assert_eq!((h[0].last_seen_ms, h[0].delayed_since_ms), (Some(T0), None));
    w.clock.0.fetch_add(3_600_001, Ordering::SeqCst);
    let h = r.health(w.tenant, w.realm).await.unwrap();
    assert_eq!(h[0].delayed_since_ms, Some(T0 + 3_600_000));
    assert_eq!(h[0].issuer, UPSTREAM);
}

// E30: delivery ack, semantic ack and authority-state ack are apart; a semantic ack is taken
// only for a SET the stream was delivered, once
#[tokio::test]
async fn acks_are_apart_and_counted() {
    let w = World::new().await;
    let uri = signal_uri(SignalKind::CredentialCompromise);
    let token = w
        .poll_stream(CLIENT, std::slice::from_ref(&uri), "both")
        .await;
    w.signal(&realm_key_compromise([5; 32], T0)).await;
    w.settle(1).await;
    let sets = w.polled(&token).await;
    let jti = sets[0]["jti"].as_str().unwrap();
    let s = w
        .streams()
        .by_token(w.tenant, w.realm, &token)
        .await
        .unwrap();
    let ack = |jti: &str, state: &str| {
        access_identity_events::domain::control::parse_ack(
            &serde_json::to_vec(&json!({"jti": jti, "state": state})).unwrap(),
        )
        .unwrap()
    };
    let streams = w.streams();
    assert!(
        streams
            .ack(w.tenant, w.realm, &s, &ack(jti, "applied"))
            .await
            .unwrap()
    );
    assert!(
        !streams
            .ack(w.tenant, w.realm, &s, &ack(jti, "ignored"))
            .await
            .unwrap()
    );
    let never = b64url_encode(&[1; 32]);
    assert!(
        !streams
            .ack(w.tenant, w.realm, &s, &ack(&never, "applied"))
            .await
            .unwrap()
    );
    let counts = streams.ack_counts(w.tenant, w.realm).await.unwrap();
    assert_eq!(
        (
            counts.delivered,
            counts.applied,
            counts.ignored,
            counts.authority_state
        ),
        (1, 1, 0, 0)
    );
}

/// An RFC 8936 poll transmitter over TLS on a private address and a port other than 443: the
/// first poll answers `sets`, every later one none; each request it saw, and the trust anchors.
async fn poll_transmitter(
    sets: Json,
) -> (
    u16,
    Arc<rustls::ClientConfig>,
    Arc<std::sync::Mutex<Vec<String>>>,
) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let der = cert.cert.der().clone();
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
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut s) = acceptor.accept(tcp).await else {
                continue;
            };
            let mut buf = Vec::new();
            let mut chunk = [0_u8; 4096];
            let head = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
                let n = s.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&chunk[..n]);
            };
            let text = String::from_utf8_lossy(&buf[..head]).to_ascii_lowercase();
            let length: usize = text
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            while buf.len() < head + length {
                let n = s.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            let first = {
                let mut l = log.lock().unwrap();
                l.push(String::from_utf8_lossy(&buf).into_owned());
                l.len() == 1
            };
            let answer = if first {
                json!({ "sets": sets, "moreAvailable": false })
            } else {
                json!({ "sets": {}, "moreAvailable": false })
            };
            let body = serde_json::to_vec(&answer).unwrap();
            let mut reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            reply.extend_from_slice(&body);
            s.write_all(&reply).await.unwrap();
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
    (port, Arc::new(tls), seen)
}

// OP-151 m.3 (l), RFC 8936, OP-149 m.23 (S-1): the poll client reads the transmitter's answer
// through the SSRF-guarded client, reaches a declared poll endpoint, takes the SETs it returns
// with the bearer credential, and acknowledges them in the next request
#[tokio::test]
async fn polling_a_declared_transmitter_takes_its_sets() {
    use access_identity_events::adapters::OutboundTransport;
    use access_identity_oauth::adapters::outbound::{DeclaredTarget, Outbound};

    let w = World::new().await;
    let k = ec();
    let compact = set(&k, SignalKind::SessionRevoked, "p1", &json!({}));
    let sets = json!({ "p1": String::from_utf8(compact).unwrap() });
    let (port, tls, seen) = poll_transmitter(sets).await;
    let url = format!("https://localhost:{port}/ssf/poll");
    let cfg = TransmitterConfig::parse(&json!({
        "issuer": UPSTREAM,
        "jwks_uri": "https://upstream.example/jwks",
        "aud": ISSUER,
        "events": SignalKind::ALL.iter().map(|k| signal_uri(*k)).collect::<Vec<_>>(),
        "poll_endpoint": url,
    }))
    .unwrap();
    let mut t = w.tx().await;
    declare(&mut t, &sealer(), [8; 16], &cfg, Some(b"poll-bearer"), None)
        .await
        .unwrap();
    t.link_upstream_subject(&subject_digest(UPSTREAM, "up-1"), w.subject)
        .await
        .unwrap();
    let row = t.transmitter([8; 16]).await.unwrap().unwrap();
    t.commit().await.unwrap();
    let before = w.epoch().await;

    let undeclared = OutboundTransport(Outbound::new(tls.clone(), Duration::from_secs(5)));
    assert!(
        w.receiver(&k)
            .poll_once(&undeclared, w.tenant, w.realm, &row)
            .await
            .is_err(),
        "an undeclared private endpoint is never reached"
    );
    assert!(seen.lock().unwrap().is_empty());

    let outbound = Outbound::new(tls, Duration::from_secs(5))
        .declaring(vec![DeclaredTarget::new(&url, None).unwrap()]);
    let taken = w
        .receiver(&k)
        .poll_once(&OutboundTransport(outbound), w.tenant, w.realm, &row)
        .await
        .unwrap();
    assert_eq!(taken, 1);
    assert_eq!(w.epoch().await, before + 1);
    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("authorization: Bearer poll-bearer\r\n"));
    let ack = requests[1].split("\r\n\r\n").nth(1).unwrap();
    let ack: Json = serde_json::from_str(ack).unwrap();
    assert_eq!(ack["ack"], json!(["p1"]));
}
