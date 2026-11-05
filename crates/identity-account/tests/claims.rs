//! The realm issuer's Claims on a real PostgreSQL (CMP-8, §10.1.7, TN-49, OP-150 L2): orders
//! queued with their identity events, placed in the realm's governing domain and handed to Claim
//! Ingest by the courier, at least once.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::accounts::change_status;
use access_identity_account::app::claims::{ClaimSigner, Courier, Issued, emit};
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::claims::{AuthFacts, Bind, RiskSignal, authentication, risk};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::{AccountDb, AccountTx, Clock};
use access_internal_api::claims::{ClaimIngest, ClaimSubmission, ClaimVerdict};
use access_internal_api::idp::Unavailable;
use access_kernel::claim::Statement;
use access_kernel::claim::body::AuthMethod;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::model::{EqValue, Id};
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::bind_subject_party;
use access_store::issuer::{NewDeviceKey, insert_device_key, set_realm_issuer};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

const NOW: u64 = 1_800_000_000_000;
const ISSUER: [u8; 16] = [0x15; 16];
const PARTY: [u8; 16] = [0x9a; 16];

struct Fixed;

impl Clock for Fixed {
    fn now_ms(&self) -> u64 {
        NOW
    }
}

/// Signs nothing: the "Claim" is the statement itself, which the test reads back.
struct Plain;

impl ClaimSigner for Plain {
    fn sign(
        &self,
        _: RealmId,
        payload: Vec<u8>,
        at: u64,
    ) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send {
        assert_eq!(at, NOW);
        std::future::ready(Ok(payload))
    }
}

#[derive(Default)]
struct Plane {
    down: AtomicBool,
    got: Mutex<Vec<ClaimSubmission>>,
}

impl ClaimIngest for &Plane {
    fn ingest(
        &self,
        s: ClaimSubmission,
    ) -> impl Future<Output = Result<ClaimVerdict, Unavailable>> + Send {
        let out = if self.down.load(Ordering::SeqCst) {
            Err(Unavailable(String::from("down")))
        } else {
            let claim = access_kernel::claim::claim_id(&s.claim);
            self.got.lock().unwrap().push(s);
            Ok(ClaimVerdict::Admitted {
                claim,
                position: 1,
                replayed: false,
            })
        };
        std::future::ready(out)
    }
}

struct Env {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    domain: [u8; 32],
    kek: SoftKek,
    ids: IdKey,
}

const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

impl Env {
    async fn new(seed: u8, issuer: bool) -> Self {
        let db = fresh().await.unwrap();
        let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
        let domain = [seed; 32];
        let d = DomainId::from_bytes(domain);
        let g = LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 1,
            leaf_hash: [seed; 32],
            envelope: vec![0xa0],
        };
        create_domain(&db.sequencer, &d, *tenant.as_bytes(), &g, &[])
            .await
            .unwrap();
        let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
        let realm = create_realm(&mut tx, &d, "claims", "pool-default")
            .await
            .unwrap();
        tx.enter_realm(realm).await.unwrap();
        if issuer {
            assert!(set_realm_issuer(&mut tx, &ISSUER).await.unwrap());
            assert!(!set_realm_issuer(&mut tx, &[1; 16]).await.unwrap());
        }
        tx.commit().await.unwrap();
        Self {
            db,
            tenant,
            realm,
            domain,
            kek: SoftKek::new("realm-kek:1", [seed; 32]),
            ids: IdKey::new(Secret::new([seed; 32])),
        }
    }

    fn realm(&self) -> Realm<'_> {
        Realm {
            tenant: self.tenant,
            realm: self.realm,
            kek: &self.kek,
            ids: &self.ids,
        }
    }

    async fn subject(&self, party: Option<[u8; 16]>) -> [u8; 16] {
        let mut tx = PgAccounts(self.db.app.clone())
            .begin(self.tenant, self.realm)
            .await
            .unwrap();
        let s = tx
            .insert_subject(AccountStatus::Active, "realm-kek:1", &[0; 40])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        if let Some(p) = party {
            let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
                .await
                .unwrap();
            assert!(bind_subject_party(&mut t, &s, &p).await.unwrap());
            t.commit().await.unwrap();
        }
        s
    }

    fn courier<'a>(&self, plane: &'a Plane) -> Courier<Plain, &'a Plane, Fixed> {
        Courier {
            app: self.db.app.clone(),
            reader: self.db.reader.clone(),
            signer: Plain,
            ingest: plane,
            clock: Fixed,
        }
    }
}

fn statements(plane: &Plane) -> Vec<Statement> {
    plane
        .got
        .lock()
        .unwrap()
        .iter()
        .map(|s| Statement::from_bytes(&s.claim).unwrap())
        .collect()
}

// TN-49, §12.3.1, OP-150 L2, OP-10, E3: a status change queues the realm issuer's account_status
// Claim in its own transaction; the courier issues it about the subject's Party in the realm's
// governing domain, and the next status supersedes it
#[tokio::test]
async fn status_changes_become_superseding_status_claims() {
    let e = Env::new(0x31, true).await;
    let s = e.subject(Some(PARTY)).await;
    let pg = PgAccounts(e.db.app.clone());
    change_status(&pg, &e.realm(), s, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    let plane = Plane::default();
    let c = e.courier(&plane);
    assert_eq!(c.step().await.unwrap().answered, 1);
    change_status(&pg, &e.realm(), s, AccountStatus::Active, &ADMIN)
        .await
        .unwrap();
    assert_eq!(c.step().await.unwrap().answered, 1);
    assert_eq!(c.step().await.unwrap().answered, 0);
    let got = statements(&plane);
    assert_eq!(got.len(), 2);
    for st in &got {
        assert_eq!(
            (st.domain, st.issuer, st.subject, st.class.as_str()),
            (Digest(e.domain), Id(ISSUER), Id(PARTY), "account_status")
        );
    }
    assert_eq!(got[0].value, Some(EqValue::Text(String::from("suspended"))));
    assert_eq!(got[1].value, Some(EqValue::Text(String::from("active"))));
    let first = access_kernel::claim::claim_id(&plane.got.lock().unwrap()[0].claim);
    assert_eq!(got[1].supersedes, Some(first));
    assert!(plane.got.lock().unwrap().iter().all(|s| s.body.is_none()));
}

// E5, §10.1.1 seam, K17: an order whose subject has no Party, or whose realm has no issuer, is no
// Claim; an outage of Claim Ingest leaves the order queued and the identity event done
#[tokio::test]
async fn orders_wait_for_the_plane_and_need_a_party_and_an_issuer() {
    let e = Env::new(0x32, true).await;
    let lone = e.subject(None).await;
    let bound = e.subject(Some(PARTY)).await;
    let plane = Plane::default();
    plane.down.store(true, Ordering::SeqCst);
    let pg = PgAccounts(e.db.app.clone());
    change_status(&pg, &e.realm(), lone, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    change_status(&pg, &e.realm(), bound, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    let courier = e.courier(&plane);
    assert!(courier.step().await.is_err());
    plane.down.store(false, Ordering::SeqCst);
    let report = courier.step().await.unwrap();
    assert_eq!((report.answered, report.unplaced), (1, 0));
    assert_eq!(statements(&plane)[0].subject, Id(PARTY));
    let order = risk(bound, RiskSignal::NewDevice, Bind::None, NOW);
    let none = Env::new(0x33, false).await;
    let other = none.subject(Some(PARTY)).await;
    assert_eq!(
        none.courier(&plane)
            .issue(
                none.tenant,
                none.realm,
                &risk(other, RiskSignal::NewDevice, Bind::None, NOW)
            )
            .await
            .unwrap(),
        Issued::Unplaced("no-issuer")
    );
    assert!(matches!(
        courier.issue(e.tenant, e.realm, &order).await.unwrap(),
        Issued::Answered {
            verdict: ClaimVerdict::Admitted { .. },
            ..
        }
    ));
}

// §10.1.5 binding, F17, TN-103: an authentication bound to the session is bound to the device
// Instance that session registered, and carries its assurance in the envelope
#[tokio::test]
async fn session_authentications_bind_the_registered_instance() {
    let e = Env::new(0x34, true).await;
    let s = e.subject(Some(PARTY)).await;
    let session = [0x5e; 16];
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    insert_device_key(
        &mut t,
        &NewDeviceKey {
            subject: s,
            public_key: &[0x11; 32],
            key_type: "OKP",
            algorithm: "Ed25519",
            instance: [0x1d; 16],
            session: Some(session),
        },
    )
    .await
    .unwrap()
    .unwrap();
    t.commit().await.unwrap();
    let mut tx = PgAccounts(e.db.app.clone())
        .begin(e.tenant, e.realm)
        .await
        .unwrap();
    emit(
        &mut tx,
        &authentication(AuthFacts {
            subject: s,
            method: AuthMethod::Password,
            auth_time: NOW - 5,
            assurance: BTreeMap::from([(String::from("aal"), 1)]),
            webauthn: None,
            evidence: None,
            bind: Bind::Session(session),
        }),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let plane = Plane::default();
    assert_eq!(e.courier(&plane).step().await.unwrap().answered, 1);
    let st = &statements(&plane)[0];
    assert_eq!(st.bound_instance, Some(Id([0x1d; 16])));
    assert_eq!(st.assurance.get("aal"), Some(&1));
    assert_eq!(st.validity.from, NOW - 5);
    assert!(plane.got.lock().unwrap()[0].body.is_some());
}
