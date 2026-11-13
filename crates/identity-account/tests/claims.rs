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
use access_identity_account::app::claims::{ClaimSigner, Courier, Issued, NotSigned, Report, emit};
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
const OTHER_PARTY: [u8; 16] = [0x9b; 16];

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
    ) -> impl Future<Output = Result<Vec<u8>, NotSigned>> + Send {
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
    vault: access_identity_account::app::vault::Vault,
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
            vault: access_identity_account::app::vault::Vault::in_memory(
                std::sync::Arc::new(SoftKek::new("realm-kek:1", [seed; 32])),
                [seed; 32],
            ),
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
        let mut tx = PgAccounts::sealed(self.db.app.clone(), self.vault.clone())
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

/// Steps the courier until `n` orders were answered in all; the outbox shows an order only once
/// every older transaction in the cluster has ended.
async fn answered(c: &Courier<Plain, &Plane, Fixed>, n: u32) -> Report {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut total = Report::default();
    loop {
        let r = c.step().await.unwrap();
        total.answered += r.answered;
        total.unplaced += r.unplaced;
        if total.answered >= n {
            return total;
        }
        assert!(std::time::Instant::now() < deadline, "{total:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Steps the courier until a step fails, as it must once an order reaches a plane that is down.
async fn until_down(c: &Courier<Plain, &Plane, Fixed>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        match c.step().await {
            Err(_) => return,
            Ok(r) => assert_eq!(r.answered, 0, "answered while the plane is down"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the plane was never reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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

// TN-49, §12.3.1, OP-150 L2, OP-10, E3
#[tokio::test]
async fn status_changes_become_superseding_status_claims() {
    let e = Env::new(0x31, true).await;
    let s = e.subject(Some(PARTY)).await;
    let pg = PgAccounts::sealed(e.db.app.clone(), e.vault.clone());
    change_status(&pg, &e.realm(), s, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    let plane = Plane::default();
    let c = e.courier(&plane);
    assert_eq!(answered(&c, 1).await.answered, 1);
    change_status(&pg, &e.realm(), s, AccountStatus::Active, &ADMIN)
        .await
        .unwrap();
    assert_eq!(answered(&c, 1).await.answered, 1);
    let other = e.subject(Some(OTHER_PARTY)).await;
    change_status(&pg, &e.realm(), other, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    assert_eq!(answered(&c, 1).await.answered, 1);
    assert_eq!(c.step().await.unwrap().answered, 0);
    let got = statements(&plane);
    assert_eq!(got.len(), 3);
    for st in &got[..2] {
        assert_eq!(
            (st.domain, st.issuer, st.subject, st.class.as_str()),
            (Digest(e.domain), Id(ISSUER), Id(PARTY), "account_status")
        );
    }
    assert_eq!(got[0].value, Some(EqValue::Text(String::from("suspended"))));
    assert_eq!(got[1].value, Some(EqValue::Text(String::from("active"))));
    let first = access_kernel::claim::claim_id(&plane.got.lock().unwrap()[0].claim);
    assert_eq!(got[1].supersedes, Some(first));
    assert_eq!(
        (got[2].subject, got[2].supersedes),
        (Id(OTHER_PARTY), None),
        "lines are per subject"
    );
    assert!(plane.got.lock().unwrap().iter().all(|s| s.body.is_none()));
}

// E5, §10.1.1, K17
#[tokio::test]
async fn orders_wait_for_the_plane_and_need_a_party_and_an_issuer() {
    let e = Env::new(0x32, true).await;
    let lone = e.subject(None).await;
    let bound = e.subject(Some(PARTY)).await;
    let plane = Plane::default();
    plane.down.store(true, Ordering::SeqCst);
    let pg = PgAccounts::sealed(e.db.app.clone(), e.vault.clone());
    change_status(&pg, &e.realm(), lone, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    change_status(&pg, &e.realm(), bound, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    let courier = e.courier(&plane);
    until_down(&courier).await;
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

// §10.1.5, F17, TN-103
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
    let mut tx = PgAccounts::sealed(e.db.app.clone(), e.vault.clone())
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
    let c = e.courier(&plane);
    assert_eq!(answered(&c, 1).await.answered, 1);
    let st = &statements(&plane)[0];
    assert_eq!(st.bound_instance, Some(Id([0x1d; 16])));
    assert_eq!(st.assurance.get("aal"), Some(&1));
    assert_eq!(st.validity.from, NOW - 5);
    assert!(plane.got.lock().unwrap()[0].body.is_some());
}

struct NoBreaches;

impl access_identity_account::ports::BreachRanges for NoBreaches {
    fn range(
        &self,
        _: &str,
    ) -> impl Future<Output = Result<String, access_identity_account::ports::RangeUnavailable>> + Send
    {
        std::future::ready(Ok(String::new()))
    }
}

// §10.1.3, OP-150 m.12 (j), OP-152 m.5 (l), K04
#[tokio::test]
async fn password_changes_become_authenticator_binding_claims() {
    use access_identity_account::adapters::system::SystemEntropy;
    use access_identity_account::app::accounts::{PasswordServices, create, set_password};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
    use access_identity_account::domain::password::Argon2Params;
    let e = Env::new(0x36, true).await;
    let pg = PgAccounts::sealed(e.db.app.clone(), e.vault.clone());
    let id = Identifier::new(IdentifierKind::Username, "pat").unwrap();
    let s = create(&pg, &e.realm(), &[id], &ADMIN).await.unwrap();
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert!(bind_subject_party(&mut t, &s, &PARTY).await.unwrap());
    t.commit().await.unwrap();
    let hasher = Hasher::new(HasherConfig::sized(
        Argon2Params {
            m_kib: 64,
            t: 1,
            p: 1,
        },
        2,
        None,
    ));
    let services = PasswordServices {
        hasher: &hasher,
        ranges: &NoBreaches,
        entropy: &SystemEntropy,
    };
    let first = set_password(
        &pg,
        &e.realm(),
        &services,
        s,
        "correct horse battery",
        &ADMIN,
    )
    .await
    .unwrap();
    set_password(
        &pg,
        &e.realm(),
        &services,
        s,
        "another horse battery",
        &ADMIN,
    )
    .await
    .unwrap();
    let plane = Plane::default();
    let c = e.courier(&plane);
    assert_eq!(answered(&c, 3).await.answered, 3);
    let got = statements(&plane);
    assert_eq!(got.len(), 3);
    assert!(got.iter().all(|st| st.class == "authenticator_binding"
        && st.subject == Id(PARTY)
        && st.bound_instance.is_none()));
    let ids: Vec<_> = plane
        .got
        .lock()
        .unwrap()
        .iter()
        .map(|s| access_kernel::claim::claim_id(&s.claim))
        .collect();
    assert_eq!(
        got[1].supersedes,
        Some(ids[0]),
        "the old password's line ends"
    );
    assert_eq!(
        got[2].supersedes, None,
        "the new password opens its own line"
    );
    let bodies: Vec<Vec<u8>> = plane
        .got
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.body.clone().unwrap())
        .collect();
    assert!(
        bodies
            .iter()
            .all(|b| !b.windows(7).any(|w| w == b"$argon2"))
    );
    assert!(!bodies[0].windows(16).any(|w| w == first));
}
