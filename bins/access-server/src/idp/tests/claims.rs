//! The realm issuer end to end (OP-150 L2, §10.1.4 rule 3, §10.1.7, CMP-8): a new realm's
//! governing domain is born accepting its issuer for actor-binding, the issuer's key holds its
//! Instance there, and the identity plane's Claims reach Claim Ingest through `internal-api`.

use std::collections::BTreeMap;

use access_authority_ingest::app::Ingest;
use access_identity_account::app::claims::{ClaimSigner, Courier, Issued, NotSigned, Report, emit};
use access_identity_account::domain::claim_classes::{
    AgeRange, DomainVerification, Guardianship, GuardianshipBasis, IdentityClass, Membership,
    VerificationMethod,
};
use access_identity_account::domain::claims::{
    self, AuthFacts, Bind, ClaimOrder, Content, PasskeyFacts, RiskSignal, account_status,
    authentication, authenticator_removed, passkey_binding, risk,
};
use access_internal_api::claims::{ClaimVerdict, Quarantine};
use access_kernel::claim::body::{AttestationResult, AuthMethod, AuthenticatorKind};
use access_kernel::model::EqValue;
use access_store::issuer::{issuer_instance, realm_issuer};

use super::*;
use crate::ingest::PgSubmissions;

pub(super) struct At;

impl access_authority_ingest::ports::Clock for At {
    fn now(&self) -> impl Future<Output = Result<u64, Unavailable>> + Send {
        std::future::ready(Ok(NOW))
    }
}

impl access_identity_account::ports::Clock for At {
    fn now_ms(&self) -> u64 {
        NOW
    }
}

pub(super) struct Keyed<'a>(&'a Opened);

impl ClaimSigner for Keyed<'_> {
    fn sign(
        &self,
        realm: RealmId,
        payload: Vec<u8>,
        at: u64,
    ) -> impl Future<Output = Result<Vec<u8>, NotSigned>> + Send {
        std::future::ready(self.0.sign_claim(realm, &payload, at))
    }
}

pub(super) type Plane =
    Ingest<Arc<Domains<AnyKeys, ActorBindings, OsSalts, Fixed>>, PgSubmissions, At>;

pub(super) fn courier(w: &World) -> Courier<Keyed<'_>, Plane, At> {
    Courier {
        app: w.db.app.clone(),
        reader: w.db.reader.clone(),
        signer: Keyed(&w.keys),
        ingest: Ingest::new(w.plane.domains.clone(), PgSubmissions(w.db.app.clone()), At),
        clock: At,
    }
}

async fn subject(w: &World, t: TenantId, r: RealmId, party: Id) -> [u8; 16] {
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let s = tx
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut tx, &s, &party.0)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    s
}

fn admitted(i: &Issued) -> bool {
    matches!(
        i,
        Issued::Answered {
            verdict: ClaimVerdict::Admitted { .. },
            ..
        }
    )
}

fn held(i: &Issued) -> Option<Quarantine> {
    match i {
        Issued::Answered {
            verdict: ClaimVerdict::Quarantined { reason, .. },
            ..
        } => Some(*reason),
        _ => None,
    }
}

// OP-150 L2, OP-144, §10.1.4 rule 3, §10.1.7, L2-CLM-1, L2-CLM-3, E18, INV-2, INV-12, CI-2
// IDI-3
#[tokio::test]
async fn the_realm_issuer_claims_are_accepted_for_actor_binding() {
    let w = World::new().await;
    let (t, r, d) = w.realm("issuer").await;
    access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
        .await
        .unwrap();
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let issuer = realm_issuer(&mut tx).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    let key = w.keys.open_issuer(r, issuer).await.unwrap();
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let domain = DomainId::from_bytes(d.0);
    let instance = issuer_instance(&mut tx, &domain, &thumbprint(&key))
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        w.admin().register_issuer(t, r).await.unwrap(),
        Some(instance)
    );
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let alice = subject(&w, t, r, ALICE).await;
    let c = courier(&w);
    let login = authentication(AuthFacts {
        subject: alice,
        method: AuthMethod::Webauthn,
        auth_time: NOW - 1,
        assurance: BTreeMap::from([
            (String::from("aal"), 2),
            (String::from("phishing_resistant"), 1),
        ]),
        webauthn: None,
        evidence: None,
        bind: Bind::None,
    });
    assert!(admitted(&c.issue(t, r, &login).await.unwrap()));
    let passkey = passkey_binding(&PasskeyFacts {
        subject: alice,
        credential: &[0xc1; 16],
        sibling: [0xc3; 16],
        public_key: &[0xc2; 77],
        alg: -7,
        attestation: Some((String::from("none"), AttestationResult::None)),
        aaguid: [0; 16],
        be: true,
        transports: std::collections::BTreeSet::new(),
        at: NOW - 1,
    });
    assert!(admitted(&c.issue(t, r, &passkey).await.unwrap()));
    let removed = authenticator_removed(alice, AuthenticatorKind::Passkey, &[0xc3; 16], NOW);
    assert!(admitted(&c.issue(t, r, &removed).await.unwrap()));
    // TN-49, §12.3.1, E5
    assert!(admitted(
        &c.issue(t, r, &account_status(alice, "suspended", NOW))
            .await
            .unwrap()
    ));
    // §7.6 TN-O4
    assert_eq!(
        held(
            &c.issue(t, r, &risk(alice, RiskSignal::NewDevice, Bind::None, NOW))
                .await
                .unwrap()
        ),
        Some(Quarantine::SourceNotAccepted)
    );
    let mut tx = access_identity_account::adapters::pg::PgTx::new(
        TenantTx::begin(&w.db.app, t, r).await.unwrap(),
    );
    emit(&mut tx, &login).await.unwrap();
    access_identity_account::ports::AccountTx::commit(tx)
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let report = loop {
        let r = c.step().await.unwrap();
        if r.answered > 0 {
            break r;
        }
        assert!(std::time::Instant::now() < deadline, "{r:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert_eq!((report.answered, report.unplaced), (1, 0));
}

async fn issuer_ready(w: &World, slug: &str) -> (TenantId, RealmId, Digest) {
    let (t, r, d) = w.realm(slug).await;
    access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
        .await
        .unwrap();
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let issuer = realm_issuer(&mut tx).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    w.keys.open_issuer(r, issuer).await.unwrap();
    assert!(w.admin().register_issuer(t, r).await.unwrap().is_some());
    (t, r, d)
}

async fn queue(w: &World, t: TenantId, r: RealmId, order: &ClaimOrder) {
    let mut tx = access_identity_account::adapters::pg::PgTx::new(
        TenantTx::begin(&w.db.app, t, r).await.unwrap(),
    );
    emit(&mut tx, order).await.unwrap();
    access_identity_account::ports::AccountTx::commit(tx)
        .await
        .unwrap();
}

fn login(subject: [u8; 16]) -> ClaimOrder {
    authentication(AuthFacts {
        subject,
        method: AuthMethod::Webauthn,
        auth_time: NOW - 1,
        assurance: BTreeMap::from([(String::from("aal"), 2)]),
        webauthn: None,
        evidence: None,
        bind: Bind::None,
    })
}

// OP-153 m.2 N0, m.3 (o), (p), (q), m.25 (i), L2-CLM-1, CMP-8
#[tokio::test]
async fn the_realm_issuer_signs_its_registry_and_org_member_claims() {
    let w = World::new().await;
    let (t, r, d) = issuer_ready(&w, "registry").await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let alice = subject(&w, t, r, ALICE).await;
    let org = Id([0x0e; 16]);
    let line = |tag: &[u8]| claims::line(&[tag, &alice]);
    let at = (NOW - 1, claims::BINDING_TTL_MS);
    let mut age = ClaimOrder::registry(
        alice,
        IdentityClass::AgeRange,
        Value::text(AgeRange::Age18Plus.name()),
        None,
        at,
        line(b"age_range"),
    );
    age.content = Content::Scalar(EqValue::Text(String::from(AgeRange::Age18Plus.name())));
    let orders = [
        ClaimOrder::registry(
            alice,
            IdentityClass::Membership,
            Membership {
                organization: org,
                member: ALICE,
                root: false,
                since: NOW - 1,
            }
            .to_value(),
            None,
            at,
            line(b"membership"),
        ),
        claims::org_member(alice, (org.0, org.0), at),
        ClaimOrder::registry(
            alice,
            IdentityClass::DomainVerification,
            DomainVerification {
                organization: org,
                domain: String::from("acme.example"),
                method: VerificationMethod::DnsTxt,
                verified_at: NOW - 1,
            }
            .to_value(),
            None,
            at,
            line(b"domain_verification"),
        ),
        ClaimOrder::registry(
            alice,
            IdentityClass::Guardianship,
            Guardianship {
                guardian: ALICE,
                ward: Id([0x0f; 16]),
                basis: GuardianshipBasis::Parent,
                until: None,
            }
            .to_value(),
            None,
            at,
            line(b"guardianship"),
        ),
        age,
    ];
    let c = courier(&w);
    for order in &orders {
        assert!(
            matches!(c.issue(t, r, order).await, Ok(Issued::Answered { .. })),
            "{}",
            order.class
        );
    }
}

/// Steps `c` until `n` orders were answered or refused in all.
async fn passed(c: &Courier<Keyed<'_>, Plane, At>, n: u32) -> Report {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut total = Report::default();
    loop {
        let r = c.step().await.unwrap();
        total.answered += r.answered;
        total.unplaced += r.unplaced;
        total.refused += r.refused;
        if total.answered + total.refused >= n {
            return total;
        }
        assert!(std::time::Instant::now() < deadline, "{total:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

// L2-CLM-1, OP-10, CMP-8, §10.1.7
#[tokio::test]
async fn an_order_the_signer_refuses_never_holds_up_the_orders_after_it() {
    let w = World::new().await;
    let (t, r, d) = issuer_ready(&w, "refused").await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let alice = subject(&w, t, r, ALICE).await;
    let c = courier(&w);
    let not_its_own = ClaimOrder {
        class: String::from("support_case"),
        content: Content::Scalar(EqValue::Text(String::from("4411"))),
        line: Some(claims::line(&[b"support_case", &alice])),
        ..login(alice)
    };
    assert_eq!(
        c.issue(t, r, &not_its_own).await.unwrap(),
        Issued::Refused("signer-payload")
    );
    w.keys
        .now
        .store(NOW + HOUR, std::sync::atomic::Ordering::SeqCst);
    queue(&w, t, r, &not_its_own).await;
    queue(&w, t, r, &login(alice)).await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let down = loop {
        match c.step().await {
            Err(e) => break e,
            Ok(r) => assert_eq!(r.answered, 0, "{r:?}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the signer was never reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(down.0.contains("signer-time"), "{down:?}");
    w.keys.now.store(NOW, std::sync::atomic::Ordering::SeqCst);
    let report = passed(&c, 2).await;
    assert_eq!(
        (report.answered, report.refused, report.unplaced),
        (1, 1, 0)
    );
    assert_eq!(c.step().await.unwrap(), Report::default());
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let domain = DomainId::from_bytes(d.0);
    assert_eq!(
        access_store::issuer::last_in_line(
            &mut tx,
            &alice,
            &domain,
            not_its_own.line.as_ref().unwrap()
        )
        .await
        .unwrap(),
        None
    );
    tx.commit().await.unwrap();
}

// OP-153 m.2 N0, m.25 (i), L2-CLM-1
#[test]
fn the_identity_issuer_signs_every_class_the_realm_issuer_queues() {
    use access_identity_signer::issuer::issues;
    for class in IdentityClass::ALL {
        assert!(issues(class.name()), "{}", class.name());
    }
    for class in [
        access_kernel::claim::body::Class::OrgMember,
        access_kernel::claim::body::Class::OperatedBy,
        access_kernel::claim::body::Class::SponsoredBy,
        access_kernel::claim::body::Class::AgentKind,
        access_kernel::claim::body::Class::AttestationRuntime,
    ] {
        assert!(issues(&class.name()), "{}", class.name());
    }
    assert!(!issues(access_identity_account::app::support::CASE_CLASS));
}
