//! The realm issuer end to end (OP-150 L2, §10.1.4 rule 3, §10.1.7, CMP-8): a new realm's
//! governing domain is born accepting its issuer for actor-binding, the issuer's key holds its
//! Instance there, and the identity plane's Claims reach Claim Ingest through `internal-api`.

use std::collections::BTreeMap;

use access_authority_ingest::app::Ingest;
use access_identity_account::app::claims::{ClaimSigner, Courier, Issued, emit};
use access_identity_account::domain::claims::{
    AuthFacts, Bind, PasskeyFacts, RiskSignal, account_status, authentication,
    authenticator_removed, passkey_binding, risk,
};
use access_internal_api::claims::{ClaimVerdict, Quarantine};
use access_kernel::claim::body::{AttestationResult, AuthMethod, AuthenticatorKind};
use access_store::issuer::{issuer_instance, realm_issuer};

use super::*;
use crate::ingest::PgSubmissions;

struct At;

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

struct Keyed<'a>(&'a Opened);

impl ClaimSigner for Keyed<'_> {
    fn sign(
        &self,
        realm: RealmId,
        payload: Vec<u8>,
        at: u64,
    ) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send {
        std::future::ready(self.0.sign_claim(realm, &payload, at))
    }
}

type Plane = Ingest<Arc<Domains<AnyKeys, ActorBindings, OsSalts, Fixed>>, PgSubmissions, At>;

fn courier(w: &World) -> Courier<Keyed<'_>, Plane, At> {
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

// OP-150 L2, OP-144, §10.1.4 rule 3, §10.1.7, L2-CLM-1, L2-CLM-3, E18, INV-2: creating a realm
// fixes its issuer Party, names it in the Genesis and opens its Claim issuer key's Instance in the
// governing domain; the issuer's authentication and authenticator_binding Claims are admitted
// for actor-binding there, its other classes wait for an explicit Acceptance, and a repeat opens
// nothing new
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
        public_key: &[0xc2; 77],
        alg: -7,
        attestation: Some((String::from("none"), AttestationResult::None)),
        aaguid: [0; 16],
        be: true,
        transports: std::collections::BTreeSet::new(),
        at: NOW - 1,
    });
    assert!(admitted(&c.issue(t, r, &passkey).await.unwrap()));
    let removed = authenticator_removed(alice, AuthenticatorKind::Passkey, &[0xc1; 16], NOW);
    assert!(admitted(&c.issue(t, r, &removed).await.unwrap()));
    // TN-49, §12.3.1, E5: the realm issuer's status Claim is accepted by default and only narrows
    assert!(admitted(
        &c.issue(t, r, &account_status(alice, "suspended", NOW))
            .await
            .unwrap()
    ));
    // §7.6 TN-O4: a risk signal is no actor-binding input; it waits for a predicate-input
    // Acceptance and gates nothing
    assert_eq!(
        held(
            &c.issue(t, r, &risk(alice, RiskSignal::NewDevice, Bind::None, NOW))
                .await
                .unwrap()
        ),
        Some(Quarantine::SourceNotAccepted)
    );
    let mut tx = access_identity_account::adapters::pg::PgTx(
        TenantTx::begin(&w.db.app, t, r).await.unwrap(),
    );
    emit(&mut tx, &login).await.unwrap();
    access_identity_account::ports::AccountTx::commit(tx)
        .await
        .unwrap();
    let report = c.step().await.unwrap();
    assert_eq!((report.answered, report.unplaced), (1, 0));
}
