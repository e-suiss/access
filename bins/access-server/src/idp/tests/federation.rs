//! The chain gate of chain-constrained issuers on the real ingest path (IDI-12, OP-155 m.3 (j)):
//! the realm issuer's Claims stop while its tracked chain does not hold and flow again once it
//! does, with no Acceptance written in between.

use std::collections::BTreeMap;

use access_identity_account::app::claims::Issued;
use access_identity_account::domain::claims::{AuthFacts, Bind, authentication};
use access_internal_api::claims::ClaimVerdict;
use access_kernel::claim::body::AuthMethod;
use access_store::issuer::{issuer_instance, realm_issuer};
use access_store::oidf::{ChainState, set_issuer_state, track_issuer};

use super::claims::courier;
use super::*;

const ENTITY: &str = "https://issuer.federation.example";

fn verdict(i: &Issued) -> Option<&ClaimVerdict> {
    match i {
        Issued::Answered { verdict, .. } => Some(verdict),
        _ => None,
    }
}

fn refused_by_chain(i: &Issued) -> bool {
    matches!(verdict(i), Some(ClaimVerdict::Rejected { code }) if code == "claim-issuer-chain")
}

fn admitted(i: &Issued) -> bool {
    matches!(verdict(i), Some(ClaimVerdict::Admitted { .. }))
}

// IDI-12, IDP-20, OP-155 m.3 (j), §9.13.8 k.4
#[tokio::test]
async fn a_lost_chain_cuts_the_issuer_and_its_return_resumes_it() {
    let w = World::new().await;
    let (t, r, d) = w.realm("oidf-gate").await;
    access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
        .await
        .unwrap();
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let issuer = realm_issuer(&mut tx).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    let key = w.keys.open_issuer(r, issuer).await.unwrap();
    let domain = DomainId::from_bytes(d.0);
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
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
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let alice = tx
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut tx, &alice, &ALICE.0)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let c = courier(&w);
    let login = |at: u64| {
        authentication(AuthFacts {
            subject: alice,
            method: AuthMethod::Webauthn,
            auth_time: at,
            assurance: BTreeMap::from([(String::from("aal"), 1)]),
            webauthn: None,
            evidence: None,
            bind: Bind::None,
        })
    };
    assert!(admitted(&c.issue(t, r, &login(NOW - 9)).await.unwrap()));
    let realm = (*t.as_bytes(), *r.as_bytes());
    track_issuer(&w.db.app, &domain, realm, ENTITY, Some(issuer), NOW)
        .await
        .unwrap();
    let head = w.plane.domains.head(d).await.unwrap();
    assert!(
        refused_by_chain(&c.issue(t, r, &login(NOW - 8)).await.unwrap()),
        "a tracked issuer whose chain never resolved"
    );
    assert_eq!(
        w.plane.domains.head(d).await.unwrap(),
        head,
        "a cut Claim is not recorded"
    );
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Resolved,
        Some("https://ta.example"),
        NOW,
        NOW + 3_600_000,
    )
    .await
    .unwrap();
    assert!(admitted(&c.issue(t, r, &login(NOW - 7)).await.unwrap()));
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Unresolved,
        None,
        NOW,
        0,
    )
    .await
    .unwrap();
    let head = w.plane.domains.head(d).await.unwrap();
    assert!(refused_by_chain(
        &c.issue(t, r, &login(NOW - 6)).await.unwrap()
    ));
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Conflict,
        None,
        NOW,
        NOW + 1,
    )
    .await
    .unwrap();
    assert!(refused_by_chain(
        &c.issue(t, r, &login(NOW - 5)).await.unwrap()
    ));
    assert_eq!(
        w.plane.domains.head(d).await.unwrap(),
        head,
        "the cut writes nothing, the Acceptance least of all"
    );
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Resolved,
        Some("https://ta.example"),
        NOW,
        NOW,
    )
    .await
    .unwrap();
    assert!(
        refused_by_chain(&c.issue(t, r, &login(NOW - 4)).await.unwrap()),
        "an expired chain"
    );
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Resolved,
        Some("https://ta.example"),
        NOW,
        NOW + 3_600_000,
    )
    .await
    .unwrap();
    assert!(
        admitted(&c.issue(t, r, &login(NOW - 3)).await.unwrap()),
        "the chain is back: input resumes with the same Acceptance"
    );
}
