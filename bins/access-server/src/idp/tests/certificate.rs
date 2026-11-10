//! CA trust for certificate sign-in on the real commit path (§10.2.5, OP-155 m.3 (m), MD-8): a
//! CA is trusted only by the governing domain root's actor-binding Acceptance of its issuer id
//! for person identity bindings; another CA, another use or another class is not.

use access_identity_admin::domain::certificate::ca_acceptance;
use access_identity_x509::domain::login::ca_issuer;
use access_identity_x509::ports::CaTrust as _;
use access_identity_x509::testing::Ca;
use access_internal_api::idp::Verdict;

use super::workloads::{establish, issuer_gate};
use super::*;

// §10.2.5, OP-155 m.3 (m), MD-8, Ek B 4671
#[tokio::test]
async fn a_ca_is_trusted_by_the_roots_actor_binding_acceptance_alone() {
    let w = World::new().await;
    let (_, _, d) = w.realm_with("certs", Some(0)).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let acme = Ca::root("Acme Issuing CA").der;
    let beta = Ca::root("Beta Issuing CA").der;
    let acme_id = ca_issuer(&acme).unwrap();
    assert!(!w.plane.accepted(d.0, acme_id).await.unwrap());
    let v = establish(&w, d, 0x81, ca_acceptance(&acme).unwrap()).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");
    assert!(w.plane.accepted(d.0, acme_id).await.unwrap());
    let beta_id = ca_issuer(&beta).unwrap();
    assert!(!w.plane.accepted(d.0, beta_id).await.unwrap());
    let other_use = issuer_gate(
        Id(beta_id),
        access_kernel::claim::PREDICATE_INPUT,
        &["identity_binding_person"],
    );
    let v = establish(&w, d, 0x82, other_use).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");
    assert!(!w.plane.accepted(d.0, beta_id).await.unwrap());
    let other_class = issuer_gate(
        Id(beta_id),
        access_kernel::claim::ACTOR_BINDING,
        &["identity_binding_workload"],
    );
    let v = establish(&w, d, 0x83, other_class).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");
    assert!(!w.plane.accepted(d.0, beta_id).await.unwrap());
}
