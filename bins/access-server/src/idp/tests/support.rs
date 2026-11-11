//! Support case systems through commit against real PostgreSQL and the authority plane (OP-157
//! m.3 (a), (e)): `idp.support.case_system_register` is CT2 and names the issuer Party whose
//! `support_case` Claims hold support Grants once the domain accepts them; it gives them no
//! effect itself. A name is never reused; retiring is CT1.

use access_identity_admin::domain::support::CaseSystemChange;
use access_internal_api::idp::IdpAction;
use access_kernel::json::b64url_encode;
use serde_json::json;

use super::*;

fn case_change(
    at: (TenantId, RealmId),
    d: Digest,
    change: CaseSystemChange,
    nonce: u8,
) -> Proposal {
    proposal(at, Change::CaseSystem(change), nonce, idp_anchor(d), 1)
}

async fn systems(w: &World, (tenant, realm): (TenantId, RealmId)) -> Vec<(String, bool)> {
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let rows = t.case_systems().await.unwrap();
    t.commit().await.unwrap();
    rows.into_iter().map(|r| (r.name, r.live)).collect()
}

// OP-157 m.3 (a), (e), OP-73, Ek B 5410
#[tokio::test]
async fn a_case_system_is_registered_once_and_retired() {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("acme").await;
    let at = (tenant, realm);
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    assert!(!IdpAction::SupportCaseSystemRegister.schema().reserved);
    let body = json!({"name": "acme-desk", "issuer": b64url_encode(&[7; 16]),
                      "provider": "zendesk", "format": "product-seam/v1"});
    let unknown = json!({"name": "acme-desk", "issuer": b64url_encode(&[7; 16]),
                         "provider": "acme-tickets", "format": "product-seam/v1"});
    assert!(
        CaseSystemChange::register(&unknown)
            .unwrap()
            .check()
            .is_err()
    );
    let register = case_change(at, d, CaseSystemChange::register(&body).unwrap(), 1);
    written(&exercise(&w, &register, ROOT_KEY).await.unwrap());
    assert_eq!(
        systems(&w, at).await,
        vec![(String::from("acme-desk"), true)]
    );
    let again = case_change(at, d, CaseSystemChange::register(&body).unwrap(), 2);
    assert!(w.admin().prepare(&again).await.is_err());
    let retire = case_change(
        at,
        d,
        CaseSystemChange::retire("acme-desk", &json!({})).unwrap(),
        3,
    );
    written(&exercise(&w, &retire, ROOT_KEY).await.unwrap());
    assert_eq!(
        systems(&w, at).await,
        vec![(String::from("acme-desk"), false)]
    );
    let gone = case_change(
        at,
        d,
        CaseSystemChange::retire("acme-desk", &json!({})).unwrap(),
        4,
    );
    assert!(w.admin().prepare(&gone).await.is_err());
    let reuse = case_change(at, d, CaseSystemChange::register(&body).unwrap(), 5);
    assert!(w.admin().prepare(&reuse).await.is_err());
}
