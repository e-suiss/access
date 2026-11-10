//! Signal sources through commit against real PostgreSQL and the authority plane (OP-156 m.3
//! (a), (r), E38): `idp.signal.source_register` is CT2 and names the issuer Party whose Claims
//! the source sends; it gives them no effect. A name is never reused; retiring is CT1.

use access_identity_signals::domain::source::{SourceChange, issuer_id};
use access_internal_api::idp::IdpAction;
use serde_json::json;

use super::*;

fn source_change(at: (TenantId, RealmId), d: Digest, change: SourceChange, nonce: u8) -> Proposal {
    proposal(
        at,
        Change::Signal(Box::new(change)),
        nonce,
        idp_anchor(d),
        1,
    )
}

async fn sources(w: &World, (tenant, realm): (TenantId, RealmId)) -> Vec<(String, bool)> {
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let rows = t.signal_sources().await.unwrap();
    t.commit().await.unwrap();
    rows.into_iter().map(|r| (r.name, r.live)).collect()
}

// OP-156 m.3 (a), (r), E38, OP-73
#[tokio::test]
async fn a_signal_source_is_registered_once_and_retired() {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("acme").await;
    let at = (tenant, realm);
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    assert!(!IdpAction::SignalSourceRegister.schema().reserved);
    let body = json!({"name": "acme-mdm", "kind": "mdm", "provider": "Acme MDM",
                      "issuer": issuer_id(&[7; 16]), "format": "intune"});
    let register = source_change(at, d, SourceChange::register(&body).unwrap(), 1);
    written(&exercise(&w, &register, ROOT_KEY).await.unwrap());
    assert_eq!(
        sources(&w, at).await,
        vec![(String::from("acme-mdm"), true)]
    );
    let again = source_change(at, d, SourceChange::register(&body).unwrap(), 2);
    assert!(w.admin().prepare(&again).await.is_err());
    let retire = source_change(
        at,
        d,
        SourceChange::retire("acme-mdm", &json!({})).unwrap(),
        3,
    );
    written(&exercise(&w, &retire, ROOT_KEY).await.unwrap());
    assert_eq!(
        sources(&w, at).await,
        vec![(String::from("acme-mdm"), false)]
    );
    let gone = source_change(
        at,
        d,
        SourceChange::retire("acme-mdm", &json!({})).unwrap(),
        4,
    );
    assert!(w.admin().prepare(&gone).await.is_err());
    let reuse = source_change(at, d, SourceChange::register(&body).unwrap(), 5);
    assert!(w.admin().prepare(&reuse).await.is_err());
}
