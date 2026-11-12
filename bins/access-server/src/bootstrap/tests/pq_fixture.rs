//! The local deployment's post-quantum signing profile fixture on the real path (OP-159 m.4 (a),
//! OP-157 m.6 (i), OP-153 m.3 (gg)): the bootstrap opens the sample realm's ML-DSA profile and
//! sets its share policy through the realm's own Exercises; a second run changes nothing.

use super::*;
use crate::bootstrap::pq_profile::PqProfilePlan;
use access_identity_admin::domain::assurance::{KexMode, MlDsa};

// CR-41, OP-159 m.3 (o), (t), m.4 (a), OP-69
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bootstrap_opens_the_sample_realm_s_post_quantum_profile_once() {
    let (w, signer) = World::open("bootstrap-pq", true).await;
    let signer = signer.unwrap();
    schedule(&signer);
    schedule(&signer);
    crate::jobs::open_now(&w.db.app, &w.db.archive, "bootstrap-pq").await;
    let plan = Plan {
        pq_profile: Some(PqProfilePlan {
            realm: String::from("acme"),
            profile: MlDsa::MlDsa65,
            kex_share: Some(KexMode::AdvertiseOnly),
        }),
        ..approve_plan(None)
    };
    let first = serde_json::to_value(w.run(&plan).await).unwrap();
    let pq = &first["pq_profile"];
    assert_eq!(pq["created"], true, "{first}");
    assert_eq!(pq["profile"], "ml-dsa-65", "{pq}");
    assert_eq!(pq["kex_share"], "advertise-only", "{pq}");
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let held = t.realm_signing().await.unwrap();
    let events: Vec<String> = t
        .list_audit(256)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.event_type)
        .collect();
    t.commit().await.unwrap();
    assert_eq!(held.profile.as_deref(), Some("ml-dsa-65"));
    assert_eq!(held.kex_share, "advertise-only");
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == "signing_profile.opened")
            .count(),
        1,
        "{events:?}"
    );

    let second = serde_json::to_value(w.run(&plan).await).unwrap();
    assert_eq!(second["pq_profile"]["created"], false, "{second}");
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let again: Vec<String> = t
        .list_audit(256)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.event_type)
        .collect();
    t.commit().await.unwrap();
    assert_eq!(
        again
            .iter()
            .filter(|e| *e == "signing_profile.opened")
            .count(),
        1,
        "{again:?}"
    );
    w.domains.release().await;
}
