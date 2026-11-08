//! Social presets through commit against real PostgreSQL and the authority plane (IDP-31,
//! OP-153 m.3 (l), TN-87): `idp.social.enable`, `update` and `disable`, the shared development
//! client refused outside a sandbox, and the warnings of a changed client id.

use access_identity_admin::app::rest::{Kind, Op, compile};
use access_identity_admin::domain::Invalid;
use access_store::sandbox::{Budget, mark};
use serde_json::json;

use super::*;

async fn ready(slug: &str) -> (World, (TenantId, RealmId), Digest) {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm(slug).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    (w, (tenant, realm), d)
}

async fn run(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    change: Change,
    nonce: u8,
) -> Result<Applied, AdminError> {
    let change = w.admin().resolve(at.0, at.1, change).await?;
    exercise(w, &proposal(at, change, nonce, idp_anchor(d), 1), ROOT_KEY).await
}

async fn refused(w: &World, at: (TenantId, RealmId), d: Digest, change: Change) -> Invalid {
    match w
        .admin()
        .prepare(&proposal(at, change, 99, idp_anchor(d), 1))
        .await
    {
        Err(AdminError::Invalid(i)) => i,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("prepared"),
    }
}

fn put(w: &World, preset: &str, body: &serde_json::Value) -> Change {
    compile(Op::PutSocial, Some(preset), body, &w.ids).unwrap()
}

// IDP-31 (4), OP-153 m.3 (l)
#[tokio::test]
async fn a_shared_development_client_is_refused_at_enable_in_a_production_realm() {
    let (w, at, d) = ready("social-prod").await;
    assert_eq!(
        refused(&w, at, d, put(&w, "google", &json!({}))).await,
        Invalid::SharedSocialKey
    );
    assert_eq!(
        compile(
            Op::PutSocial,
            Some("myspace"),
            &json!({"client_id": "c", "client_secret_ref": "secret://s"}),
            &w.ids
        )
        .unwrap()
        .check(&DeclaredTargets::default()),
        Err(Invalid::Social)
    );
    assert!(matches!(
        compile(
            Op::PutSocial,
            Some("google"),
            &json!({"client_id": "c"}),
            &w.ids
        ),
        Err(Invalid::Social)
    ));
    written(
        &run(
            &w,
            at,
            d,
            put(
                &w,
                "google",
                &json!({"client_id": "own-1", "client_secret_ref": "secret://social/google"}),
            ),
            1,
        )
        .await
        .unwrap(),
    );
    let read = w
        .admin()
        .read(at.0, at.1, Kind::Socials, None, None, 10)
        .await
        .unwrap();
    assert_eq!(read.items.len(), 1);
    assert_eq!(read.items[0].0["client_id"], "own-1");
    assert_eq!(read.items[0].0["shared_development_client"], false);
    assert_eq!(read.items[0].0["warnings"], json!([]));
}

// TN-87, IDP-31 (4)
#[tokio::test]
async fn a_sandbox_realm_uses_the_shared_client_and_a_changed_client_id_warns() {
    let (w, at, d) = ready("social-sandbox").await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    mark(
        &mut t,
        &DomainId::from_bytes(d.0),
        Budget {
            exercises_per_day: 100,
            projections_per_day: 100,
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    written(
        &run(&w, at, d, put(&w, "apple", &json!({})), 1)
            .await
            .unwrap(),
    );
    assert_eq!(
        refused(&w, at, d, put(&w, "apple", &json!({}))).await,
        Invalid::SocialExists,
    );
    let own = |id: &str| json!({"client_id": id, "client_secret_ref": "secret://social/apple"});
    written(
        &run(&w, at, d, put(&w, "apple", &own("team-a")), 2)
            .await
            .unwrap(),
    );
    written(
        &run(&w, at, d, put(&w, "apple", &own("team-b")), 3)
            .await
            .unwrap(),
    );
    let one = w
        .admin()
        .read(at.0, at.1, Kind::Socials, Some("apple"), None, 1)
        .await
        .unwrap();
    let warnings: Vec<_> = one.items[0].0["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        warnings,
        ["social-client-id-changed", "apple-transfer-window"]
    );
    let disable = compile(Op::DisableSocial, Some("apple"), &json!({}), &w.ids).unwrap();
    written(&run(&w, at, d, disable.clone(), 4).await.unwrap());
    assert_eq!(refused(&w, at, d, disable).await, Invalid::NoSocial);
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(!t.social_provider("apple").await.unwrap().unwrap().active);
    t.commit().await.unwrap();
}
