//! Client profiles on the real commit path (OP-155 m.3 (k), IDP-12, IDP-24): each change is an
//! `idp.client.*` Exercise of the realm's governing domain, applied over the client's current
//! profile and refused when the client cannot hold it.

use access_identity_admin::domain::{AuthMethod, ProfileDelta};
use access_identity_oauth::domain::fapi::{ClientProfile, IdAlg};
use access_store::client_profiles::{frontchannel_enabled, profile};

use super::*;

async fn stored(w: &World, tenant: TenantId, realm: RealmId, id: &str) -> ClientProfile {
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let row = access_store::idp::client(&mut t, id)
        .await
        .unwrap()
        .unwrap();
    let p = profile(&mut t, row.client_uuid).await.unwrap();
    t.commit().await.unwrap();
    p.map(|r| ClientProfile::from_row(r).unwrap())
        .unwrap_or_default()
}

// IDP-12, IDP-24, OP-155 m.3 (k), Ek B 4717, 5044, 5093, 5096
#[tokio::test]
async fn client_profiles_change_through_commit() {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("prof").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let public = new_client(&w).await;
    let keyed = Client {
        id: w.admin().new_client_id().await.unwrap(),
        auth: AuthMethod::PrivateKeyJwt {
            jwks_uri: String::from("https://shop.example/jwks.json"),
        },
        ..new_client(&w).await
    };
    let mut nonce = 0;
    let mut run = |change: Change| {
        nonce += 1;
        let p = proposal((tenant, realm), change, nonce, idp_anchor(d), 1);
        let w = &w;
        async move { exercise(w, &p, ROOT_KEY).await }
    };
    written(&run(Change::ClientRegister(public.clone())).await.unwrap());
    written(&run(Change::ClientRegister(keyed.clone())).await.unwrap());

    // IDP-12
    let fapi = |c: &Client, on: bool| Change::ClientProfile {
        client: c.id.clone(),
        delta: ProfileDelta::Fapi2(on),
    };
    assert!(run(fapi(&public, true)).await.is_err());
    written(&run(fapi(&keyed, true)).await.unwrap());
    assert!(stored(&w, tenant, realm, keyed.id.as_str()).await.fapi2);
    let rs256 = Change::ClientProfile {
        client: keyed.id.clone(),
        delta: ProfileDelta::SigningAlg(Some(IdAlg::Rs256)),
    };
    assert!(run(rs256.clone()).await.is_err());
    written(&run(fapi(&keyed, false)).await.unwrap());
    written(&run(rs256).await.unwrap());
    let p = stored(&w, tenant, realm, keyed.id.as_str()).await;
    assert!(!p.fapi2 && p.rs256 && p.id_alg == Some(IdAlg::Rs256));

    // CR-38
    let post = Change::ClientProfile {
        client: keyed.id.clone(),
        delta: ProfileDelta::SecretPost,
    };
    assert!(run(post).await.is_err());

    // IDP-24
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert!(!frontchannel_enabled(&mut t).await.unwrap());
    t.commit().await.unwrap();
    written(&run(Change::FrontchannelLogout).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert!(frontchannel_enabled(&mut t).await.unwrap());
    t.commit().await.unwrap();
}
