//! A realm's FIPS and password hash profiles through the management API's single write path,
//! then the hosted login's kit and the passwords it hashes (CR-15, CR-36, OP-33, OP-158 m.3
//! (a), (y), m.6 (b), OP-153 m.3 (gg)).

use access_identity_account::domain::password::{HashPolicy, HashProfile, Password};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::ports::Kits as _;
use axum::http::StatusCode;

use super::management::{Console, console};
use super::recovery::admin_write;
use crate::login::{HsmKits, RealmKeks};

async fn kit_hash(c: &Console) -> HashPolicy {
    let kits = HsmKits::new(
        RealmKeks::new(c.w.keys.clone()),
        c.w.db.router.clone(),
        c.w.db.app.clone(),
        SessionPolicy::DEFAULT,
    );
    let entry = RealmEntry {
        tenant: c.route.tenant,
        realm: c.route.realm,
        slug: c.route.slug.clone(),
        issuer: access_identity_oauth::domain::issuer::Issuer::parse(&c.route.issuer).unwrap(),
    };
    kits.kit(&entry).await.unwrap().hash
}

async fn hashes_with(c: &Console, policy: HashPolicy) -> String {
    use access_identity_account::adapters::system::{cgroup_memory_budget, cores};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::domain::password::Argon2Params;
    let _ = c;
    let h = Hasher::new(HasherConfig::sized(
        Argon2Params::CANONICAL,
        cores(),
        cgroup_memory_budget(),
    ))
    .for_policy(policy);
    let pw = Password::new("correct horse battery staple").unwrap();
    let phc = h
        .hash(&pw, access_crypto::random::bytes::<16>().unwrap())
        .await
        .unwrap();
    assert!(h.verify(&pw, phc.clone()).await.unwrap().matched);
    phc.expose().clone()
}

// CR-15, CR-36, OP-33, OP-158
#[tokio::test]
async fn the_realm_profiles_are_written_once_and_the_login_hashes_under_them() {
    let c = console("realm-crypto", false).await;
    assert_eq!(
        kit_hash(&c).await,
        HashPolicy::of(HashProfile::Standard, false)
    );
    assert!(
        hashes_with(&c, kit_hash(&c).await)
            .await
            .starts_with("$argon2id$v=19$m=7168,t=5,p=1$")
    );

    let (status, body) = admin_write(
        &c,
        "putHashProfile",
        None,
        "/admin/realms/acme/settings/hash-profile",
        serde_json::json!({"profile": "high-memory"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        kit_hash(&c).await,
        HashPolicy::of(HashProfile::HighMemory, false)
    );

    // OP-33
    let (status, body) = admin_write(
        &c,
        "putHashProfile",
        None,
        "/admin/realms/acme/settings/hash-profile",
        serde_json::json!({"profile": "canonical"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "hash-profile-downgrade", "{body}");
    assert_eq!(
        kit_hash(&c).await,
        HashPolicy::of(HashProfile::HighMemory, false)
    );

    // CR-15
    let (status, body) = admin_write(
        &c,
        "putCryptoProfile",
        None,
        "/admin/realms/acme/settings/crypto-profile",
        serde_json::json!({"fips": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fips = kit_hash(&c).await;
    assert_eq!(fips, HashPolicy::of(HashProfile::HighMemory, true));
    let phc = hashes_with(&c, fips).await;
    assert!(phc.starts_with("$pbkdf2-sha256$i=600000$"), "{phc}");
    assert!(!phc.contains("argon2"));
}
