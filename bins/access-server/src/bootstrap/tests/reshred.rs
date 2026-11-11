//! OP-42, OP-57 item 7, OP-158 m.3 (r): after a restore to before a destruction, the server stays
//! closed until the shred journal is applied again, on the real server's world and store.

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::Realm;
use access_identity_account::app::accounts::{change_status, create};
use access_identity_account::app::vault;
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_export::adapters::cold_file::FileCold;
use access_store::restore::{Shredded, pending_reshred};
use access_store::testing::{backup_subject, restore_subject};

use super::management::console;
use super::*;

fn cold() -> FileCold {
    let n = access_crypto::random::bytes::<8>().unwrap();
    FileCold {
        root: std::env::temp_dir().join(format!("access-reshred-{:016x}", u64::from_be_bytes(n))),
    }
}

async fn shredded(
    app: &access_store::Pool,
    route: &access_store::tenancy::RealmRoute,
    subject: [u8; 16],
) -> Shredded {
    let mut t = TenantTx::begin(app, route.tenant, route.realm)
        .await
        .unwrap();
    let s = t.subject_shredded(subject).await.unwrap();
    t.commit().await.unwrap();
    s
}

// OP-42, OP-57, U58
#[tokio::test]
async fn a_restore_before_a_destruction_keeps_the_server_closed_until_it_is_reshredded() {
    let c = console("reshred", false).await;
    let route = c.route.clone();
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let v = crate::login::RealmKeks::new(c.w.keys.clone())
        .vault(route.realm)
        .unwrap();
    let realm = Realm {
        tenant: route.tenant,
        realm: route.realm,
        kek: &*v.kek,
        ids: &ids,
    };
    let db = PgAccounts::sealed(c.w.db.app.clone(), v.clone());
    let email = Identifier::new(IdentifierKind::Email, "Rhea@Example.com").unwrap();
    let who = access_identity_account::app::Actor {
        actor: "test",
        correlation: "test",
    };
    let victim = create(&db, &realm, &[email], &who).await.unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&db, &realm, victim, to, &who).await.unwrap();
    }
    let mut tx = db.begin(route.tenant, route.realm).await.unwrap();
    vault::set_profile(&mut tx.0, &v, victim, "name", "Rhea Example")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let (tenant, realm_id) = (*route.tenant.as_bytes(), *route.realm.as_bytes());
    let backup = backup_subject(&c.w.db, tenant, realm_id, victim)
        .await
        .unwrap();
    let cold = cold();
    crate::reshred::gate(&c.w.db.app, Some(&cold))
        .await
        .unwrap();

    let mut t = TenantTx::begin(&c.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    assert!(t.reshred_subject(victim).await.unwrap() >= 2);
    t.commit().await.unwrap();
    crate::reshred::journal_to(&cold, &route, &[victim])
        .await
        .unwrap();
    assert_eq!(shredded(&c.w.db.app, &route, victim).await, Shredded::Yes);
    crate::reshred::gate(&c.w.db.app, Some(&cold))
        .await
        .unwrap();

    restore_subject(&c.w.db, &backup).await.unwrap();
    assert_eq!(shredded(&c.w.db.app, &route, victim).await, Shredded::No);
    let closed = crate::reshred::gate(&c.w.db.app, Some(&cold))
        .await
        .unwrap_err();
    assert!(closed.contains("restore-reshred-pending"), "{closed}");
    assert_eq!(pending_reshred(&c.w.db.app).await.unwrap(), Some(1));
    assert!(
        crate::reshred::gate(&c.w.db.app, None).await.is_err(),
        "the recorded restore keeps it closed even without the journal"
    );

    let done = crate::reshred::reshred(&c.w.db.app, &cold).await.unwrap();
    assert_eq!((done.entries, done.generation), (1, Some(1)));
    assert!(done.keys >= 2);
    assert_eq!(shredded(&c.w.db.app, &route, victim).await, Shredded::Yes);
    let mut tx = db.begin(route.tenant, route.realm).await.unwrap();
    assert_eq!(
        vault::profile(&mut tx.0, &v, victim).await.unwrap(),
        Vec::<(String, String)>::new(),
        "the restored profile is unreadable again"
    );
    tx.commit().await.unwrap();
    crate::reshred::gate(&c.w.db.app, Some(&cold))
        .await
        .unwrap();
    assert_eq!(pending_reshred(&c.w.db.app).await.unwrap(), None);
}

// CR-35, OP-42
#[tokio::test(flavor = "multi_thread")]
async fn a_database_dump_holds_no_plain_secret_or_personal_value() {
    let c = console("dump", false).await;
    let route = c.route.clone();
    let subject = super::recovery::account(&c, "Dora.Dump@Example.com", true).await;
    let v = crate::login::RealmKeks::new(c.w.keys.clone())
        .vault(route.realm)
        .unwrap();
    let db = PgAccounts::sealed(c.w.db.app.clone(), v.clone());
    let mut tx = db.begin(route.tenant, route.realm).await.unwrap();
    vault::set_profile(&mut tx.0, &v, subject, "name", "Dora Q. Dumpling")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let name = c.w.db.name.clone();
    let dump = tokio::task::spawn_blocking(move || access_store::testing::dump(&name));
    let text = dump.await.unwrap().unwrap();
    assert!(text.contains("identity_subjects"), "a real dump");
    for plain in [
        super::recovery::PW,
        "Dora.Dump@Example.com",
        "dora.dump@example.com",
        "Dora Q. Dumpling",
        "PRIVATE KEY",
    ] {
        assert!(!text.contains(plain), "the dump holds {plain:?}");
    }
}
