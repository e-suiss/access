//! The environment KEK rotation job against PostgreSQL and the environment's keys in the token (OP-138,
//! OP-144, OP-158 m.3 (y), OP-153 m.3 (gg)): the subject DEKs move to a new KEK generation
//! inside the token, the run is counted and resumes where it stopped, and the accounts stay
//! usable through the whole rotation.

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{PasswordServices, set_password};
use access_identity_account::app::{Actor, Environment};
use access_identity_account::ports::{BreachRanges, RangeUnavailable};
use access_store::identity::TenantTx;
use suiss_crypto::envelope::Kek as _;

use super::management::console;
use super::recovery::{PW, account};
use crate::kek_rotation::rotate;
use crate::login::{EnvironmentKeks, kek_id_at, kek_label_at};

const WHO: Actor<'static> = Actor {
    actor: "test",
    correlation: "test",
};

struct Corpus;

impl BreachRanges for Corpus {
    fn range(&self, _: &str) -> impl Future<Output = Result<String, RangeUnavailable>> + Send {
        std::future::ready(Ok(String::new()))
    }
}

/// Seals a fresh password for `subject` through the environment's vault, which needs its DEK.
async fn reseal(c: &super::management::Console, keks: &EnvironmentKeks, subject: [u8; 16]) {
    use access_identity_account::adapters::system::{cgroup_memory_budget, cores};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::domain::password::Argon2Params;
    let vault = keks.vault(c.route.environment).unwrap();
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let environment = Environment {
        tenant: c.route.tenant,
        environment: c.route.environment,
        kek: &*vault.kek,
        ids: &ids,
    };
    let db = PgAccounts::sealed(c.w.db.app.clone(), vault.clone());
    let h = Hasher::new(HasherConfig::sized(
        Argon2Params::CANONICAL,
        cores(),
        cgroup_memory_budget(),
    ));
    set_password(
        &db,
        &environment,
        &PasswordServices {
            hasher: &h,
            ranges: &Corpus,
            entropy: &SystemEntropy,
        },
        subject,
        PW,
        &WHO,
    )
    .await
    .unwrap();
}

async fn under(c: &super::management::Console, kek: &str) -> usize {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.environment)
        .await
        .unwrap();
    let n = t.wrapped_by_kek(kek, 10_000).await.unwrap().len();
    t.commit().await.unwrap();
    n
}

// OP-138, OP-144, OP-158, CR-32
#[tokio::test]
async fn a_environment_kek_rotation_rewraps_inside_the_token_and_resumes() {
    let c = console("kek-rotation", false).await;
    let environment = *c.route.environment.as_bytes();
    let (first, second) = (kek_id_at(&environment, 1), kek_id_at(&environment, 2));
    let mut subjects = Vec::new();
    for n in 0..3 {
        subjects.push(account(&c, &format!("rotate{n}@example.com"), true).await);
    }
    let before = under(&c, &first).await;
    assert!(before >= 3, "{before}");
    assert_eq!(under(&c, &second).await, 0);

    let keks = EnvironmentKeks::new(c.w.keys.clone());
    let stopped = rotate(
        &keks,
        &c.w.db.app,
        (c.route.tenant, c.route.environment),
        1,
        1,
    )
    .await
    .unwrap();
    assert_eq!(stopped.moved, 1);
    assert_eq!(stopped.rotation.from_kek, first);
    assert_eq!(stopped.rotation.to_kek, second);
    assert!(!stopped.rotation.finished);
    assert_eq!(under(&c, &first).await, before - 1);
    assert!(c.w.keys.kek(&kek_label_at(&environment, 2)).is_ok());

    for s in &subjects {
        reseal(&c, &keks, *s).await;
    }
    reseal(&c, &EnvironmentKeks::new(c.w.keys.clone()), subjects[0]).await;

    let done = rotate(
        &keks,
        &c.w.db.app,
        (c.route.tenant, c.route.environment),
        2,
        100,
    )
    .await
    .unwrap();
    assert!(done.rotation.finished);
    assert_eq!(done.rotation.rewrapped, u64::try_from(before).unwrap());
    assert_eq!(under(&c, &first).await, 0);
    assert_eq!(under(&c, &second).await, before);
    // OP-41
    let audited = access_store::operational::operational_rows(&c.w.db.checkpointer, 10_000)
        .await
        .unwrap();
    assert_eq!(
        audited
            .iter()
            .filter(|r| r.event_type == "kek.rotated" && r.target == second)
            .count(),
        1
    );

    let old = c.w.keys.kek(&kek_label_at(&environment, 1)).unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.environment)
        .await
        .unwrap();
    let moved = t.wrapped_by_kek(&second, 10_000).await.unwrap();
    t.commit().await.unwrap();
    for key in &moved {
        assert!(
            old.unwrap(&key.wrapped).is_err(),
            "the old KEK opens nothing moved"
        );
    }
    let fresh = EnvironmentKeks::new(c.w.keys.clone());
    for s in &subjects {
        reseal(&c, &fresh, *s).await;
    }
    assert_eq!(fresh.vault(c.route.environment).unwrap().kek.id(), second);

    let again = rotate(
        &keks,
        &c.w.db.app,
        (c.route.tenant, c.route.environment),
        256,
        10,
    )
    .await
    .unwrap();
    assert_eq!(again.rotation.to_kek, kek_id_at(&environment, 3));
    assert!(again.rotation.finished);
}
