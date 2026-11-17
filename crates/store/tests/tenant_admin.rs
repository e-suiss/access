//! OP-159 m.47 against a real PostgreSQL: one slug space over environments and foundings, one
//! primary environment per tenant, a founding's secrets as hashes that change only by a
//! reinvitation, administrators that become owners once and are removed once, and nothing deleted
//! (TN-16, TN-138, TN-141, OP-73).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_environment, create_tenant};
use access_store::tenant_admin::{
    NewAdmin, NewFounding, SessionInstance, add_admin, admin, admins, attach_instance,
    complete_founding, create_primary_environment, due_tenants, end_admin, end_line, founding,
    founding_by_token, insert_founding, line_of_party, lines, make_owner, open_line,
    reinvite_founding, session_instances, set_admin_party, set_display_name, set_tenant_status,
    slug_free, stated, tenant_environments, tenant_profile, verify_founding,
};
use access_store::testing::{TestDb, fresh};

async fn domain(db: &TestDb, tenant: TenantId, seed: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *tenant.as_bytes(), &g, &[])
        .await
        .unwrap();
    d
}

fn new_id(seed: u8) -> EnvironmentId {
    EnvironmentId::from_bytes([
        0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, seed,
    ])
}

async fn founded(db: &TestDb, slug: &str, seed: u8) -> (TenantId, EnvironmentId) {
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let environment = new_id(seed);
    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    assert!(
        insert_founding(
            &mut t,
            &NewFounding {
                slug,
                environment,
                founder_index: &[seed; 32],
                token_hash: &[seed.wrapping_add(1); 32],
                code_hash: &[seed.wrapping_add(2); 32],
                exercise: &[seed.wrapping_add(3); 32],
                ttl_s: 7 * 86_400,
            },
        )
        .await
        .unwrap()
    );
    t.commit().await.unwrap();
    (tenant, environment)
}

fn owner_of(party: &[u8; 16]) -> NewAdmin<'_> {
    NewAdmin {
        party: Some(party),
        owner: true,
        exercise: None,
        cooling_s: None,
        scope: None,
    }
}

fn plain(exercise: Option<&[u8; 32]>, cooling_s: Option<i64>) -> NewAdmin<'_> {
    NewAdmin {
        party: None,
        owner: false,
        exercise,
        cooling_s,
        scope: None,
    }
}

async fn raw(db: &TestDb, tenant: TenantId, sql: &str) -> Result<(), String> {
    let t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    t.raw_rows(sql).await.map(drop).map_err(|e| e.to_string())
}

async fn raw_in(
    db: &TestDb,
    (tenant, environment): (TenantId, EnvironmentId),
    sql: &str,
) -> Result<(), String> {
    let t = TenantTx::begin(&db.app, tenant, environment).await.unwrap();
    t.raw_rows(sql).await.map(drop).map_err(|e| e.to_string())
}

// TN-16, TN-20, TN-141
#[tokio::test]
async fn a_founding_reserves_its_slug_against_every_environment() {
    let db = fresh().await.unwrap();
    let (acme, m) = founded(&db, "acme-admin", 1).await;
    assert!(!slug_free(&db.app, "acme-admin").await.unwrap());
    assert!(slug_free(&db.router, "acme").await.unwrap());

    let other = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, other, 2).await;
    let mut t = TenantTx::begin_tenant(&db.app, other).await.unwrap();
    assert!(
        create_environment(&mut t, &d, "acme-admin", "pool-default")
            .await
            .is_err()
    );
    t.rollback().await.unwrap();

    let mut t = TenantTx::begin_tenant(&db.app, other).await.unwrap();
    create_environment(&mut t, &d, "globex", "pool-default")
        .await
        .unwrap();
    t.commit().await.unwrap();
    let mut t = TenantTx::begin_tenant(&db.app, other).await.unwrap();
    assert!(
        insert_founding(
            &mut t,
            &NewFounding {
                slug: "globex",
                environment: new_id(9),
                founder_index: &[9; 32],
                token_hash: &[9; 32],
                code_hash: &[9; 32],
                exercise: &[9; 32],
                ttl_s: 86_400,
            },
        )
        .await
        .is_err()
    );
    t.rollback().await.unwrap();

    let d = domain(&db, acme, 3).await;
    let mut t = TenantTx::begin_tenant(&db.app, acme).await.unwrap();
    assert!(
        create_environment(&mut t, &d, "acme-admin", "pool-default")
            .await
            .is_err(),
        "a standard environment never takes a founding's slug"
    );
    t.rollback().await.unwrap();
    let mut t = TenantTx::begin_tenant(&db.app, acme).await.unwrap();
    create_primary_environment(&mut t, m, &d, ("acme-admin", "pool-default"))
        .await
        .unwrap();
    t.commit().await.unwrap();

    // TN-138
    let d2 = domain(&db, acme, 4).await;
    let mut t = TenantTx::begin_tenant(&db.app, acme).await.unwrap();
    assert!(
        create_primary_environment(&mut t, new_id(8), &d2, ("acme-ops", "pool-default"))
            .await
            .is_err()
    );
    t.rollback().await.unwrap();
    let mut t = TenantTx::begin_tenant(&db.app, acme).await.unwrap();
    let envs = tenant_environments(&mut t).await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].kind, "primary");
    assert!(
        raw(
            &db,
            acme,
            "UPDATE access.environments SET kind = 'standard'"
        )
        .await
        .is_err()
    );
}

// TN-89 (1), (8), TN-141, OP-73
#[tokio::test]
async fn a_founding_changes_only_by_verification_completion_or_reinvitation() {
    let db = fresh().await.unwrap();
    let (tenant, environment) = founded(&db, "acme-admin", 1).await;
    let route = founding_by_token(&db.router, &[2; 32])
        .await
        .unwrap()
        .unwrap();
    assert!(route.tenant == tenant && route.environment == environment);
    assert!(!route.verified && !route.completed);
    assert!(
        founding_by_token(&db.app, &[7; 32])
            .await
            .unwrap()
            .is_none()
    );

    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    assert!(!complete_founding(&mut t, &[5; 16]).await.unwrap());
    assert!(verify_founding(&mut t).await.unwrap());
    assert!(!verify_founding(&mut t).await.unwrap());
    t.commit().await.unwrap();

    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    assert!(
        reinvite_founding(&mut t, &[20; 32], &[21; 32], 86_400)
            .await
            .unwrap()
    );
    let f = founding(&mut t).await.unwrap().unwrap();
    t.commit().await.unwrap();
    assert_eq!((f.reinvites, f.verified), (1, false));
    assert!(
        founding_by_token(&db.app, &[2; 32])
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        founding_by_token(&db.app, &[20; 32])
            .await
            .unwrap()
            .is_some()
    );

    for bad in [
        "UPDATE access.tenant_foundings SET token_hash = '\\x2222222222222222222222222222222222222222222222222222222222222222'",
        "UPDATE access.tenant_foundings SET primary_slug = 'other-slug'",
        "UPDATE access.tenant_foundings SET expires_at = issued_at + interval '31 days', reinvites = reinvites + 1",
        "DELETE FROM access.tenant_foundings",
        "TRUNCATE access.tenant_foundings",
    ] {
        assert!(raw(&db, tenant, bad).await.is_err(), "{bad}");
    }

    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    assert!(verify_founding(&mut t).await.unwrap());
    assert!(complete_founding(&mut t, &[5; 16]).await.unwrap());
    t.commit().await.unwrap();
    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    assert!(
        !reinvite_founding(&mut t, &[30; 32], &[31; 32], 86_400)
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    assert!(
        founding_by_token(&db.app, &[20; 32])
            .await
            .unwrap()
            .unwrap()
            .completed
    );

    // TN-1, TN-131
    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    assert!(set_display_name(&mut t, "Acme").await.unwrap());
    assert!(
        set_tenant_status(&mut t, "active", "suspended")
            .await
            .unwrap()
    );
    assert!(
        !set_tenant_status(&mut t, "active", "suspended")
            .await
            .unwrap()
    );
    let (name, status) = tenant_profile(&mut t).await.unwrap().unwrap();
    t.commit().await.unwrap();
    assert_eq!(
        (name.as_deref(), status.as_str()),
        (Some("Acme"), "suspended")
    );
}

// OP-159 m.47 (e), (f), TN-109, TN-142, OP-73
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one administrator from its addition through its removal"
)]
async fn administrators_own_once_end_once_and_their_lines_stay() {
    let db = fresh().await.unwrap();
    let (tenant, m) = founded(&db, "acme-admin", 1).await;
    let d = domain(&db, tenant, 3).await;
    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    create_primary_environment(&mut t, m, &d, ("acme-admin", "pool-default"))
        .await
        .unwrap();
    t.commit().await.unwrap();

    let founder = [1; 16];
    let invited = [2; 16];
    let mut t = TenantTx::begin(&db.app, tenant, m).await.unwrap();
    assert!(
        add_admin(&mut t, &founder, &owner_of(&[1; 16]))
            .await
            .unwrap()
    );
    assert!(
        !add_admin(&mut t, &founder, &plain(None, None))
            .await
            .unwrap()
    );
    assert!(
        add_admin(&mut t, &invited, &plain(Some(&[9; 32]), Some(86_400)))
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    let mut t = TenantTx::begin(&db.app, tenant, m).await.unwrap();
    assert!(
        add_admin(
            &mut t,
            &[3; 16],
            &NewAdmin {
                party: Some(&[3; 16]),
                owner: true,
                exercise: None,
                cooling_s: Some(86_400),
                scope: None,
            },
        )
        .await
        .is_err(),
        "no ownership at a cooling first acceptance"
    );
    t.rollback().await.unwrap();

    let mut t = TenantTx::begin(&db.app, tenant, m).await.unwrap();
    let listed = admins(&mut t).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed[1].cooling_until_ms.is_some());
    assert!(
        make_owner(&mut t, &invited).await.is_err(),
        "an owner has a Party"
    );
    t.rollback().await.unwrap();
    let mut t = TenantTx::begin(&db.app, tenant, m).await.unwrap();
    assert!(
        set_admin_party(&mut t, &invited, &[0x55; 16])
            .await
            .unwrap()
    );
    assert!(
        !set_admin_party(&mut t, &invited, &[0x56; 16])
            .await
            .unwrap()
    );
    assert!(make_owner(&mut t, &invited).await.unwrap());
    assert!(!make_owner(&mut t, &invited).await.unwrap());
    let consuming = DomainId::from_bytes([0x44; 32]);
    assert!(
        open_line(&mut t, &invited, &consuming, &[0x55; 16])
            .await
            .unwrap()
    );
    assert!(
        stated(
            &mut t,
            (&invited, &consuming, 1),
            &[0x66; 16],
            (1_000, 3_601_000)
        )
        .await
        .unwrap()
    );
    t.commit().await.unwrap();
    assert_eq!(due_tenants(&db.app, 3_601_000).await.unwrap().len(), 1);
    assert!(due_tenants(&db.app, 3_600_999).await.unwrap().is_empty());

    let mut t = TenantTx::begin(&db.app, tenant, m).await.unwrap();
    assert!(end_admin(&mut t, &invited, Some(&[8; 32])).await.unwrap());
    assert!(!end_admin(&mut t, &invited, None).await.unwrap());
    assert!(!make_owner(&mut t, &invited).await.unwrap());
    assert!(
        end_line(&mut t, (&invited, &consuming, 1), 2_000, None)
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    assert_eq!(due_tenants(&db.app, 0).await.unwrap().len(), 1);
    let mut t = TenantTx::begin(&db.app, tenant, m).await.unwrap();
    assert!(
        end_line(&mut t, (&invited, &consuming, 1), 2_500, Some(&[0x77; 16]))
            .await
            .unwrap()
    );
    assert!(
        !stated(
            &mut t,
            (&invited, &consuming, 1),
            &[0x68; 16],
            (3_000, 9_000)
        )
        .await
        .unwrap()
    );
    let line = lines(&mut t, Some(&invited)).await.unwrap();
    let removed = admin(&mut t, &invited).await.unwrap().unwrap();
    t.commit().await.unwrap();
    assert_eq!(line[0].ended_ms, Some(2_000));
    assert_eq!(line[0].ended_claim, Some([0x77; 16]));
    assert_eq!(line[0].episode, 1);
    assert!(removed.ended_ms.is_some() && removed.owner);
    assert!(due_tenants(&db.app, 0).await.unwrap().is_empty());
    // OP-159 m.48 (d)
    let mut t = TenantTx::begin(&db.app, tenant, m).await.unwrap();
    assert!(
        open_line(&mut t, &invited, &consuming, &[0x55; 16])
            .await
            .unwrap()
    );
    assert!(
        !open_line(&mut t, &invited, &consuming, &[0x55; 16])
            .await
            .unwrap()
    );
    let both = lines(&mut t, Some(&invited)).await.unwrap();
    assert_eq!(
        both.iter()
            .map(|l| (l.episode, l.ended_ms.is_some()))
            .collect::<Vec<_>>(),
        [(1, true), (2, false)]
    );
    assert!(
        stated(
            &mut t,
            (&invited, &consuming, 2),
            &[0x69; 16],
            (3_000, 9_000)
        )
        .await
        .unwrap()
    );
    let (found, _) = line_of_party(&mut t, &consuming, &[0x55; 16])
        .await
        .unwrap()
        .unwrap();
    assert_eq!((found.episode, found.claim), (2, Some([0x69; 16])));
    t.commit().await.unwrap();
    assert!(
        raw_in(
            &db,
            (tenant, m),
            "UPDATE access.tenant_admin_claims SET episode = 3 WHERE episode = 2"
        )
        .await
        .is_err()
    );
    for bad in [
        "UPDATE access.tenant_admins SET owner = false",
        "DELETE FROM access.tenant_admins",
        "UPDATE access.tenant_admin_claims SET party_id = '\\x00000000000000000000000000000000'",
        "DELETE FROM access.tenant_admin_claims",
    ] {
        assert!(raw_in(&db, (tenant, m), bad).await.is_err(), "{bad}");
    }
}

// TN-142, INV-13
#[tokio::test]
async fn a_console_session_holds_one_instance_per_domain() {
    let db = fresh().await.unwrap();
    let session = access_store::console::open(
        &db.app,
        &access_store::console::NewConsoleSession {
            cookie_digest: &[1; 32],
            tenant: TenantId::from_bytes([
                0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1,
            ]),
            environment: new_id(2),
            subject: [3; 16],
            login_session: [4; 16],
            session_epoch: 0,
            slug: "acme-admin",
            domain: &[5; 32],
            account: "acc_1",
            binding: &[6; 8],
            auth_time_ms: 1_000,
            now_ms: 1_000,
        },
    )
    .await
    .unwrap();
    let one = |seed: u8, slug: &str| SessionInstance {
        domain: DomainId::from_bytes([seed; 32]),
        slug: String::from(slug),
        party: [seed; 16],
        kid: [seed; 32],
        key: vec![seed; 32],
    };
    assert!(
        attach_instance(&db.app, &session, &one(5, "acme-admin"), 2_000)
            .await
            .unwrap()
    );
    assert!(
        attach_instance(&db.app, &session, &one(7, "acme"), 2_000)
            .await
            .unwrap()
    );
    let mut other = one(7, "acme");
    other.kid = [9; 32];
    assert!(
        !attach_instance(&db.app, &session, &other, 3_000)
            .await
            .unwrap()
    );
    let all = session_instances(&db.app, &session).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].kid, [7; 32]);
}
