//! OP-7, OP-52, OP-53, OP-130 m.10: the start-up checks against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::StoreError;
use access_store::connect::{
    ConnectError, Durability, Quorum, Site, Standby, Target, Topology, check_durability,
    check_server, check_topology, fits, migrate, options, quorum, supported,
};
use access_store::testing::{fresh, unmigrated};
use sqlx::postgres::PgSslMode;

// OP-130 m.10
#[test]
fn options_verify_the_server_fully() {
    let t = Target {
        host: "db.cell-1.internal",
        port: 5432,
        database: "access",
        user: "access_app_login",
        password: "x",
        root_cert: b"-----BEGIN CERTIFICATE-----\n",
    };
    assert!(matches!(options(&t).get_ssl_mode(), PgSslMode::VerifyFull));
}

// OP-7, OP-53
#[test]
fn version_and_pool_limits() {
    assert!(supported(180_000) && supported(180_006));
    assert!(!supported(170_005));
    assert!(fits(70, 100) && !fits(71, 100));
}

// OP-52
#[tokio::test]
async fn the_server_check_refuses_an_unencrypted_connection() {
    let db = fresh().await.unwrap();
    let single = Durability::SingleNode;
    check_server(&db.app, 8, false, single, None).await.unwrap();
    let tls = check_server(&db.app, 8, true, single, None).await;
    assert!(matches!(tls, Err(StoreError::Unsafe(m)) if m.contains("TLS")));
    let pools = check_server(&db.app, 100_000, false, single, None).await;
    assert!(matches!(pools, Err(StoreError::Unsafe(m)) if m.contains("max_connections")));
    // U51
    let replicated = check_server(&db.app, 8, false, Durability::Replicated, None).await;
    assert!(matches!(replicated, Err(StoreError::Unsafe(m)) if m.contains("synchronous_commit")));
}

// OP-55, OP-12, OP-130 m.2
#[tokio::test]
async fn the_migration_job_runs_as_the_migrator_and_is_idempotent() {
    let db = unmigrated().await.unwrap();
    let total = i64::try_from(access_store::MIGRATOR.iter().count()).unwrap();
    let applied = async || -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
            .fetch_one(&db.migrator)
            .await
            .unwrap()
    };
    migrate(&db.migrator).await.unwrap();
    assert_eq!(applied().await, total);
    migrate(&db.migrator).await.unwrap();
    assert_eq!(applied().await, total);
    let foreign: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname IN ('access', 'access_ops', 'access_derived')
            AND pg_get_userbyid(c.relowner) <> 'access_migrator'",
    )
    .fetch_one(&db.migrator)
    .await
    .unwrap();
    assert_eq!(foreign, 0);
    // OP-12
    assert!(migrate(&db.app).await.is_err());
}

// OP-55, OP-138
#[tokio::test]
async fn the_migration_job_lists_what_it_applied() {
    let db = unmigrated().await.unwrap();
    let first = access_store::connect::migrate_listed(&db.migrator)
        .await
        .unwrap();
    let known: Vec<i64> = access_store::MIGRATOR.iter().map(|m| m.version).collect();
    assert_eq!(first.iter().map(|a| a.version).collect::<Vec<_>>(), known);
    assert!(first.iter().any(|a| a.description == "m2 sandbox domains"));
    let second = access_store::connect::migrate_listed(&db.migrator)
        .await
        .unwrap();
    assert_eq!(second, Vec::new());
}

// OP-24, OP-54-RL6, OPI-4, Ek B 5989, 6093
#[test]
fn op_54_rl6_one_standby_or_local_commits_are_refused() {
    let r = Durability::Replicated;
    assert_eq!(
        quorum("ANY 1 (sb_a, sb_b)"),
        Some(Quorum {
            k: 1,
            names: vec![String::from("sb_a"), String::from("sb_b")]
        })
    );
    assert_eq!(
        quorum(r#"any 1 ("sb_a", sb_b, sb_c)"#).unwrap().names.len(),
        3
    );
    check_durability("on", "ANY 1 (sb_a, sb_b)", r).unwrap();
    check_durability("remote_apply", "ANY 1 (sb_a, sb_b)", r).unwrap();
    for one in [
        "ANY 1 (sb_a)",
        "sb_a",
        "FIRST 1 (sb_a, sb_b)",
        "*",
        "ANY 2 (sb_a, sb_b)",
        "ANY 0 (a, b)",
        "ANY 1 (a, a)",
        "ANY 1 (a b)",
    ] {
        assert!(
            matches!(check_durability("on", one, r), Err(ConnectError::Quorum(_))),
            "{one}"
        );
    }
    for weak in ["local", "off", "remote_write"] {
        assert!(matches!(
            check_durability(weak, "ANY 1 (sb_a, sb_b)", r),
            Err(ConnectError::Durability { .. })
        ));
        assert!(check_durability(weak, "", Durability::SingleNode).is_err());
    }
    assert!(check_durability("on", "", r).is_err());
    check_durability("on", "", Durability::SingleNode).unwrap();
}

fn site(zone: &str, region: &str) -> Site {
    Site {
        zone: zone.into(),
        region: region.into(),
    }
}

fn standby(name: &str, zone: &str, region: &str, rtt_ms: Option<u32>) -> Standby {
    Standby {
        name: name.into(),
        site: site(zone, region),
        rtt_ms,
    }
}

// OP-24, OP-28, OP-54-RL5, OPI-5, Ek B 5989, 6090
#[test]
fn op_54_rl5_standbys_in_one_zone_or_across_continents_are_refused() {
    let q = quorum("ANY 1 (sb_a, sb_b)").unwrap();
    let mut t = Topology {
        primary: site("a", "eu-central-1"),
        multi_region_sync: false,
        standbys: vec![
            standby("sb_a", "b", "eu-central-1", None),
            standby("sb_b", "c", "eu-central-1", None),
        ],
    };
    check_topology(&q, &t).unwrap();
    t.standbys[1].site.zone = String::from("b");
    assert!(matches!(check_topology(&q, &t), Err(ConnectError::Topology(m)) if m.contains("zone")));
    t.standbys[1].site.zone = String::from("a");
    assert!(check_topology(&q, &t).is_err());
    t.standbys[1] = standby("sb_b", "c", "us-east-1", Some(80));
    assert!(
        matches!(check_topology(&q, &t), Err(ConnectError::Topology(m)) if m.contains("multi-region"))
    );
    t.multi_region_sync = true;
    assert!(
        matches!(check_topology(&q, &t), Err(ConnectError::Topology(m)) if m.contains("10 ms"))
    );
    t.standbys[1] = standby("sb_b", "c", "eu-west-1", Some(6));
    check_topology(&q, &t).unwrap();
    t.standbys.pop();
    assert!(
        matches!(check_topology(&q, &t), Err(ConnectError::Topology(m)) if m.contains("not declared"))
    );
}

// OPI-5, OP-54-RL3, OP-54-RL4, Ek B 6090
#[tokio::test]
async fn opi_5_logical_replication_or_a_multi_primary_extension_is_refused() {
    let db = fresh().await.unwrap();
    let single = Durability::SingleNode;
    check_server(&db.app, 8, false, single, None).await.unwrap();
    let mut admin = <sqlx::PgConnection as sqlx::Connection>::connect_with(&db.admin)
        .await
        .unwrap();
    sqlx::query(
        "CREATE SUBSCRIPTION w7_lww CONNECTION 'host=127.0.0.1 dbname=nowhere' PUBLICATION p \
         WITH (connect = false, enabled = false, create_slot = false, slot_name = NONE)",
    )
    .execute(&mut admin)
    .await
    .unwrap();
    let lww = check_server(&db.app, 8, false, single, None).await;
    sqlx::query("DROP SUBSCRIPTION w7_lww")
        .execute(&mut admin)
        .await
        .unwrap();
    assert!(
        matches!(&lww, Err(StoreError::Unsafe(m)) if m.contains("subscription")),
        "{lww:?}"
    );
}
