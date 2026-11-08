//! OP-7, OP-52, OP-53, OP-130 m.10: the start-up checks against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::StoreError;
use access_store::connect::{Durability, Target, check_server, fits, migrate, options, supported};
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
    check_server(&db.app, 8, false, single).await.unwrap();
    let tls = check_server(&db.app, 8, true, single).await;
    assert!(matches!(tls, Err(StoreError::Unsafe(m)) if m.contains("TLS")));
    let pools = check_server(&db.app, 100_000, false, single).await;
    assert!(matches!(pools, Err(StoreError::Unsafe(m)) if m.contains("max_connections")));
    // U51
    let replicated = check_server(&db.app, 8, false, Durability::Replicated).await;
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
