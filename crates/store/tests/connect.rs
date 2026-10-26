//! OP-7, OP-52, OP-53, OP-130 m.10: the start-up checks against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::Path;

use access_store::StoreError;
use access_store::connect::{Durability, Target, check_server, fits, options, supported};
use access_store::testing::fresh;
use sqlx::postgres::PgSslMode;

// OP-130 m.10: the client always verifies the full chain against the given root
#[test]
fn options_verify_the_server_fully() {
    let t = Target {
        host: "db.cell-1.internal",
        port: 5432,
        database: "access",
        user: "access_app_login",
        password: "x",
        root_cert: Path::new("/run/secrets/db-root.pem"),
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

// OP-52: a plain connection fails the TLS check; the local and CI servers meet the rest
#[tokio::test]
async fn the_server_check_refuses_an_unencrypted_connection() {
    let db = fresh().await.unwrap();
    let single = Durability::SingleNode;
    check_server(&db.app, 8, false, single).await.unwrap();
    let tls = check_server(&db.app, 8, true, single).await;
    assert!(matches!(tls, Err(StoreError::Unsafe(m)) if m.contains("TLS")));
    let pools = check_server(&db.app, 100_000, false, single).await;
    assert!(matches!(pools, Err(StoreError::Unsafe(m)) if m.contains("max_connections")));
    // U51: the test servers have no synchronous standby, so a replicated deployment is refused
    let replicated = check_server(&db.app, 8, false, Durability::Replicated).await;
    assert!(matches!(replicated, Err(StoreError::Unsafe(m)) if m.contains("synchronous_commit")));
}
