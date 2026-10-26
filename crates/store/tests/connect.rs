//! OP-7, OP-52, OP-53, OP-130 m.10: the start-up checks against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::Path;

use access_store::StoreError;
use access_store::connect::{Target, check_server, fits, options, supported};
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
    check_server(&db.app, 8, false).await.unwrap();
    assert!(
        matches!(check_server(&db.app, 8, true).await, Err(StoreError::Unsafe(m)) if m.contains("TLS"))
    );
    assert!(
        matches!(check_server(&db.app, 100_000, false).await, Err(StoreError::Unsafe(m)) if m.contains("max_connections"))
    );
}
