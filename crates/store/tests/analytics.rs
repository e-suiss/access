//! IDP-36, TI-18, OP-47, OP-151 m.3 (n): the analytics summary tables hold the realm, the day and
//! counters, nothing that could carry a personal identifier or a pseudonym.

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::analytics::{COUNTERS, KEY};
use access_store::testing::fresh;

// IDP-36, TI-18: an allowlist of column names and types; a new column of any other kind fails
#[tokio::test]
async fn analytics_columns_cannot_carry_identifiers() {
    let db = fresh().await.unwrap();
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text, data_type::text
           FROM information_schema.columns
          WHERE table_schema = 'access' AND table_name LIKE 'analytics\\_%'
          ORDER BY table_name, ordinal_position",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap();
    for table in ["analytics_daily", "analytics_alert"] {
        assert!(rows.iter().any(|r| r.0 == table), "{table}");
    }
    for (table, column, ty) in &rows {
        let allowed = match column.as_str() {
            "tenant_id" | "realm_id" => ty == "uuid",
            "day" => ty == "integer",
            "computed_at" | "created_at" => ty == "timestamp with time zone",
            "kind" => table == "analytics_alert" && ty == "text",
            "observed" | "baseline" => table == "analytics_alert" && ty == "bigint",
            c if COUNTERS.contains(&c) => table == "analytics_daily" && ty == "bigint",
            _ => false,
        };
        assert!(allowed, "{table}.{column} {ty}");
    }
    let daily = rows.iter().filter(|r| r.0 == "analytics_daily").count();
    assert_eq!(daily, COUNTERS.len() + KEY.len());
    let kind: Vec<(String,)> = sqlx::query_as(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint
          WHERE conrelid = 'access.analytics_alert'::regclass AND contype = 'c'
            AND pg_get_constraintdef(oid) LIKE '%kind%'",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap();
    assert_eq!(kind.len(), 1, "the alert kind is a closed code");
}
