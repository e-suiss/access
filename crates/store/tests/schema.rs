//! §12.1.3 isolation test 1 and OP-66 m.4: schema invariants read from the catalog, so every
//! future table is covered without being listed here.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::testing::fresh;
use sqlx::{Connection, PgConnection, Row};

const SCOPE_COLUMNS: [&str; 2] = ["domain_id", "tenant_id"];
const APPEND_ONLY: [&str; 8] = [
    "authority_log",
    "authority_nonce",
    "authority_outbox",
    "proof_store",
    "identity_outbox",
    "authority_single_use",
    "identity_audit",
    "audit_checkpoint",
];

async fn admin() -> PgConnection {
    let db = fresh().await.unwrap();
    PgConnection::connect_with(&db.admin).await.unwrap()
}

async fn strings(c: &mut PgConnection, sql: &'static str) -> Vec<String> {
    sqlx::query(sql)
        .fetch_all(c)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect()
}

// TNI-3
#[tokio::test]
async fn every_table_has_forced_row_level_security_and_a_restrictive_scope_policy() {
    let mut c = admin().await;
    let bad = strings(
        &mut c,
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname IN ('access', 'access_ops', 'access_derived') AND c.relkind IN ('r', 'p')
            AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity
                 OR NOT EXISTS (SELECT FROM pg_policy p WHERE p.polrelid = c.oid AND NOT p.polpermissive))",
    )
    .await;
    assert!(bad.is_empty(), "{bad:?}");
}

// HL-33
#[tokio::test]
async fn the_migrator_owns_everything_and_no_role_bypasses_rls() {
    let mut c = admin().await;
    let owners = strings(
        &mut c,
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname IN ('access', 'access_ops', 'access_derived') AND pg_get_userbyid(c.relowner) <> 'access_migrator'
         UNION ALL
         SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname IN ('access', 'access_ops', 'access_derived') AND pg_get_userbyid(p.proowner) <> 'access_migrator'",
    )
    .await;
    assert!(owners.is_empty(), "{owners:?}");
    let bypass = strings(
        &mut c,
        "SELECT rolname::text FROM pg_roles
          WHERE rolname LIKE 'access\\_%' AND (rolbypassrls OR rolsuper OR rolcreaterole OR rolcreatedb)",
    )
    .await;
    assert!(bypass.is_empty(), "{bypass:?}");
}

// TNI-3
#[tokio::test]
async fn primary_keys_and_foreign_keys_start_with_the_scope_column() {
    let mut c = admin().await;
    let rows = sqlx::query(
        "SELECT c.relname::text, con.contype::text, a.attname::text
           FROM pg_constraint con
           JOIN pg_class c ON c.oid = con.conrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = con.conkey[1]
          WHERE n.nspname = 'access' AND con.contype IN ('p', 'f', 'u')  -- scope columns: tenant and domain tables only",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    let bad: Vec<String> = rows
        .iter()
        .filter(|r| !SCOPE_COLUMNS.contains(&r.get::<String, _>(2).as_str()))
        .map(|r| format!("{} {}", r.get::<String, _>(0), r.get::<String, _>(1)))
        .collect();
    assert!(bad.is_empty(), "{bad:?}");
}

#[tokio::test]
async fn no_unlogged_tables_and_no_unpinned_security_definer() {
    let mut c = admin().await;
    let unlogged = strings(
        &mut c,
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname IN ('access', 'access_ops', 'access_derived') AND c.relpersistence = 'u'",
    )
    .await;
    assert!(unlogged.is_empty(), "{unlogged:?}");
    let definer = strings(
        &mut c,
        "SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname IN ('access', 'access_ops', 'access_derived')
            AND NOT EXISTS (SELECT FROM unnest(coalesce(p.proconfig, '{}')) s WHERE s LIKE 'search\\_path=%')",
    )
    .await;
    assert!(definer.is_empty(), "{definer:?}");
}

#[tokio::test]
async fn append_only_tables_grant_no_change_and_carry_both_triggers() {
    let mut c = admin().await;
    let grants = strings(
        &mut c,
        "SELECT table_name::text || ' ' || grantee::text || ' ' || privilege_type::text
           FROM information_schema.role_table_grants
          WHERE table_schema IN ('access', 'access_ops', 'access_derived') AND grantee <> 'access_migrator'
            AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
            AND table_name = ANY (ARRAY['authority_log', 'authority_nonce', 'authority_outbox', 'proof_store', 'identity_outbox', 'authority_single_use', 'identity_audit', 'audit_checkpoint'])",
    )
    .await;
    assert!(grants.is_empty(), "{grants:?}");
    let deletes = strings(
        &mut c,
        "SELECT table_name::text || ' ' || grantee::text FROM information_schema.role_table_grants
          WHERE table_schema IN ('access', 'access_ops', 'access_derived') AND grantee <> 'access_migrator' AND privilege_type IN ('DELETE', 'TRUNCATE')",
    )
    .await;
    assert!(deletes.is_empty(), "OP-73: {deletes:?}");
    for table in APPEND_ONLY {
        let triggers: i64 = sqlx::query(
            "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
              WHERE c.relname = $1 AND t.tgname IN ('append_only_row', 'append_only_truncate') AND NOT t.tgisinternal",
        )
        .bind(table)
        .fetch_one(&mut c)
        .await
        .unwrap()
        .get(0);
        assert_eq!(triggers, 2, "{table}");
    }
}

// TN-20: a unique index that does not start with a scope column is on one of the four global
// identifiers, so uniqueness never becomes a cross-tenant channel
#[tokio::test]
async fn only_the_four_global_identifiers_are_unique_across_tenants() {
    let mut c = admin().await;
    let rows = sqlx::query(
        "SELECT i.relname::text, coalesce(a.attname::text, pg_get_indexdef(x.indexrelid, 1, true))
           FROM pg_index x
           JOIN pg_class i ON i.oid = x.indexrelid
           JOIN pg_class t ON t.oid = x.indrelid
           JOIN pg_namespace n ON n.oid = t.relnamespace
           LEFT JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = x.indkey[0]
          WHERE n.nspname = 'access' AND x.indisunique",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    let allowed = [
        "domain_id",
        "tenant_id",
        "slug",
        "hostname",
        "client_id",
        "kid",
    ];
    let bad: Vec<String> = rows
        .iter()
        .filter(|r| !allowed.contains(&r.get::<String, _>(1).as_str()))
        .map(|r| format!("{} on {}", r.get::<String, _>(0), r.get::<String, _>(1)))
        .collect();
    assert!(bad.is_empty(), "{bad:?}");
}
