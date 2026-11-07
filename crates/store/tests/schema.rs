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
const APPEND_ONLY: [&str; 13] = [
    "authority_log",
    "authority_audit",
    "authority_audit_checkpoint",
    "authority_nonce",
    "authority_outbox",
    "proof_store",
    "identity_outbox",
    "authority_single_use",
    "identity_audit",
    "audit_checkpoint",
    "relay_undelivered",
    "idp_config_log",
    "backchannel_undelivered",
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

/// Every (table, role, privilege) granted in `access` and `access_ops` to a role other than the
/// owner without a RESTRICTIVE policy that applies to that role and command.
const UNRESTRICTED_GRANTS: &str = "
SELECT n.nspname::text || '.' || c.relname::text || ' ' || r.rolname::text || ' ' || priv.p
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 CROSS JOIN pg_roles r
 CROSS JOIN (VALUES ('SELECT', 'r'), ('INSERT', 'a'), ('UPDATE', 'w'), ('DELETE', 'd')) AS priv (p, cmd)
 WHERE n.nspname IN ('access', 'access_ops') AND c.relkind IN ('r', 'p')
   AND r.rolname LIKE 'access\\_%' AND NOT r.rolcanlogin AND r.oid <> c.relowner
   AND has_table_privilege(r.oid, c.oid, priv.p)
   AND NOT EXISTS (
         SELECT FROM pg_policy pol
          WHERE pol.polrelid = c.oid AND NOT pol.polpermissive
            AND pol.polcmd::text IN ('*', priv.cmd)
            AND (0 = ANY (pol.polroles)
                 OR EXISTS (SELECT FROM unnest(pol.polroles) pr WHERE pg_has_role(r.oid, pr, 'MEMBER'))))
 ORDER BY 1";

// TNI-3, OP-131: each role's grant on a table meets a RESTRICTIVE policy for that
// role and command, in the tenant schema and in the operations schema
#[tokio::test]
async fn every_granted_role_meets_a_restrictive_policy_for_its_command() {
    let mut c = admin().await;
    let bad = strings(&mut c, UNRESTRICTED_GRANTS).await;
    assert!(bad.is_empty(), "{bad:?}");
    for sql in [
        "CREATE TABLE access_ops.tni3_probe (x int)",
        "ALTER TABLE access_ops.tni3_probe ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE access_ops.tni3_probe FORCE ROW LEVEL SECURITY",
        "CREATE POLICY router_only ON access_ops.tni3_probe AS RESTRICTIVE FOR ALL TO access_router USING (true)",
        "CREATE POLICY reads ON access_ops.tni3_probe AS RESTRICTIVE FOR SELECT TO access_app USING (true)",
        "GRANT SELECT, INSERT ON access_ops.tni3_probe TO access_app, access_router",
    ] {
        sqlx::query(sql).execute(&mut c).await.unwrap();
    }
    let probe = strings(&mut c, UNRESTRICTED_GRANTS).await;
    assert_eq!(
        probe,
        vec!["access_ops.tni3_probe access_app INSERT".to_owned()]
    );
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
            AND table_name = ANY (ARRAY['authority_log', 'authority_nonce', 'authority_outbox', 'proof_store', 'identity_outbox', 'authority_single_use', 'identity_audit', 'audit_checkpoint', 'relay_undelivered', 'idp_config_log', 'backchannel_undelivered', 'authority_audit', 'authority_audit_checkpoint'])",
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

// §9.7.1, §9.16.3, C30: explain traces and Cedar diagnostics are operator telemetry, never the
// record: no table of the Authority Record or its proofs has a trace, span or diagnostics column
#[tokio::test]
async fn record_tables_carry_no_trace_columns() {
    let mut c = admin().await;
    let traced = strings(
        &mut c,
        "SELECT table_name::text || '.' || column_name::text FROM information_schema.columns
          WHERE table_schema = 'access'
            AND table_name IN ('authority_log', 'authority_log_default', 'authority_nonce',
                               'authority_state', 'authority_version', 'authority_counter',
                               'authority_single_use', 'authority_receipt', 'proof_store')
            AND (column_name ILIKE '%trace%' OR column_name ILIKE '%span%'
                 OR column_name ILIKE '%diagnostic%' OR column_name ILIKE '%explain%')",
    )
    .await;
    assert!(traced.is_empty(), "{traced:?}");
}
