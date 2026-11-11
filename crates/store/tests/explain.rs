//! OP-66, OP-138, OP-158 m.3 (z): the `EXPLAIN` plan gate. The frequent read and write-path
//! queries are planned generically on a migrated database with sequential scans priced out: a
//! `Seq Scan` left in a plan means no index serves the query, and a `Sort` appears only where the
//! query is listed as sorting a bounded result. `just explain-gate` runs this file.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::testing::fresh;
use sqlx::{Connection, PgConnection, Row};

/// A frequent query: its name, its SQL with `$n` parameters and whether a `Sort` node is
/// expected (a sort of a bounded set the index cannot order, such as a union).
struct Frequent {
    name: &'static str,
    sql: &'static str,
    sorts: bool,
}

const FREQUENT: &[Frequent] = &[
    Frequent {
        name: "state_of",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT key, value, version FROM access.authority_state WHERE domain_id = $1 AND key = ANY($2::bytea[]) ORDER BY key"
        ),
        sorts: false,
    },
    Frequent {
        name: "read_head",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT pos, epoch, leaf_hash, recorded_at FROM access.domain_head WHERE domain_id = $1"
        ),
        sorts: false,
    },
    Frequent {
        name: "read_log",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT pos, kind, recorded_at, leaf_hash, envelope FROM access.authority_log WHERE domain_id = $1 AND pos BETWEEN $2 AND $3 ORDER BY pos"
        ),
        sorts: false,
    },
    Frequent {
        name: "position_at",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT pos FROM access.authority_log WHERE domain_id = $1 AND recorded_at <= $2 ORDER BY recorded_at DESC, pos DESC LIMIT 1"
        ),
        sorts: false,
    },
    Frequent {
        name: "find_nonce",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT nonce, decision_pos FROM (SELECT nonce, decision_pos FROM access.authority_nonce WHERE domain_id = $1 AND nonce = $2 UNION ALL SELECT nonce, decision_pos FROM access.authority_nonce_archive WHERE domain_id = $1 AND nonce = $2) n ORDER BY decision_pos DESC LIMIT 1"
        ),
        sorts: true,
    },
    Frequent {
        name: "find_opening",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT decision_pos FROM access.authority_nonce WHERE domain_id = $1 AND intent_digest = $2 AND outcome = 'require_action' ORDER BY decision_pos DESC LIMIT 1"
        ),
        sorts: false,
    },
    Frequent {
        name: "grants_in",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT grant_id FROM access_derived.grant_index WHERE domain_id = $1 AND namespace = $2 AND NOT ended AND grant_id > $3 ORDER BY grant_id LIMIT $4"
        ),
        sorts: false,
    },
    Frequent {
        name: "keys_of",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT kid, party_id FROM access_derived.key_index WHERE domain_id = $1 AND kid = ANY($2::bytea[])"
        ),
        sorts: false,
    },
    Frequent {
        name: "closure_of",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT class, members, pos FROM access_derived.group_closure WHERE domain_id = $1 AND class = ANY($2::text[])"
        ),
        sorts: false,
    },
    Frequent {
        name: "ordinals_of",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT party_id, ordinal FROM access_derived.party_ordinal WHERE domain_id = $1 AND party_id = ANY($2::bytea[])"
        ),
        sorts: false,
    },
    Frequent {
        name: "derived_cursor",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT pos FROM access_derived.cursor WHERE domain_id = $1"
        ),
        sorts: false,
    },
    Frequent {
        name: "witnessed_through",
        sql: concat!(
            "EXPLAIN (GENERIC_PLAN) ",
            "SELECT max(size) FROM access.witness_cosign WHERE domain_id = $1"
        ),
        sorts: false,
    },
];

/// The node types of a text plan, outermost first.
fn nodes(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.trim_start().trim_start_matches("->").trim_start())
        .filter(|l| !l.contains(':') || l.contains("  ("))
        .filter_map(|l| l.split("  (").next())
        .map(|l| {
            l.split(" on ")
                .next()
                .unwrap_or(l)
                .split(" using ")
                .next()
                .unwrap_or(l)
                .to_owned()
        })
        .collect()
}

// OP-66, OP-138, Ek B 6112
#[tokio::test]
async fn frequent_queries_use_an_index_and_sort_only_where_listed() {
    let db = fresh().await.unwrap();
    let mut c = PgConnection::connect_with(&db.admin).await.unwrap();
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut c)
        .await
        .unwrap();
    let mut failed = Vec::new();
    for q in FREQUENT {
        let lines: Vec<String> = sqlx::raw_sql(q.sql)
            .fetch_all(&mut c)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", q.name))
            .iter()
            .map(|r| r.get::<String, _>(0))
            .collect();
        let kinds = nodes(&lines);
        let has = |k: &str| kinds.iter().any(|n| n == k);
        if has("Seq Scan") {
            failed.push(format!("{}: sequential scan in {kinds:?}", q.name));
        }
        if !q.sorts && (has("Sort") || has("Incremental Sort")) {
            failed.push(format!("{}: unexpected sort in {kinds:?}", q.name));
        }
        println!("explain-gate {} {kinds:?}", q.name);
    }
    assert!(failed.is_empty(), "{failed:#?}");
}
