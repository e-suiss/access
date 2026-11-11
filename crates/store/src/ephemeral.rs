//! Day partitions of the ephemeral protocol tables (OP-146 m.5 (f), m.7 (d), m.10 (g)): login
//! flows, authorization requests and codes, client assertion and DPoP replay keys, login
//! counters and Claim Ingest submission digests (OP-150 m.2). The archive role opens each day
//! ahead; a day that is not open is a cache outage for DPoP and Claim Ingest and lands in the
//! default partition elsewhere. Once a day is past its TTL, the archive job closes it: the one
//! partition drop OP-73 allows, for these tables only (OP-73 m.7, OP-158 m.3 (w)).

use sqlx::PgPool;

use crate::StoreError;

/// Opens the login counter partition of `day` (days since the Unix epoch); idempotent.
///
/// # Errors
/// [`StoreError`].
pub async fn open_throttle_day(archive: &PgPool, day: i32) -> Result<String, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT access.open_throttle_day(date '1970-01-01' + $1::int) AS "name!""#,
        day,
    )
    .fetch_one(archive)
    .await?)
}

/// The partitions of `access.<table>`, by name; for the opener's tests.
///
/// # Errors
/// [`StoreError`].
#[cfg(feature = "testing")]
pub async fn partitions(owner: &PgPool, table: &str) -> Result<Vec<String>, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT c.relname::text AS "name!" FROM pg_inherits i
             JOIN pg_class c ON c.oid = i.inhrelid
             JOIN pg_class p ON p.oid = i.inhparent
             JOIN pg_namespace n ON n.oid = p.relnamespace
            WHERE n.nspname = 'access' AND p.relname = $1
            ORDER BY 1"#,
        table,
    )
    .fetch_all(owner)
    .await?)
}

/// Closes every ephemeral protocol day partition past its TTL (archive role): detached, moved
/// into `access_ephemeral` and dropped there (OP-73 m.7, OP-158 m.3 (w)). The TTL is the
/// database's, from its own clock; no caller can name a partition. Returns the closed names.
///
/// # Errors
/// [`StoreError`]. A partition that cannot be closed is left as it was and tried next time.
pub async fn close_days(archive: &PgPool) -> Result<Vec<String>, StoreError> {
    Ok(
        sqlx::query_scalar!(r#"SELECT access.close_ephemeral_days() AS "name!""#)
            .fetch_all(archive)
            .await?,
    )
}

/// What one table family did for one day.
#[derive(Debug)]
pub struct Opened {
    /// Days since the Unix epoch.
    pub day: i32,
    /// `auth_flows`, `oauth`, `dpop_replay`, `claim_ingest` or `login_throttle`.
    pub family: &'static str,
    /// Whether it is open now.
    pub result: Result<(), StoreError>,
}

/// Opens days `from..=from + ahead` of every ephemeral table family (archive role). Every
/// family and day is tried; a failure of one does not stop the others.
pub async fn open_days(archive: &PgPool, from: i32, ahead: i32) -> Vec<Opened> {
    let mut out = Vec::new();
    for offset in 0..=ahead.max(0) {
        let Some(day) = from.checked_add(offset) else {
            break;
        };
        let flows = crate::sessions::open_flow_day(archive, day).await.map(drop);
        out.push(Opened {
            day,
            family: "auth_flows",
            result: flows,
        });
        let oauth = crate::oauth::open_oauth_day(archive, day).await;
        out.push(Opened {
            day,
            family: "oauth",
            result: oauth,
        });
        let dpop = match u32::try_from(day) {
            Ok(d) => crate::dpop::open_dpop_replay_day(archive, d)
                .await
                .map(drop),
            Err(_) => Err(StoreError::Range),
        };
        out.push(Opened {
            day,
            family: "dpop_replay",
            result: dpop,
        });
        let ingest = match u32::try_from(day) {
            Ok(d) => crate::claims::open_claim_ingest_day(archive, d)
                .await
                .map(drop),
            Err(_) => Err(StoreError::Range),
        };
        out.push(Opened {
            day,
            family: "claim_ingest",
            result: ingest,
        });
        let throttle = open_throttle_day(archive, day).await.map(drop);
        out.push(Opened {
            day,
            family: "login_throttle",
            result: throttle,
        });
    }
    out
}
