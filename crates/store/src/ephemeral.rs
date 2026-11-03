//! Day partitions of the ephemeral protocol tables (OP-146 m.5 (f), m.7 (d), m.10 (g)): login
//! flows, authorization requests and codes, client assertion and DPoP replay keys, and login
//! counters. The archive role opens each day ahead; a day that is not open is a cache outage
//! for DPoP and lands in the default partition elsewhere. Closing old days is the archive
//! job's and is not here (OP-73).

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

/// What one table family did for one day.
#[derive(Debug)]
pub struct Opened {
    /// Days since the Unix epoch.
    pub day: i32,
    /// `auth_flows`, `oauth`, `dpop_replay` or `login_throttle`.
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
        let throttle = open_throttle_day(archive, day).await.map(drop);
        out.push(Opened {
            day,
            family: "login_throttle",
            result: throttle,
        });
    }
    out
}
