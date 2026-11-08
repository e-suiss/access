//! The day-partition opener of the ephemeral protocol tables (OP-146 m.5 (f), m.7 (d)), run
//! through the jobs table (OP-129 m.2) so that one node of the cell does it per day: each
//! node schedules today's job, one claims it and opens today and the days ahead as the
//! archive role, and this month's and next month's identity audit partitions (OP-13b, OP-134
//! m.2). Closing old days is not done here (OP-73).
//!
//! The same tick releases the management API's `Idempotency-Key` answers past their 24 hours
//! (TN-126, OP-151 m.3 (c)): the answer is cleared and the key released in place, never deleted.
//!
//! The daily tenant analytics (IDP-36, OP-151 m.3 (n)) run the same way: one node aggregates
//! yesterday for every live realm, in a transaction scoped to that realm, and sets the
//! process-wide SL2 false-positive ratio gauge (OP-151 m.3 (o)). Nothing reads either back to
//! decide anything (TI-18).

use std::time::Duration;

use access_identity_events::app::emit;
use access_identity_events::domain::catalog::IdentityEvent;
use access_identity_risk::app::analytics::aggregate;
use access_store::Pool;
use access_store::StoreError;
use access_store::audit::open_month;
use access_store::ephemeral::open_days;
use access_store::identity::TenantTx;
use access_store::jobs::{claim_kind, complete, schedule};
use access_store::tenancy::routes;

/// The analytics job kind.
pub(crate) const ANALYTICS: &str = "analytics.daily";

/// Days the false-positive ratio looks back over (PD).
const FP_WINDOW_DAYS: u32 = 30;

/// The job kind.
pub(crate) const KIND: &str = "partitions.open";

/// Days opened ahead of today (PD).
pub(crate) const AHEAD_DAYS: i32 = 3;

/// How often a node schedules and claims (PD).
pub(crate) const INTERVAL: Duration = Duration::from_secs(600);

/// How long a claim holds (PD).
const LEASE: Duration = Duration::from_secs(300);

const DAY_MS: u64 = 86_400_000;

/// What one [`tick`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tick {
    /// Jobs completed.
    pub(crate) completed: u32,
    /// Partition openings that failed.
    pub(crate) failed: u32,
}

/// The calendar month of Unix day `day` and the month after it, as (year, month).
fn months(day: i32) -> Option<[(i32, u32); 2]> {
    let at = time::OffsetDateTime::from_unix_timestamp(i64::from(day).checked_mul(86_400)?).ok()?;
    let (year, month) = (at.year(), u32::from(u8::from(at.month())));
    let next = if month == 12 {
        (year.checked_add(1)?, 1)
    } else {
        (year, month.checked_add(1)?)
    };
    Some([(year, month), next])
}

/// Opens the identity audit partitions of `day`'s month and the next one (OP-13b). Rows of a
/// month written before its partition existed sit in the default partition, which then refuses
/// that month's partition; such a month is only tried and stays in the default, so the job
/// still completes once the next month is open.
async fn open_audit_months(archive: &Pool, day: i32) -> (bool, u32) {
    let Some([this, next]) = months(day) else {
        return (false, 1);
    };
    let mut failed = 0_u32;
    if let Err(error) = open_month(archive, this.0, this.1).await {
        failed = failed.saturating_add(1);
        tracing::warn!(%error, year = this.0, month = this.1, "audit month not opened; its rows stay in the default partition");
    }
    let done = match open_month(archive, next.0, next.1).await {
        Ok(_) => true,
        Err(error) => {
            failed = failed.saturating_add(1);
            tracing::warn!(%error, year = next.0, month = next.1, "next audit month not opened");
            false
        }
    };
    (done, failed)
}

/// Schedules today's job and runs the ones this node claims. A job completes once every day
/// after its own is open; today may already hold rows in a default partition and is tried
/// only.
///
/// # Errors
/// [`StoreError`] when the jobs table cannot be read or written.
pub(crate) async fn tick(
    app: &Pool,
    archive: &Pool,
    worker: &str,
    now_ms: u64,
) -> Result<Tick, StoreError> {
    let today = i32::try_from(now_ms / DAY_MS).map_err(|_| StoreError::Range)?;
    schedule(
        app,
        KIND,
        &today.to_string(),
        &format!("{KIND}:{today}"),
        Duration::ZERO,
    )
    .await?;
    let mut out = Tick::default();
    for job in claim_kind(app, worker, KIND, 8, LEASE).await? {
        let Ok(day) = job.subject.parse::<i32>() else {
            tracing::warn!(subject = %job.subject, "partition job with an unreadable day");
            continue;
        };
        let mut done = true;
        for o in open_days(archive, day, AHEAD_DAYS).await {
            if let Err(error) = o.result {
                out.failed = out.failed.saturating_add(1);
                tracing::warn!(%error, family = o.family, day = o.day, "day partition not opened");
                done &= o.day == day;
            }
        }
        // OP-13b, OP-134 m.2
        let (months_open, failed) = open_audit_months(archive, day).await;
        out.failed = out.failed.saturating_add(failed);
        done &= months_open;
        if done && complete(app, job.id, worker).await? {
            out.completed = out.completed.saturating_add(1);
        }
    }
    Ok(out)
}

/// One tick at the wall clock, its failure logged: today's partitions are opened before the
/// couriers and the listener start, so the first Claim or flow of a fresh deployment finds its
/// day (OP-146 m.5 (f)).
pub(crate) async fn open_now(app: &Pool, archive: &Pool, worker: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok());
    let Some(now) = now else {
        tracing::error!("system clock before the Unix epoch; partitions not opened");
        return;
    };
    if let Err(error) = tick(app, archive, worker, now).await {
        tracing::warn!(%error, "partition job failed");
    }
}

/// What one [`analytics_tick`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AnalyticsTick {
    /// Realms aggregated.
    pub(crate) realms: u32,
    /// Realms whose aggregation failed (retried with the job).
    pub(crate) failed: u32,
    /// Surge alerts raised.
    pub(crate) surges: u32,
}

/// Schedules yesterday's analytics and runs the jobs this node claims: every live realm's row of
/// the day, then the FP ratio gauge over the last [`FP_WINDOW_DAYS`] days. A job completes once
/// every realm is aggregated; a realm that failed is tried again on the next claim.
///
/// # Errors
/// [`StoreError`] when the jobs table or the realm list cannot be read.
pub(crate) async fn analytics_tick(
    app: &Pool,
    router: &Pool,
    worker: &str,
    now_ms: u64,
) -> Result<AnalyticsTick, StoreError> {
    let today = u32::try_from(now_ms / DAY_MS).map_err(|_| StoreError::Range)?;
    let yesterday = today.checked_sub(1).ok_or(StoreError::Range)?;
    schedule(
        app,
        ANALYTICS,
        &yesterday.to_string(),
        &format!("{ANALYTICS}:{yesterday}"),
        Duration::ZERO,
    )
    .await?;
    let mut out = AnalyticsTick::default();
    for job in claim_kind(app, worker, ANALYTICS, 4, LEASE).await? {
        let Ok(day) = job.subject.parse::<u32>() else {
            tracing::warn!(subject = %job.subject, "analytics job with an unreadable day");
            continue;
        };
        let mut done = true;
        let (mut fp, mut reviews, mut legacy) = (0_u64, 0_u64, 0_u64);
        for realm in routes(router).await? {
            let step = async {
                let mut tx = TenantTx::begin(app, realm.tenant, realm.realm).await?;
                let a = aggregate(&mut tx, day).await.map_err(|e| e.to_string());
                // OP-151 m.3 (i), IDP-36
                if let Ok(Some(s)) = a.as_ref().map(|a| a.surge) {
                    let id = access_crypto::random::bytes::<32>().map_err(|_| StoreError::Range)?;
                    let event = IdentityEvent::login_failed_surge(
                        id,
                        realm.realm.as_bytes(),
                        u32::try_from(s.observed).unwrap_or(u32::MAX),
                        DAY_MS,
                        now_ms,
                    );
                    emit(&mut tx, &event).await?;
                }
                let window = tx
                    .analytics_days(day.saturating_sub(FP_WINDOW_DAYS.saturating_sub(1)), day)
                    .await?;
                tx.commit().await?;
                Ok::<_, StoreError>((a, window))
            };
            match step.await {
                Ok((Ok(a), window)) => {
                    out.realms = out.realms.saturating_add(1);
                    legacy = legacy.saturating_add(a.day.legacy_password_accounts);
                    out.surges = out.surges.saturating_add(u32::from(a.surge.is_some()));
                    for d in &window {
                        fp = fp.saturating_add(d.risk_false_positives);
                        reviews = reviews.saturating_add(d.risk_reviews);
                    }
                }
                Ok((Err(error), _)) => {
                    done = false;
                    out.failed = out.failed.saturating_add(1);
                    tracing::warn!(%error, "realm analytics not aggregated");
                }
                Err(error) => {
                    done = false;
                    out.failed = out.failed.saturating_add(1);
                    tracing::warn!(%error, "realm analytics not aggregated");
                }
            }
        }
        // OP-151 m.3 (o), OP-47
        let ratio = access_identity_risk::domain::analytics::ppm(fp, reviews).unwrap_or(0);
        access_telemetry::signals::RISK_FP_RATIO.set_u64(ratio, []);
        // TN-85, CR-37, OP-47
        if done {
            access_telemetry::signals::LEGACY_HASH_ACCOUNTS.set_u64(legacy, []);
        }
        if done && complete(app, job.id, worker).await? {
            tracing::info!(
                event = "analytics.aggregated",
                realms = out.realms,
                "tenant analytics aggregated (IDP-36)"
            );
        }
    }
    Ok(out)
}

fn wall_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

/// Most idempotency answers released per tick (PD).
const RELEASE_BATCH: u32 = 1_000;

/// Releases the `Idempotency-Key` answers past their retention (TN-126, OP-73): each such key's
/// answer is cleared and its state set to released, in batches until none is left.
pub(crate) async fn release_answers(app: &Pool, now_ms: u64) -> Result<u64, StoreError> {
    let mut total = 0_u64;
    loop {
        let n = access_store::api_idempotency::release_expired(app, now_ms, RELEASE_BATCH).await?;
        total = total.saturating_add(n);
        if n < u64::from(RELEASE_BATCH) {
            return Ok(total);
        }
    }
}

/// Ticks every [`INTERVAL`] until the task is aborted.
pub(crate) async fn run(app: Pool, archive: Pool, router: Pool, worker: String) {
    let mut every = tokio::time::interval(INTERVAL);
    loop {
        every.tick().await;
        open_now(&app, &archive, &worker).await;
        let Some(now) = wall_ms() else {
            continue;
        };
        if let Err(error) = analytics_tick(&app, &router, &worker, now).await {
            tracing::warn!(%error, "analytics job failed");
        }
        // TN-126, OP-151 m.3 (c)
        if let Err(error) = release_answers(&app, now).await {
            tracing::warn!(%error, "idempotency answers not released");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_store::ephemeral::partitions;
    use access_store::testing::fresh;

    use super::*;

    // IDP-36, OP-151 m.3 (n), OP-129 m.2
    #[tokio::test]
    async fn analytics_aggregate_yesterday_once() {
        use access_store::authority::{LogRecord, create_domain};
        use access_store::scope::DomainId;
        use access_store::tenancy::{create_realm, create_tenant, set_issuer};

        let db = fresh().await.unwrap();
        let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
        let d = DomainId::from_bytes([0x71; 32]);
        let g = LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 1,
            leaf_hash: [0x71; 32],
            envelope: vec![0xa0],
        };
        create_domain(&db.sequencer, &d, *tenant.as_bytes(), &g, &[])
            .await
            .unwrap();
        let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
        let realm = create_realm(&mut tx, &d, "jobs-analytics", "pool-default")
            .await
            .unwrap();
        tx.enter_realm(realm).await.unwrap();
        set_issuer(&mut tx, "https://jobs-analytics.example")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let now = 20_000 * DAY_MS + 5;
        let first = analytics_tick(&db.app, &db.router, "node-a", now)
            .await
            .unwrap();
        assert_eq!((first.realms, first.failed), (1, 0));
        let again = analytics_tick(&db.app, &db.router, "node-b", now)
            .await
            .unwrap();
        assert_eq!(again, AnalyticsTick::default());
        let mut tx = TenantTx::begin(&db.app, tenant, realm).await.unwrap();
        let rows = tx.analytics_days(19_999, 19_999).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].flows_started, 0);
    }

    // OP-146 m.5 (f), m.7 (d), OP-129 m.2
    #[tokio::test]
    async fn the_opener_opens_days_ahead_once() {
        let db = fresh().await.unwrap();
        let now = 20_000 * DAY_MS + 5;
        let first = tick(&db.app, &db.archive, "node-a", now).await.unwrap();
        assert_eq!(
            first,
            Tick {
                completed: 1,
                failed: 0
            }
        );
        let again = tick(&db.app, &db.archive, "node-b", now).await.unwrap();
        assert_eq!(again, Tick::default());
        let days = |prefix: &str| -> Vec<String> {
            (20_000..=20_003).map(|d| format!("{prefix}{d}")).collect()
        };
        for (table, prefix) in [
            ("auth_flows", "auth_flows_d"),
            ("oauth_requests", "oauth_requests_d"),
            ("oauth_codes", "oauth_codes_d"),
            ("client_assertion_replay", "client_assertion_replay_d"),
            ("dpop_replay", "dpop_replay_d"),
            ("claim_ingest", "claim_ingest_d"),
        ] {
            let open = partitions(&db.owner, table).await.unwrap();
            for name in days(prefix) {
                assert!(open.contains(&name), "{table}: {open:?}");
            }
        }
        let throttle = partitions(&db.owner, "login_throttle").await.unwrap();
        for name in ["login_throttle_20241004", "login_throttle_20241007"] {
            assert!(throttle.iter().any(|t| t == name), "{throttle:?}");
        }
        // D-1, OP-13b, OP-134 m.2
        let audit = partitions(&db.owner, "identity_audit").await.unwrap();
        for name in ["identity_audit_202410", "identity_audit_202411"] {
            assert!(audit.iter().any(|t| t == name), "{audit:?}");
        }
    }

    // D-1, OP-13b
    #[test]
    fn the_months_of_a_day() {
        assert_eq!(months(20_000), Some([(2024, 10), (2024, 11)]));
        assert_eq!(months(20_088), Some([(2024, 12), (2025, 1)]));
    }

    // D-1, OP-13b, OP-73
    #[tokio::test]
    async fn a_month_already_in_the_default_partition_opens_the_next() {
        use access_store::audit::AuditEvent;
        use access_store::identity::RealmId;
        let db = fresh().await.unwrap();
        let mut t = TenantTx::begin(
            &db.app,
            access_store::identity::TenantId::from_bytes([0x41; 16]),
            RealmId::from_bytes([0x42; 16]),
        )
        .await
        .unwrap();
        t.audit(&AuditEvent {
            event_type: "session.revoked",
            actor: "adm_1",
            target: "usr_1",
            correlation: "req_1",
        })
        .await
        .unwrap();
        t.commit().await.unwrap();
        let now = wall_ms().unwrap();
        let day = i32::try_from(now / DAY_MS).unwrap();
        let [this, next] = months(day).unwrap();
        let first = tick(&db.app, &db.archive, "node-a", now).await.unwrap();
        assert_eq!(first.completed, 1);
        assert_eq!(first.failed, 1);
        let audit = partitions(&db.owner, "identity_audit").await.unwrap();
        let name = |(y, m): (i32, u32)| format!("identity_audit_{y:04}{m:02}");
        assert!(!audit.contains(&name(this)), "{audit:?}");
        assert!(audit.contains(&name(next)), "{audit:?}");
    }

    // D-4, TN-126, OP-151 m.3 (c), OP-73
    #[tokio::test]
    async fn expired_idempotency_answers_are_released() {
        use access_store::api_idempotency::{Begun, begin, finish};
        let db = fresh().await.unwrap();
        let (old, live, req) = ([1; 32], [2; 32], [9; 32]);
        assert_eq!(
            begin(&db.app, &old, &req, 1_000, 10, 100).await.unwrap(),
            Begun::Run
        );
        finish(&db.app, &old, &req, Some(b"old")).await.unwrap();
        assert_eq!(
            begin(&db.app, &live, &req, 1_000, 10, 10_000)
                .await
                .unwrap(),
            Begun::Run
        );
        finish(&db.app, &live, &req, Some(b"live")).await.unwrap();
        assert_eq!(release_answers(&db.app, 5_000).await.unwrap(), 1);
        assert_eq!(release_answers(&db.app, 5_000).await.unwrap(), 0);
        assert_eq!(
            begin(&db.app, &live, &req, 5_000, 10, 10_000)
                .await
                .unwrap(),
            Begun::Replay(b"live".to_vec())
        );
    }
}
