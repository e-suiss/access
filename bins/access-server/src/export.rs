//! The export pass outside the request path (OP-156 m.3 (s), OP-41, X22): every
//! [`INTERVAL`] one node claims the slot through the jobs table (OP-129 m.2) and sends every
//! live export sink of every realm the audit rows it has not accepted yet. A sink that refuses
//! keeps its cursor; the record is never touched.

use std::time::Duration;

use access_identity_export::adapters::OutboundWire;
use access_identity_export::app::{Outcome, Pass};
use access_identity_export::ports::{RealmKek, Wire};
use access_identity_oauth::adapters::outbound::Outbound;
use access_store::Pool;
use access_store::StoreError;
use access_store::jobs::{claim_kind, complete, schedule};
use access_store::tenancy::routes;

/// The pass's job kind.
pub(crate) const KIND: &str = "export";

/// How often a node schedules and claims a pass (PD).
pub(crate) const INTERVAL: Duration = Duration::from_secs(10);

const LEASE: Duration = Duration::from_mins(5);

fn now_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

/// Schedules this slot's pass and runs it over every live realm when this node claims it.
///
/// # Errors
/// [`StoreError`] when the jobs table or the realm list cannot be read.
pub(crate) async fn tick<W: Wire, K: RealmKek>(
    (app, router): (&Pool, &Pool),
    (wire, keys): (&W, &K),
    worker: &str,
    now_ms: u64,
) -> Result<Outcome, StoreError> {
    let every = u64::try_from(INTERVAL.as_millis()).unwrap_or(10_000);
    let slot = now_ms.checked_div(every).unwrap_or(0);
    schedule(
        app,
        KIND,
        &slot.to_string(),
        &format!("{KIND}:{slot}"),
        Duration::ZERO,
    )
    .await?;
    let pass = Pass { app, wire, keys };
    let mut out = Outcome::default();
    for job in claim_kind(app, worker, KIND, 2, LEASE).await? {
        let mut done = true;
        for route in routes(router).await? {
            match pass.realm((route.tenant, route.realm), now_ms).await {
                Ok(o) => {
                    out.sent = out.sent.saturating_add(o.sent);
                    out.batches = out.batches.saturating_add(o.batches);
                    out.refused = out.refused.saturating_add(o.refused);
                    out.notified = out.notified.saturating_add(o.notified);
                }
                Err(error) => {
                    done = false;
                    tracing::warn!(%error, job = KIND, "export pass failed; retried");
                }
            }
        }
        if done {
            complete(app, job.id, worker).await?;
        }
    }
    Ok(out)
}

/// Runs the pass every [`INTERVAL`] until aborted.
pub(crate) async fn run<K: RealmKek>(
    (app, router): (Pool, Pool),
    outbound: Outbound,
    keys: K,
    worker: String,
) {
    let wire = OutboundWire(outbound);
    let mut passing = tokio::time::interval(INTERVAL);
    loop {
        passing.tick().await;
        let Some(now) = now_ms() else { continue };
        if let Err(error) = tick((&app, &router), (&wire, &keys), &worker, now).await {
            tracing::warn!(%error, job = KIND, "export pass not run");
        }
    }
}
