//! The privacy jobs (OP-153 m.3 (aa), (bb), (dd); TN-51, TN-77, TN-78, OP-74, OP-147), run
//! through the jobs table so one node of the cell does each per day (OP-129 m.2):
//!
//! - `retention.daily`: in every live realm, seal identifiers still written in plaintext, write
//!   the tombstones whose cancellation window ran out, and destroy the keys of tombstoned
//!   accounts whose delay ran out and that no hold covers. It runs daily, far under the KVKK
//!   six-month ceiling of the periodic destruction.
//! - `inactivity.daily`: the inactivity sweep, on its own clock and its own job, never the
//!   destruction's (TN-78).
//!
//! A realm whose vault keys the token refuses is skipped and its job retried; nothing personal
//! is touched without them (TI-9).

use std::time::Duration;

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::privacy::{
    InactivityPolicy, destroy_due, inactivity_sweep, seal_plaintext, tombstone_due,
};
use access_identity_account::app::{Actor, Realm};
use access_store::Pool;
use access_store::StoreError;
use access_store::jobs::{claim_kind, complete, schedule};
use access_store::tenancy::{RealmRoute, routes};

use crate::login::RealmKeks;

/// The destruction job kind.
pub(crate) const RETENTION: &str = "retention.daily";

/// The inactivity sweep's job kind.
pub(crate) const INACTIVITY: &str = "inactivity.daily";

/// How often a node schedules and claims (PD).
pub(crate) const INTERVAL: Duration = Duration::from_mins(10);

/// How long a claim holds (PD).
const LEASE: Duration = Duration::from_mins(15);

/// Plaintext identifiers sealed per realm and pass (PD).
const SEAL_BATCH: i64 = 1_000;

const DAY_MS: u64 = 86_400_000;

/// Who the jobs are in the account audit log (OP-10).
const JOB: Actor<'static> = Actor {
    actor: "access-retention",
    correlation: "retention",
};

/// What one pass over the realms did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pass {
    /// Identifiers sealed.
    pub(crate) sealed: u64,
    /// Tombstones written.
    pub(crate) tombstoned: u32,
    /// Accounts whose keys were destroyed.
    pub(crate) destroyed: u32,
    /// Accounts a hold kept.
    pub(crate) kept: u32,
    /// Accounts deactivated for inactivity.
    pub(crate) deactivated: u32,
    /// Accounts told of their coming deactivation.
    pub(crate) notified: u32,
    /// Realms that failed and are tried again.
    pub(crate) failed: u32,
}

/// The realm's account tables with its vault, and its scope with the KEK.
fn realm_parts(
    app: &Pool,
    keks: &RealmKeks,
    route: &RealmRoute,
) -> Option<(PgAccounts, access_identity_account::app::vault::Vault)> {
    let vault = keks.vault(route.realm)?;
    Some((PgAccounts::sealed(app.clone(), vault.clone()), vault))
}

/// One destruction pass in one realm.
///
/// # Errors
/// [`access_identity_account::AccountError`].
pub(crate) async fn retain_realm(
    app: &Pool,
    keks: &RealmKeks,
    ids: &access_crypto::opaque_id::IdKey,
    route: &RealmRoute,
    out: &mut Pass,
) -> Result<(), access_identity_account::AccountError> {
    let (db, vault) =
        realm_parts(app, keks, route).ok_or(access_identity_account::AccountError::Vault)?;
    let realm = Realm {
        tenant: route.tenant,
        realm: route.realm,
        kek: &*vault.kek,
        ids,
    };
    out.sealed = out
        .sealed
        .saturating_add(seal_plaintext(&db, &realm, SEAL_BATCH).await?);
    out.tombstoned = out
        .tombstoned
        .saturating_add(tombstone_due(&db, &realm, &JOB).await?);
    let d = destroy_due(&db, &realm, &JOB).await?;
    // OP-42
    crate::reshred::journal(route, &d.subjects).await;
    out.destroyed = out.destroyed.saturating_add(d.destroyed);
    out.kept = out.kept.saturating_add(d.kept);
    Ok(())
}

/// One inactivity sweep in one realm, under the consumer policy until the realm's own
/// `idp.realm.inactivity_policy` is set (OP-153 m.3 (dd)).
///
/// # Errors
/// [`access_identity_account::AccountError`].
pub(crate) async fn sweep_realm(
    app: &Pool,
    keks: &RealmKeks,
    ids: &access_crypto::opaque_id::IdKey,
    route: &RealmRoute,
    out: &mut Pass,
) -> Result<(), access_identity_account::AccountError> {
    let (db, vault) =
        realm_parts(app, keks, route).ok_or(access_identity_account::AccountError::Vault)?;
    let realm = Realm {
        tenant: route.tenant,
        realm: route.realm,
        kek: &*vault.kek,
        ids,
    };
    // TN-51, OP-157 m.3 (h)
    let mut t = access_store::identity::TenantTx::begin(app, route.tenant, route.realm).await?;
    let exempt: Vec<[u8; 16]> = t
        .breakglass_accounts()
        .await?
        .into_iter()
        .map(|a| a.subject)
        .collect();
    // OP-157 m.3 (h), §12.3.8 (5)
    access_identity_account::app::breakglass::drill_check(
        &mut t,
        (&*vault.kek, ids),
        &access_identity_account::adapters::system::SystemEntropy,
        &access_identity_account::adapters::system::SystemClock,
        &route.issuer,
        access_identity_account::ports::Clock::now_ms(
            &access_identity_account::adapters::system::SystemClock,
        ),
    )
    .await
    .map_err(|_| access_identity_account::AccountError::Vault)?;
    t.commit().await?;
    let s = inactivity_sweep(&db, &realm, InactivityPolicy::CONSUMER, &exempt, &JOB).await?;
    out.deactivated = out.deactivated.saturating_add(s.deactivated);
    out.notified = out.notified.saturating_add(s.notified);
    Ok(())
}

/// Schedules today's job of `kind` and runs the ones this node claims over every live realm;
/// a job completes once every realm passed.
///
/// # Errors
/// [`StoreError`] when the jobs table or the realm list cannot be read.
pub(crate) async fn tick(
    (app, router): (&Pool, &Pool),
    keks: &RealmKeks,
    ids: &access_crypto::opaque_id::IdKey,
    (kind, worker): (&'static str, &str),
    now_ms: u64,
) -> Result<Pass, StoreError> {
    let today = now_ms / DAY_MS;
    schedule(
        app,
        kind,
        &today.to_string(),
        &format!("{kind}:{today}"),
        Duration::ZERO,
    )
    .await?;
    let mut out = Pass::default();
    for job in claim_kind(app, worker, kind, 2, LEASE).await? {
        let mut done = true;
        for route in routes(router).await? {
            let step = if kind == INACTIVITY {
                sweep_realm(app, keks, ids, &route, &mut out).await
            } else {
                retain_realm(app, keks, ids, &route, &mut out).await
            };
            if let Err(error) = step {
                done = false;
                out.failed = out.failed.saturating_add(1);
                tracing::warn!(%error, job = kind, "realm privacy job failed; retried");
            }
        }
        if done && complete(app, job.id, worker).await? {
            tracing::info!(
                event = "privacy.job.completed",
                job = kind,
                sealed = out.sealed,
                tombstoned = out.tombstoned,
                destroyed = out.destroyed,
                kept = out.kept,
                deactivated = out.deactivated,
                "privacy job completed (OP-153 m.3 (bb), (dd))"
            );
        }
    }
    Ok(out)
}

/// Ticks both jobs every [`INTERVAL`] until the task is aborted.
pub(crate) async fn run(
    app: Pool,
    router: Pool,
    keks: RealmKeks,
    ids: std::sync::Arc<crate::ids::CellIds>,
    worker: String,
) {
    let mut every = tokio::time::interval(INTERVAL);
    loop {
        every.tick().await;
        let Some(key) = ids.key() else {
            tracing::warn!("cell id key unavailable; privacy jobs wait");
            continue;
        };
        let Some(now) = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
        else {
            continue;
        };
        for kind in [RETENTION, INACTIVITY] {
            if let Err(error) = tick((&app, &router), &keks, &key, (kind, &worker), now).await {
                tracing::warn!(%error, job = kind, "privacy job not run");
            }
        }
    }
}
