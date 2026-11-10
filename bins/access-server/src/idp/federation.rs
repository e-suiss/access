//! The chain refresher of chain-constrained issuers (IDI-12, OP-155 m.3 (j)): every round
//! re-resolves, through the guarded outbound client, the chain of each issuer each realm's
//! governing domain tracks, well inside the one-hour freshness window the ingest gate holds them
//! to. A round that cannot run leaves the state to age: the gate then cuts, never admits.

use std::time::Duration;

use access_identity_oauth::adapters::cimd::HttpClientDocuments;
use access_identity_oauth::adapters::oidf::refresh_issuers;
use access_identity_oauth::adapters::outbound::Outbound;
use access_store::Pool;
use access_store::identity::TenantTx;

/// How often the chains are re-resolved (PD: a quarter of the freshness window).
pub(crate) const REFRESH_EVERY: Duration = Duration::from_secs(900);

/// Runs the refresher until the task is aborted.
pub(crate) async fn refresh_run(app: Pool, router: Pool, outbound: Outbound) {
    let documents = HttpClientDocuments::new(outbound);
    let mut every = tokio::time::interval(REFRESH_EVERY);
    loop {
        every.tick().await;
        let Some(now) = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
        else {
            continue;
        };
        let Ok(realms) = access_store::tenancy::routes(&router).await else {
            tracing::warn!("federation chain round not run");
            continue;
        };
        for r in realms {
            let Ok(mut t) = TenantTx::begin(&app, r.tenant, r.realm).await else {
                continue;
            };
            let governing = access_store::idp::governance(&mut t).await.ok().flatten();
            let _ = t.commit().await;
            let Some(g) = governing else {
                continue;
            };
            if let Err(e) = refresh_issuers(&app, &documents, &g.domain, now).await {
                tracing::warn!(error = %e, "federation chain round failed for a realm");
            }
        }
    }
}
