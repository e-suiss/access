//! Token Status Lists in this process (OP-150 m.3 (a), (s), T24): the publisher signs the lists
//! of the domains led here at a short interval, and `GET /access/v1/status-lists/{list}` serves
//! the latest publication.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use access_authority_core::status::Publisher;
use access_authority_core::status::adapters::{PgLists, SignerSocket};
use access_authority_sequencer::ports::Clock as _;
use access_http::status::{Served, StatusLists, Unavailable};
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::scope::DomainId;

/// How often the publisher looks at the lists (PD). A revocation is signed at the next look; an
/// unchanged list only on its heartbeat.
pub(crate) const INTERVAL: Duration = Duration::from_secs(5);

/// The published lists in `access_app`.
pub(crate) struct PgStatusLists(pub(crate) Pool);

impl StatusLists for PgStatusLists {
    async fn latest(&self, domain: Digest, list_no: u64) -> Result<Option<Served>, Unavailable> {
        let scope = DomainId::from_bytes(domain.0);
        let Some(list) = access_store::status::list(&self.0, &scope, list_no)
            .await
            .map_err(|_| Unavailable)?
        else {
            return Ok(None);
        };
        let latest = access_store::status::latest(&self.0, &scope, &list.uri)
            .await
            .map_err(|_| Unavailable)?;
        Ok(latest.map(|p| Served {
            token: p.token,
            excerpt: p.excerpt,
            as_of: p.applied_pos,
            seq: p.seq,
        }))
    }
}

/// `GET /access/v1/status-lists/{list}` over the application pool.
pub(crate) fn routes(app: Pool) -> axum::Router {
    access_http::status::router(PgStatusLists(app))
}

/// Publishes the lists of the domains `led` names every [`INTERVAL`] until the task is
/// aborted; trusted time is read as the sequencer reads it.
pub(crate) async fn run<F>(led: F, pools: (Pool, Pool), signer: std::path::PathBuf)
where
    F: Fn() -> Vec<Digest> + Send,
{
    let (app, sequencer) = pools;
    let mut clock = access_authority_sequencer::adapters::SourcesClock::new(app.clone());
    let publisher = Publisher::new(PgLists { app, sequencer }, SignerSocket(signer));
    let mut every = tokio::time::interval(INTERVAL);
    loop {
        every.tick().await;
        let Ok(now) = clock.now().await else {
            tracing::warn!("no trusted time; status lists not published");
            continue;
        };
        let mut oldest: Option<u64> = None;
        for domain in led() {
            match publisher.publish_aged(domain, now).await {
                Ok((_, Some(iat))) => oldest = Some(oldest.map_or(iat, |o| o.min(iat))),
                Ok((_, None)) => {}
                Err(error) => tracing::warn!(%error, "status lists not published"),
            }
        }
        // §17.8.2, SI-7
        if let Some(iat) = oldest {
            access_telemetry::signals::STATUS_LIST_IAT_AGE
                .set_u64(now.saturating_sub(iat).checked_div(1_000).unwrap_or(0), []);
        }
    }
}

/// The running publisher; dropping it stops it.
pub(crate) struct Publishing(Option<tokio::task::JoinHandle<()>>);

impl Drop for Publishing {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

/// The publisher over the domains `domains` leads; without a signer it publishes nothing.
pub(crate) fn spawn(
    domains: &Arc<crate::ServerDomains>,
    app: &Pool,
    sequencer: &Pool,
    signer: Option<&PathBuf>,
) -> Publishing {
    let domains = Arc::clone(domains);
    Publishing(signer.cloned().map(|signer| {
        tokio::spawn(run(
            move || domains.led(),
            (app.clone(), sequencer.clone()),
            signer,
        ))
    }))
}

#[cfg(test)]
mod tests;
