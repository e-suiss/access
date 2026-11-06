//! The realm issuer's courier in this process (CMP-8, §10.1.7, OP-150 L2): identity events'
//! Claim orders, signed by each realm's Claim issuer key in the identity signer and handed to
//! Claim Ingest of the domains this process leads, through `internal-api` (OP-62).

use std::sync::Arc;
use std::time::Duration;

use access_authority_ingest::app::Ingest;
use access_authority_ingest::ports::Ledger;
use access_identity_account::adapters::system::SystemClock;
use access_identity_account::app::claims::Courier;
use access_identity_oauth::adapters::SignerKeys;

use crate::events::EventPools;
use crate::ingest::{PgSubmissions, Trusted};

/// How often the courier looks for new orders (PD).
pub(crate) const INTERVAL: Duration = Duration::from_secs(2);

/// The running courier, beside the task that renews the leases of the domains it submits to.
pub(crate) struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    renewing: tokio::task::JoinHandle<()>,
}

/// The realm issuer's courier of this process.
pub(crate) type ClaimsCourier<L> =
    Courier<SignerKeys, Ingest<Arc<L>, PgSubmissions, Trusted>, SystemClock>;

/// Starts the lease renewal `renew` of `domains` and the courier over them, reading the identity
/// outbox with the event pools' reader; both stop together. The courier is also returned, for
/// the approvals that need their Claim at once (SI-5, OP-150 L6).
pub(crate) fn start<L, R, F>(
    signer: SignerKeys,
    pools: &EventPools,
    domains: Arc<L>,
    renew: R,
) -> (Running, Arc<ClaimsCourier<L>>)
where
    L: Ledger + 'static,
    R: FnOnce(Arc<L>) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    let (app, reader) = (pools.app.clone(), pools.reader.clone());
    let renewing = tokio::spawn(renew(Arc::clone(&domains)));
    let clock = access_authority_sequencer::adapters::SourcesClock::new(app.clone());
    let courier = Arc::new(Courier {
        app: app.clone(),
        reader,
        signer,
        ingest: Ingest::new(
            domains,
            PgSubmissions(app),
            Trusted(tokio::sync::Mutex::new(clock)),
        ),
        clock: SystemClock,
    });
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let running = Arc::clone(&courier);
    let task = tokio::spawn(async move { running.run(INTERVAL, &stopped).await });
    (
        Running {
            stop,
            task,
            renewing,
        },
        courier,
    )
}

impl Running {
    /// Finishes the step in flight and stops, then stops the lease renewal.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
        self.renewing.abort();
    }
}
