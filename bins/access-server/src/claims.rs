//! The environment issuer's courier in this process (CMP-8, §10.1.7, OP-150 L2): identity events'
//! Claim orders, signed by each environment's Claim issuer key in the identity signer and handed to
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
    scim: tokio::task::JoinHandle<()>,
    hr: tokio::task::JoinHandle<()>,
    administration: tokio::task::JoinHandle<()>,
    renewing: tokio::task::JoinHandle<()>,
}

/// How often the administration courier looks for lines to renew or end (OP-159 m.47 (f), PD).
pub(crate) const ADMINISTRATION_INTERVAL: Duration = Duration::from_secs(10);

/// The environment issuer's courier of this process.
pub(crate) type ClaimsCourier<L> =
    Courier<SignerKeys, Ingest<Arc<L>, PgSubmissions, Trusted>, SystemClock>;

/// Starts the lease renewal `renew` of `domains` and the courier over them, reading the identity
/// outbox with the event pools' reader; both stop together. The courier is also returned, for
/// the approvals that need their Claim at once (SI-5, OP-150 L6), and the administration
/// courier, for the removals and suspensions that end their Claims at once (OP-159 m.47 (f)).
pub(crate) fn start<L, R, F>(
    (signer, administration_signer): (SignerKeys, SignerKeys),
    pools: &EventPools,
    (domains, hr): (Arc<L>, (crate::hr::Vaults, Arc<crate::ids::CellIds>)),
    renew: R,
) -> (
    Running,
    Arc<ClaimsCourier<L>>,
    Arc<dyn crate::admin::tenant::EndAdministration>,
)
where
    L: Ledger + 'static,
    R: FnOnce(Arc<L>) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    let (app, reader) = (pools.app.clone(), pools.reader.clone());
    let renewing = tokio::spawn(renew(Arc::clone(&domains)));
    let clock = access_authority_sequencer::adapters::SourcesClock::new(app.clone());
    // OP-155 m.3 (g), INV-16
    let scim = access_identity_scim::app::claims::Courier {
        app: app.clone(),
        reader: reader.clone(),
        ingest: Ingest::new(
            Arc::clone(&domains),
            PgSubmissions(app.clone()),
            Trusted(tokio::sync::Mutex::new(
                access_authority_sequencer::adapters::SourcesClock::new(app.clone()),
            )),
        ),
        clock: access_identity_scim::ports::SystemClock,
    };
    // OP-156 m.3 (q), INV-16
    let hr_ingest = Ingest::new(
        Arc::clone(&domains),
        PgSubmissions(app.clone()),
        Trusted(tokio::sync::Mutex::new(
            access_authority_sequencer::adapters::SourcesClock::new(app.clone()),
        )),
    );
    let hr_pools = (app.clone(), reader.clone());
    // OP-159 m.47 (f)
    let administration = Arc::new(
        access_identity_account::app::administration::Administration {
            app: app.clone(),
            signer: administration_signer,
            ingest: Ingest::new(
                Arc::clone(&domains),
                PgSubmissions(app.clone()),
                Trusted(tokio::sync::Mutex::new(
                    access_authority_sequencer::adapters::SourcesClock::new(app.clone()),
                )),
            ),
            clock: SystemClock,
        },
    );
    let ender: Arc<dyn crate::admin::tenant::EndAdministration> = administration.clone();
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
    let scim_stopped = stopped.clone();
    let hr_stopped = stopped.clone();
    let administration_stopped = stopped.clone();
    let task = tokio::spawn(async move { running.run(INTERVAL, &stopped).await });
    let scim = tokio::spawn(async move { scim.run(INTERVAL, &scim_stopped).await });
    let hr = tokio::spawn(crate::hr::run(hr_pools, hr_ingest, hr, hr_stopped));
    let administration = tokio::spawn(async move {
        administration
            .run(ADMINISTRATION_INTERVAL, &administration_stopped)
            .await;
    });
    (
        Running {
            stop,
            task,
            scim,
            hr,
            administration,
            renewing,
        },
        courier,
        ender,
    )
}

impl Running {
    /// Finishes the step in flight and stops, then stops the lease renewal.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
        let _ = self.scim.await;
        let _ = self.hr.await;
        let _ = self.administration.await;
        self.renewing.abort();
    }
}
