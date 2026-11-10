//! The HR job in this process (OP-156 m.3 (q), IDP-35): every 5 minutes it states the HR
//! sources' record versions as their HR Claims through Claim Ingest of the domains this process
//! leads, and applies the start and end dates that came. Every node may run it: a date is
//! applied once, a record version's Claims are recorded once.

use std::sync::Arc;

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::vault::Vault;
use access_identity_admin::app::hr::{HrJob, INTERVAL};
use access_internal_api::claims::ClaimIngest;
use access_store::Pool;
use access_store::identity::RealmId;

/// The realm vaults of this process.
pub(crate) struct Vaults(pub(crate) crate::login::RealmKeks);

impl access_identity_admin::app::hr::Vaults for Vaults {
    fn vault(&self, realm: RealmId) -> Option<Vault> {
        self.0.vault(realm)
    }
}

/// Runs the HR job every [`INTERVAL`] until `stop` turns true.
pub(crate) async fn run<I: ClaimIngest>(
    (app, reader): (Pool, Pool),
    ingest: I,
    (vaults, ids): (Vaults, Arc<crate::ids::CellIds>),
    stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut stop = stop;
    loop {
        if let Some(key) = ids.key() {
            once(&app, &reader, &ingest, &vaults, &key).await;
        }
        let _ = tokio::time::timeout(INTERVAL, stop.changed()).await;
        if *stop.borrow() {
            return;
        }
    }
}

async fn once<I: ClaimIngest>(app: &Pool, reader: &Pool, ingest: &I, vaults: &Vaults, ids: &IdKey) {
    let Ok(now) = access_store::authority::server_time(app).await else {
        tracing::warn!(job = "hr", "HR job: no server time");
        return;
    };
    let job = HrJob {
        app,
        reader,
        ingest,
        vaults,
        ids,
    };
    if let Err(error) = job.run_once(now).await {
        tracing::warn!(error = %error.0, job = "hr", "HR job run failed");
    }
}
