//! Event delivery of the identity plane in this process (OP-149 m.4, m.7, m.17): the fan-out
//! from the identity and authority outboxes, the push courier over the SSRF-guarded client,
//! and the realms' SSF transmitter. Webhook secrets are sealed under the realm KEKs the hosted
//! login opens.

use std::sync::Arc;

use access_identity_account::notify::delivery::Backoff;
use access_identity_events::adapters::{KekSealer, OutboundTransport};
use access_identity_events::app::Db;
use access_identity_events::app::courier::Courier;
use access_identity_events::app::fanout::Fanout;
use access_identity_events::app::ssf::Transmitter;
use access_identity_events::app::streams::Streams;
use access_identity_events::ports::{TenantIds, Transport};
use access_identity_oauth::adapters::dpop::SystemClock;
use access_identity_oauth::adapters::oauth::OsRandom;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_store::Pool;

use crate::login::RealmKeks;

/// The pools delivery reads and writes.
#[derive(Clone)]
pub(crate) struct EventPools {
    /// `access_app`.
    pub(crate) app: Pool,
    /// `access_outbox_reader`.
    pub(crate) reader: Pool,
    /// `access_router`, for the live realms.
    pub(crate) router: Pool,
    /// The tenants' `tnt_` ids (OP-149 m.15 (i)).
    pub(crate) ids: Arc<dyn TenantIds>,
}

impl EventPools {
    pub(crate) fn db(&self) -> Db {
        Db {
            app: self.app.clone(),
            reader: self.reader.clone(),
            ids: self.ids.clone(),
        }
    }
}

/// The fan-out and the courier as two tasks of this process.
pub(crate) struct Delivery {
    stop: tokio::sync::watch::Sender<bool>,
    fanning: tokio::task::JoinHandle<()>,
    sending: tokio::task::JoinHandle<()>,
}

impl Delivery {
    /// Starts both over `transport`.
    pub(crate) fn start<T: Transport + 'static>(
        pools: &EventPools,
        transport: T,
        signer: SignerKeys,
        keks: RealmKeks,
    ) -> Self {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let fanout = Fanout::new(pools.db(), SystemClock);
        let router = pools.router.clone();
        let until = stopped.clone();
        let fanning = tokio::spawn(async move { fanout.run(&router, &until).await });
        let courier = Courier::new(
            pools.db(),
            transport,
            signer,
            KekSealer(keks),
            SystemClock,
            Backoff::default(),
        );
        let sending = tokio::spawn(async move { courier.run(&stopped).await });
        Self {
            stop,
            fanning,
            sending,
        }
    }

    /// Starts both over the identity plane's outbound client.
    pub(crate) fn outbound(
        pools: &EventPools,
        outbound: Outbound,
        signer: SignerKeys,
        keks: RealmKeks,
    ) -> Self {
        Self::start(pools, OutboundTransport(outbound), signer, keks)
    }

    /// Both finish their step.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.fanning.await;
        let _ = self.sending.await;
    }
}

/// The realms' SSF transmitter routes (SSF 1.0, RFC 8936).
pub(crate) fn ssf(pools: &EventPools, signer: SignerKeys, keks: RealmKeks) -> axum::Router {
    access_http::ssf::router(Transmitter::new(
        PgDirectory::new(pools.router.clone()),
        Streams::new(pools.db(), KekSealer(keks), OsRandom),
        signer,
        SystemClock,
    ))
}

#[cfg(test)]
mod tests;
