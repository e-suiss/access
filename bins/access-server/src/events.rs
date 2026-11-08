//! Event delivery of the identity plane in this process (OP-149 m.4, m.7, m.17, OP-151 m.3 (l)):
//! the fan-out from the identity and authority outboxes, the push courier over the SSRF-guarded
//! client, the realms' SSF transmitter, and the SSF receiver with its RFC 8936 poll client.
//! Webhook secrets and poll credentials are sealed under the realm KEKs the hosted login opens.

use std::sync::Arc;

use access_http::internal::ReadyFlag;
use access_identity_account::notify::delivery::Backoff;
use access_identity_events::adapters::{KekSealer, OutboundTransport};
use access_identity_events::app::Db;
use access_identity_events::app::courier::Courier;
use access_identity_events::app::fanout::Fanout;
use access_identity_events::app::receiver::Receiver;
use access_identity_events::app::ssf::Transmitter;
use access_identity_events::app::streams::Streams;
use access_identity_events::app::webhooks::{WebhookCourier, WebhookFanout};
use access_identity_events::ports::{TenantIds, Transport};
use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys};
use access_identity_oauth::adapters::dpop::SystemClock;
use access_identity_oauth::adapters::oauth::OsRandom;
use access_identity_oauth::adapters::outbound::{DeclaredTargets, Outbound};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_store::Pool;

use crate::login::RealmKeks;

/// The pools delivery and stream management read and write.
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
    /// The operator's declared delivery targets, which stream endpoints are checked against
    /// (OP-149 m.23).
    pub(crate) declared: DeclaredTargets,
    /// The SSRF-guarded client the receiver fetches transmitter keys with; without it the
    /// realms take no inbound SETs (OP-151 m.3 (l)).
    pub(crate) outbound: Option<Outbound>,
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

/// The stream fan-out and courier, and the webhook fan-out and courier (TN-136), as tasks of
/// this process.
pub(crate) struct Delivery {
    stop: tokio::sync::watch::Sender<bool>,
    fanning: tokio::task::JoinHandle<()>,
    sending: tokio::task::JoinHandle<()>,
    polling: Option<tokio::task::JoinHandle<()>>,
    webhook_fanning: tokio::task::JoinHandle<()>,
    webhook_sending: tokio::task::JoinHandle<()>,
}

impl Delivery {
    /// Starts the four delivery tasks over `transport`; `alive` is unset when one of them ends.
    pub(crate) fn start<T: Transport + Clone + 'static>(
        pools: &EventPools,
        transport: T,
        signer: SignerKeys,
        keks: RealmKeks,
        alive: &ReadyFlag,
    ) -> Self {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let fanout = Fanout::new(pools.db(), SystemClock);
        let router = pools.router.clone();
        let until = stopped.clone();
        let ended = alive.clone();
        let fanning = tokio::spawn(async move {
            fanout.run(&router, &until).await;
            ended.set(false);
        });
        let courier = Courier::new(
            pools.db(),
            transport.clone(),
            signer,
            KekSealer(keks.clone()),
            SystemClock,
            Backoff::default(),
        );
        let until = stopped.clone();
        let ended = alive.clone();
        let sending = tokio::spawn(async move {
            courier.run(&until).await;
            ended.set(false);
        });
        // TN-136, OP-151 m.3 (i)
        let webhook_fanout = WebhookFanout::new(pools.db(), SystemClock);
        let until = stopped.clone();
        let ended = alive.clone();
        let webhook_fanning = tokio::spawn(async move {
            webhook_fanout.run(&until).await;
            ended.set(false);
        });
        let webhook_courier =
            WebhookCourier::new(pools.db(), transport, KekSealer(keks), SystemClock);
        let ended = alive.clone();
        let webhook_sending = tokio::spawn(async move {
            webhook_courier.run(&stopped).await;
            ended.set(false);
        });
        Self {
            stop,
            fanning,
            sending,
            polling: None,
            webhook_fanning,
            webhook_sending,
        }
    }

    /// Starts both over the identity plane's outbound client.
    pub(crate) fn outbound(
        pools: &EventPools,
        outbound: Outbound,
        signer: SignerKeys,
        keks: RealmKeks,
        alive: &ReadyFlag,
    ) -> Self {
        let mut delivery = Self::start(
            pools,
            OutboundTransport(outbound.clone()),
            signer,
            keks.clone(),
            alive,
        );
        // OP-151 m.3 (l)
        let receiver = receiver(pools, outbound.clone(), keks);
        let client = OutboundTransport(outbound);
        let router = pools.router.clone();
        let stopped = delivery.stop.subscribe();
        let ended = alive.clone();
        delivery.polling = Some(tokio::spawn(async move {
            receiver.run(&client, &router, &stopped).await;
            ended.set(false);
        }));
        delivery
    }

    /// Both finish their step.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.fanning.await;
        let _ = self.sending.await;
        if let Some(p) = self.polling {
            let _ = p.await;
        }
        let _ = self.webhook_fanning.await;
        let _ = self.webhook_sending.await;
    }
}

type InboundReceiver = Receiver<PgDirectory, HttpClientKeys, KekSealer<RealmKeks>, SystemClock>;

/// The SSF receiver: transmitter keys over the SSRF-guarded client (OP-151 m.3 (l)).
fn receiver(pools: &EventPools, outbound: Outbound, keks: RealmKeks) -> InboundReceiver {
    Receiver::new(
        PgDirectory::new(pools.router.clone()),
        pools.db(),
        HttpClientKeys::new(outbound, CachePolicy::default()),
        KekSealer(keks),
        SystemClock,
    )
}

/// The realms' SSF transmitter and receiver routes (SSF 1.0, RFC 8935, RFC 8936).
pub(crate) fn ssf(pools: &EventPools, signer: SignerKeys, keks: RealmKeks) -> axum::Router {
    let transmitter = access_http::ssf::router(Transmitter::new(
        PgDirectory::new(pools.router.clone()),
        Streams::new(pools.db(), KekSealer(keks.clone()), OsRandom)
            .declaring(pools.declared.clone()),
        signer,
        SystemClock,
    ));
    match &pools.outbound {
        Some(o) => {
            let receiver = receiver(pools, o.clone(), keks);
            transmitter.merge(access_http::ssf::inbound_router(receiver))
        }
        None => transmitter,
    }
}

#[cfg(test)]
mod tests;
