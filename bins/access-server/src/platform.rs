//! The platform product API of this process (OP-149 m.4, m.16 (a), m.17 (e), (g)): pairing and
//! event streams for platform clients, over the identity plane's stores, the realm directory,
//! clients' JWKS documents and the authority plane. The same API verifies the client assertions
//! the product routes accept (OP-149 m.37).

use std::sync::Arc;

use access_identity_admin::app::platform::PlatformApi;
use access_identity_admin::ports::Instances;
use access_identity_events::adapters::KekSealer;
use access_identity_events::app::streams::Streams;
use access_identity_oauth::adapters::PgDirectory;
use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys};
use access_identity_oauth::adapters::dpop::SystemClock;
use access_identity_oauth::adapters::oauth::OsRandom;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_ui::domain::frontend::IDENTITY_PEP;

use crate::events::EventPools;
use crate::login::RealmKeks;

/// The platform API of this process over the authority plane `I`.
pub(crate) type Api<I> =
    PlatformApi<PgDirectory, HttpClientKeys, I, KekSealer<RealmKeks>, OsRandom, SystemClock>;

/// The platform routes under `api_base`, and the API behind them for the product routes'
/// assertion verification (OP-149 m.37).
pub(crate) fn routes<I: Instances + 'static>(
    pools: &EventPools,
    outbound: Outbound,
    keks: RealmKeks,
    instances: I,
    api_base: String,
) -> (axum::Router, Arc<Api<I>>) {
    let api = Arc::new(PlatformApi {
        app: pools.app.clone(),
        router: pools.router.clone(),
        directory: PgDirectory::new(pools.router.clone()),
        streams: Streams::new(pools.db(), KekSealer(keks), OsRandom)
            .declaring(pools.declared.clone()),
        client_keys: HttpClientKeys::new(outbound, CachePolicy::default()),
        instances,
        ids: Arc::clone(&pools.ids),
        pep: String::from(IDENTITY_PEP),
        clock: SystemClock,
    });
    (
        access_http::platform::router(Arc::clone(&api), api_base),
        api,
    )
}
