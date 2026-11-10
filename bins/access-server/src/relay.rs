//! The Relay courier in this process (E42, OP-156 m.3 (c), Ek B 5393, 5401): Access's
//! messages to people leave the identity outbox for Relay, where Access is a platform tenant.
//!
//! - The tenant, the credential file and Relay's trust anchors are configuration
//!   (`[suiss.relay_platform]`); without them the server does not start.
//! - Nothing waits for Relay at start (E42 m.5): the courier reads Relay's discovery document in
//!   the background and sends only once it names this Access, the events capability and an
//!   intake on Relay's origin. Until then messages wait in the outbox.
//! - One node at a time holds the courier lease and sends (`access_ops.courier_leases`).
//! - The lag, the age of the oldest message waiting for Relay, is public at
//!   `GET /access/v1/relay-status`; past 60 s it reads as notifications delayed.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_crypto::secret_file::SecretFile;
use access_http::internal::ReadyFlag;
use access_identity_account::adapters::system::SystemClock;
use access_identity_account::notify::courier::Courier;
use access_identity_account::notify::delivery::{Backoff, check_discovery};
use access_identity_account::notify::http::{HttpRelay, HttpRelayConfig, RelayEndpoint, discover};
use access_identity_account::notify::pg::PgCourierStore;
use access_identity_account::notify::ports::{CourierStore as _, RealmKeys};
use access_identity_events::adapters::RealmKek as _;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use suiss_crypto::envelope::Kek;

use crate::config::Config;
use crate::login::RealmKeks;

/// The public lag route.
pub(crate) const STATUS_PATH: &str = "/access/v1/relay-status";

/// Past this lag notifications read as delayed (OP-156 m.3 (c), PD).
pub(crate) const DELAYED_MS: u64 = 60_000;

/// How long one Relay exchange may take (PD).
const TIMEOUT: Duration = Duration::from_secs(10);

/// How often an unconfirmed Relay is asked for its discovery document again (PD).
const DISCOVERY_RETRY: Duration = Duration::from_secs(30);

/// What the courier needs from the file system, read before the lockdown.
pub(crate) struct Prepared {
    relay: String,
    issuer: String,
    credential: PathBuf,
    tls: Arc<rustls::ClientConfig>,
}

/// Reads Relay's trust anchors and checks the credential file (E42, OP-156 m.3 (c)).
///
/// # Errors
/// No `[suiss.relay_platform]`, an unreadable or group-readable credential file, or no
/// usable trust anchor: the server does not start (TI-9).
pub(crate) fn prepare(config: &Config, system_roots: &[&str]) -> Result<Prepared, String> {
    let suiss = config.suiss.as_ref().ok_or("no suiss section")?;
    let platform = &suiss.relay_platform;
    SecretFile::load(platform.credential_file.clone())
        .map_err(|e| format!("suiss.relay_platform.credential_file: {e}"))?;
    let pem = match &platform.ca_file {
        Some(f) => std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?,
        None => system_roots
            .iter()
            .find_map(|f| std::fs::read(f).ok())
            .ok_or("no trust anchors for Relay")?,
    };
    let tls = access_http::tls::client_config(&pem).map_err(|e| e.to_string())?;
    Ok(Prepared {
        relay: suiss.relay.clone(),
        issuer: config.issuer.clone().ok_or("no issuer")?,
        credential: platform.credential_file.clone(),
        tls,
    })
}

/// What the lockdown must leave open for the courier: the credential file's directory, for its
/// rotation, and Relay's port.
pub(crate) fn lockdown_needs(config: &Config) -> (Option<PathBuf>, Option<u16>) {
    let Some(suiss) = config.suiss.as_ref() else {
        return (None, None);
    };
    let dir = suiss
        .relay_platform
        .credential_file
        .parent()
        .map(Path::to_path_buf);
    let port = suiss
        .relay
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .map(|authority| {
            authority
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse().ok())
                .unwrap_or(443)
        });
    (dir, port)
}

/// The realms' KEKs the courier unwraps subject keys with.
pub(crate) struct Keks(pub(crate) RealmKeks);

impl RealmKeys for Keks {
    fn kek(
        &self,
        tenant: TenantId,
        realm: RealmId,
        kek_id: &str,
    ) -> Option<Arc<dyn Kek + Send + Sync>> {
        self.0.kek(tenant, realm).filter(|k| k.id() == kek_id)
    }
}

/// The running courier.
pub(crate) struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Finishes the send in flight, gives the lease up and stops.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn confirmed(p: &Prepared, stop: &mut tokio::sync::watch::Receiver<bool>) -> Option<String> {
    loop {
        if *stop.borrow() {
            return None;
        }
        let why = match discover(&p.relay, p.tls.clone(), TIMEOUT).await {
            Ok(doc) => match check_discovery(&doc, &p.relay, &p.issuer) {
                Ok(url) => return Some(url),
                Err(e) => e.to_string(),
            },
            Err(e) => e.to_string(),
        };
        tracing::warn!(reason = %why, "relay not confirmed; messages wait in the outbox");
        let _ = tokio::time::timeout(DISCOVERY_RETRY, stop.changed()).await;
    }
}

/// Starts the courier as `holder` over the outbox reader and the application pool; `alive` is
/// unset when it ends other than by [`Running::stop`].
pub(crate) fn start(
    prepared: Prepared,
    (reader, app): (Pool, Pool),
    keks: RealmKeks,
    ids: [u8; 32],
    holder: String,
    alive: &ReadyFlag,
) -> Running {
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let ended = alive.clone();
    let task = tokio::spawn(async move {
        let mut until = stopped.clone();
        let Some(url) = confirmed(&prepared, &mut until).await else {
            return;
        };
        let relay = RelayEndpoint::parse(&url)
            .map_err(|e| e.to_string())
            .and_then(|endpoint| {
                HttpRelay::new(HttpRelayConfig {
                    endpoint,
                    tls: prepared.tls.clone(),
                    token_file: prepared.credential.clone(),
                    timeout: TIMEOUT,
                })
                .map_err(|e| e.to_string())
            });
        let relay = match relay {
            Ok(r) => r,
            Err(error) => {
                tracing::error!(%error, "relay courier cannot start");
                ended.set(false);
                return;
            }
        };
        tracing::info!("relay confirmed; the courier starts");
        let courier = Courier::new(
            PgCourierStore { reader, app },
            relay,
            Keks(keks),
            SystemClock,
            IdKey::new(Secret::new(ids)),
            Backoff::default(),
        );
        courier.run(&holder, &stopped).await;
        if !*stopped.borrow() {
            ended.set(false);
        }
    });
    Running { stop, task }
}

/// `GET /access/v1/relay-status` over the courier's store (OP-156 m.3 (c), §8.13).
pub(crate) fn routes(reader: Pool, app: Pool) -> axum::Router {
    axum::Router::new()
        .route(STATUS_PATH, axum::routing::get(status))
        .with_state(Arc::new(PgCourierStore { reader, app }))
}

/// The status body: the lag, `null` when nothing waits, and whether it reads as delayed.
#[must_use]
pub(crate) fn body(lag_ms: Option<u64>) -> serde_json::Value {
    json!({
        "relay_lag_ms": lag_ms,
        "notifications_delayed": lag_ms.is_some_and(|l| l > DELAYED_MS),
    })
}

async fn status(State(store): State<Arc<PgCourierStore>>) -> Response {
    match store.lag_ms().await {
        Ok(lag) => {
            let mut r = Json(body(lag)).into_response();
            r.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }
        Err(error) => {
            tracing::warn!(%error, "relay lag unavailable");
            access_http::problem::codes::UNAVAILABLE
                .problem()
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests;
