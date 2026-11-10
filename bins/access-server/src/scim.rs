//! The SCIM server and the outbound SCIM client in this process (OP-155 m.3 (g), IDP-23, IDP-29):
//! the realms' PII vault keys, the SCIM routes, and the outbound worker over the guarded HTTP
//! client with each target's secret opened under its realm KEK.

use std::sync::Arc;
use std::time::Duration;

use access_crypto::opaque_id::IdKey;
use access_crypto::scim_cursor::CursorKey;
use access_identity_account::app::vault::Vault;
use access_identity_events::adapters::KekSealer;
use access_identity_events::ports::Sealer as _;
use access_identity_oauth::adapters::PgDirectory;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_scim::app::outbound::{MAX_ANSWER, Pending, Reply, Secrets, Sender, Worker};
use access_identity_scim::app::{Scim, Vaults};
use access_identity_scim::ports::SystemClock;
use access_store::Pool;
use access_store::events::SealedKey;
use access_store::identity::{RealmId, TenantId};

use crate::login::RealmKeks;

/// How often the outbound worker looks for new pushes (PD).
pub(crate) const INTERVAL: Duration = Duration::from_secs(2);

/// The realms' PII vault keys from the token.
#[derive(Clone)]
pub(crate) struct ScimVaults(pub(crate) RealmKeks);

impl Vaults for ScimVaults {
    fn vault(&self, _: TenantId, realm: RealmId) -> Option<Vault> {
        self.0.vault(realm)
    }
}

/// The SCIM service of this process.
pub(crate) type Service = Scim<ScimVaults, SystemClock>;

/// The SCIM service over `app`.
///
/// # Errors
/// No randomness for the cursor key.
pub(crate) fn service(app: Pool, keks: RealmKeks, ids: Arc<IdKey>) -> Result<Service, String> {
    let cursors = CursorKey::generate().map_err(|e| e.to_string())?;
    Ok(Scim::new(app, ScimVaults(keks), SystemClock, cursors, ids))
}

/// The SCIM routes: realms named by the router role, requests in the application role.
///
/// # Errors
/// No randomness for the cursor key.
pub(crate) fn routes(
    router: Pool,
    app: Pool,
    keks: RealmKeks,
    ids: Arc<IdKey>,
) -> Result<axum::Router, String> {
    Ok(access_http::scim::router(
        PgDirectory::new(router),
        service(app, keks, ids)?,
    ))
}

/// The guarded outbound client as the SCIM pusher.
pub(crate) struct Pusher(pub(crate) Outbound);

impl Sender for Pusher {
    fn send<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        secret: &'a [u8],
        body: Option<&'a [u8]>,
    ) -> Pending<'a, Option<Reply>> {
        Box::pin(async move {
            let bearer = std::str::from_utf8(secret).ok()?;
            let headers = [
                ("authorization", format!("Bearer {bearer}")),
                ("accept", String::from("application/scim+json")),
            ];
            match self
                .0
                .send_json(method, url, &headers, body, MAX_ANSWER)
                .await
            {
                Ok(a) => Some(Reply {
                    status: a.status,
                    body: a.body,
                }),
                Err(error) => {
                    tracing::warn!(%error, "scim push not delivered");
                    None
                }
            }
        })
    }
}

/// Targets' secrets opened under their realm KEK.
pub(crate) struct TargetSecrets(pub(crate) KekSealer<RealmKeks>);

impl Secrets for TargetSecrets {
    fn open(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        sealed: &SealedKey,
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        self.0.open(tenant, realm, id, sealed).ok()
    }
}

/// The running outbound worker.
pub(crate) struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// Starts the outbound worker over the identity outbox.
///
/// # Errors
/// No randomness for the cursor key.
pub(crate) fn start(
    (app, reader): (Pool, Pool),
    outbound: Outbound,
    keks: RealmKeks,
    ids: Arc<IdKey>,
) -> Result<Running, String> {
    let worker = Worker {
        app: app.clone(),
        reader,
        sender: Pusher(outbound),
        secrets: TargetSecrets(KekSealer(keks.clone())),
        local: service(app, keks, ids)?,
    };
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { worker.run(INTERVAL, &stopped).await });
    Ok(Running { stop, task })
}

impl Running {
    /// Finishes the step in flight and stops.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}
