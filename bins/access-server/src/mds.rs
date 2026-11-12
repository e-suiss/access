//! The FIDO metadata refresh job (OP-148, OP-146 m.4 (d), OP-158 m.3 (y)): the blob is fetched
//! from the operator's configured URL through the guarded outbound client, its signature chain
//! is verified against the configured root and its `nextUpdate` against trusted time, and the
//! verified bytes are cached in `access.mds_cache`. Every process starts from the newest cached
//! blob, verified again, and goes to the URL only when that one is due; a lower serial than the
//! one held is refused (rollback). A blob that does not verify is never used.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use access_crypto::xmlsec::{Digest, digest};
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_webauthn::WebAuthnError;
use access_identity_webauthn::adapters::MemoryMdsCache;
use access_identity_webauthn::domain::mds::{MAX_BLOB, MdsBlob, MdsError, verify_blob};
use access_identity_webauthn::ports::MdsCache as _;
use access_store::Pool;

/// How often the job looks (PD): the blob changes about monthly; a missed round only ages it.
pub(crate) const REFRESH_EVERY: Duration = Duration::from_hours(6);

/// What a round did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refreshed {
    /// The held blob is fresh and not yet due.
    Held(u64),
    /// A newer blob came from the cache another process or a restart left.
    FromCache(u64),
    /// A newer blob came from the URL and was cached.
    Fetched(u64),
}

/// The metadata of this process: where it comes from, the root it must chain to, and the
/// blob held now.
pub(crate) struct Metadata {
    url: String,
    root: Vec<u8>,
    source: [u8; 32],
    held: Arc<MemoryMdsCache>,
}

impl Metadata {
    /// The metadata from `url`, chained to the DER root `root`.
    pub(crate) fn new(url: String, root: Vec<u8>) -> Self {
        let mut source = [0_u8; 32];
        for (d, s) in source
            .iter_mut()
            .zip(digest(Digest::Sha256, url.as_bytes()))
        {
            *d = s;
        }
        Self {
            url,
            root,
            source,
            held: Arc::new(MemoryMdsCache::default()),
        }
    }

    /// This metadata holding its blob in `held`.
    fn holding(mut self, held: Arc<MemoryMdsCache>) -> Self {
        self.held = held;
        self
    }

    /// The blob held now, when it is still fresh at `now_s`.
    #[cfg(test)]
    pub(crate) async fn current(&self, now_s: u64) -> Option<MdsBlob> {
        self.held
            .current()
            .await
            .ok()
            .flatten()
            .filter(|b| b.is_fresh(now_s))
    }

    async fn held_serial(&self) -> Option<MdsBlob> {
        self.held.current().await.ok().flatten()
    }

    /// One round at `now_s` (Unix seconds).
    ///
    /// # Errors
    /// [`WebAuthnError`]: the URL could not be read, or its blob does not verify or rolls back;
    /// the blob held stays.
    pub(crate) async fn refresh(
        &self,
        app: &Pool,
        outbound: &Outbound,
        now_s: u64,
    ) -> Result<Refreshed, WebAuthnError> {
        let held = self.held_serial().await;
        let cached = access_store::mds::latest(app, &self.source)
            .await
            .map_err(|e| WebAuthnError::MdsSource(e.to_string()))?;
        let mut from_cache = None;
        if let Some((serial, bytes)) = cached
            && held.as_ref().is_none_or(|h| h.serial < serial)
            && let Ok(blob) = verify_blob(&bytes, &self.root, now_s)
        {
            from_cache = Some(blob.serial);
            self.held.replace(blob).await?;
        }
        let held = self.held_serial().await;
        if let Some(h) = &held
            && h.is_fresh(now_s)
            && now_s < h.next_update
        {
            return Ok(from_cache.map_or(Refreshed::Held(h.serial), Refreshed::FromCache));
        }
        let answer = outbound
            .get_configured(
                &self.url,
                "application/jwt, application/octet-stream",
                MAX_BLOB,
            )
            .await
            .map_err(|e| WebAuthnError::MdsSource(e.to_string()))?;
        if answer.status != 200 {
            return Err(WebAuthnError::MdsSource(format!(
                "status {}",
                answer.status
            )));
        }
        let blob = verify_blob(&answer.body, &self.root, now_s)?;
        if let Some(h) = &held {
            if blob.serial < h.serial {
                return Err(MdsError::Rollback.into());
            }
            if blob.serial == h.serial {
                return Ok(Refreshed::Held(h.serial));
            }
        }
        let serial = blob.serial;
        access_store::mds::record(app, &self.source, serial, blob.next_update, &answer.body)
            .await
            .map_err(|e| WebAuthnError::MdsSource(e.to_string()))?;
        self.held.replace(blob).await?;
        let target = format!("fido-mds:{serial}");
        // OP-41, OP-148
        access_store::operational::record_operational(
            app,
            &access_store::operational::OperationalEvent {
                event_type: "mds.refreshed",
                occurred_at_ms: now_s.saturating_mul(1000),
                tenant: None,
                domain: None,
                actor: "access-server:fido-mds",
                target: &target,
                reason: "",
                correlation: &target,
            },
        )
        .await
        .map_err(|e| WebAuthnError::MdsSource(e.to_string()))?;
        tracing::info!(serial, "FIDO metadata refreshed (OP-148)");
        Ok(Refreshed::Fetched(serial))
    }
}

/// The blob this process holds, which the refresh job keeps and a realm's `direct` attestation
/// policy reads (OP-159 m.3 (ll)); empty without a configured service.
pub(crate) fn shared() -> Arc<MemoryMdsCache> {
    static HELD: OnceLock<Arc<MemoryMdsCache>> = OnceLock::new();
    HELD.get_or_init(Arc::default).clone()
}

/// OP-148, OP-158 m.3 (y): the job of the configured service, none without one.
///
/// # Errors
/// The configured root is not base64url DER.
pub(crate) fn spawn(
    config: Option<&crate::config::FidoMds>,
    app: Pool,
    outbound: &Outbound,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    let Some(m) = config else {
        return Ok(None);
    };
    let root = access_kernel::json::b64url_decode(&m.root)
        .map_err(|_| "identity.fido_mds.root is not base64url DER".to_owned())?;
    Ok(Some(tokio::spawn(run(
        Arc::new(Metadata::new(m.url.clone(), root).holding(shared())),
        app,
        outbound.clone(),
    ))))
}

/// Runs the job until the task is aborted.
pub(crate) async fn run(metadata: Arc<Metadata>, app: Pool, outbound: Outbound) {
    let mut every = tokio::time::interval(REFRESH_EVERY);
    loop {
        every.tick().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if let Err(error) = metadata.refresh(&app, &outbound, now).await {
            tracing::warn!(%error, code = error.code(), "FIDO metadata not refreshed; the held blob ages");
        }
    }
}

#[cfg(test)]
mod tests;
