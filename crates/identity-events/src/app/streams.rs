//! Streams in minimal form (SSF 1.0 §8, OP-149 m.7): create, read, update the requested events
//! and status, and disable (never delete, OP-73); and RFC 8936 poll.
//!
//! - A webhook stream gets a Standard Webhooks secret, shown once at creation and stored
//!   sealed under the realm KEK.
//! - A poll stream gets a bearer credential, shown once and stored as its digest (CR-38).
//!   It authenticates poll and the stream's own management calls (RFC 6750).

use access_crypto::webhook::WebhookSecret;
use access_kernel::json::b64url_encode;
use access_store::events::SubscriptionRow;
use access_store::identity::{RealmId, TenantId, TenantTx};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::app::{Db, down, realm_signing};
use crate::domain::Invalid;
use crate::domain::set::SET_TYP;
use crate::domain::stream::{
    Channel, StreamRequest, parse_poll, poll_response, requested, stream_json,
};
use crate::ports::{Clock, Random, Sealer, TokenSigner, Unavailable};

/// Why a stream operation did not happen.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// The request is not valid.
    #[error(transparent)]
    Invalid(#[from] Invalid),
    /// No live stream for this credential or id.
    #[error("no such stream")]
    NotFound,
    /// Storage, keys or the signer failed.
    #[error("unavailable")]
    Unavailable,
}

impl From<Unavailable> for StreamError {
    fn from(_: Unavailable) -> Self {
        Self::Unavailable
    }
}

impl StreamError {
    /// HTTP status and stable reason code of the RFC 9457 problem.
    #[must_use]
    pub const fn problem(&self) -> (u16, &'static str) {
        match self {
            Self::Invalid(i) => (400, i.0),
            Self::NotFound => (404, "no-such-stream"),
            Self::Unavailable => (503, "temporarily-unavailable"),
        }
    }
}

/// A new stream and what is shown of it once.
pub struct Created {
    /// Its id.
    pub id: [u8; 16],
    /// Its configuration.
    pub stream: Value,
    /// A webhook stream's `whsec_` secret.
    pub secret: Option<Zeroizing<String>>,
    /// A poll stream's bearer credential.
    pub token: Option<Zeroizing<String>>,
}

impl core::fmt::Debug for Created {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Created")
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

/// Digest of a poll credential as stored.
#[must_use]
pub fn token_digest(token: &str) -> [u8; 32] {
    access_crypto::oauth::secret_digest(token.as_bytes())
}

fn as_v4(mut b: [u8; 16]) -> [u8; 16] {
    if let Some(v) = b.get_mut(6) {
        *v = (*v & 0x0f) | 0x40;
    }
    if let Some(v) = b.get_mut(8) {
        *v = (*v & 0x3f) | 0x80;
    }
    b
}

/// Stream management and poll.
pub struct Streams<K, R> {
    db: Db,
    sealer: K,
    random: R,
}

impl<K: Sealer, R: Random> Streams<K, R> {
    /// Streams over `db`.
    pub const fn new(db: Db, sealer: K, random: R) -> Self {
        Self { db, sealer, random }
    }

    async fn issuer(&self, tenant: TenantId, realm: RealmId) -> Result<String, StreamError> {
        let (issuer, _) = realm_signing(&self.db.app, tenant, realm)
            .await?
            .ok_or(StreamError::NotFound)?;
        Ok(String::from(issuer.as_str()))
    }

    fn render(issuer: &str, s: &SubscriptionRow) -> Value {
        let channel = Channel::from_name(&s.channel).unwrap_or(Channel::SsfPoll);
        let status = if s.disabled { "disabled" } else { &s.status };
        stream_json(
            issuer,
            &s.id,
            channel,
            s.endpoint.as_deref(),
            &s.audience,
            &s.events,
            status,
        )
    }

    /// Creates a stream of `realm` (OP-149 m.7: one channel per stream).
    ///
    /// # Errors
    /// [`StreamError`].
    pub async fn create(
        &self,
        tenant: TenantId,
        realm: RealmId,
        req: &StreamRequest,
    ) -> Result<Created, StreamError> {
        let issuer = self.issuer(tenant, realm).await?;
        let mut raw = [0_u8; 16];
        self.random.fill(&mut raw)?;
        let id = as_v4(raw);
        let (secret, sealed) = if req.channel == Channel::Webhook {
            let s = WebhookSecret::generate().map_err(down)?;
            let sealed = self.sealer.seal(tenant, realm, &id, s.expose_bytes())?;
            (Some(s.expose_text()), Some(sealed))
        } else {
            (None, None)
        };
        let token = if req.channel == Channel::SsfPoll {
            let mut t = Zeroizing::new([0_u8; 32]);
            self.random.fill(t.as_mut_slice())?;
            Some(Zeroizing::new(b64url_encode(t.as_slice())))
        } else {
            None
        };
        let row = SubscriptionRow {
            realm: *realm.as_bytes(),
            id,
            channel: String::from(req.channel.name()),
            endpoint: req.endpoint.clone(),
            audience: req.audience.clone(),
            events: req.events.clone(),
            description: req.description.clone(),
            secret: sealed,
            token_digest: token.as_deref().map(|t| token_digest(t)),
            status: String::from("enabled"),
            disabled: false,
        };
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        t.insert_subscription(&row).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(Created {
            id,
            stream: Self::render(&issuer, &row),
            secret,
            token,
        })
    }

    /// The live stream whose bearer credential is `token`.
    ///
    /// # Errors
    /// [`StreamError::NotFound`].
    pub async fn by_token(
        &self,
        tenant: TenantId,
        realm: RealmId,
        token: &str,
    ) -> Result<SubscriptionRow, StreamError> {
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let s = t
            .subscription_by_token(realm, &token_digest(token))
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        s.ok_or(StreamError::NotFound)
    }

    /// A stream's configuration.
    ///
    /// # Errors
    /// [`StreamError`].
    pub async fn get(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: [u8; 16],
    ) -> Result<Value, StreamError> {
        let issuer = self.issuer(tenant, realm).await?;
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let s = t.subscription(realm, id).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(Self::render(&issuer, &s.ok_or(StreamError::NotFound)?))
    }

    /// Replaces the requested events, the status (`enabled` or `paused`) and description.
    ///
    /// # Errors
    /// [`StreamError`].
    pub async fn update(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: [u8; 16],
        body: &[u8],
    ) -> Result<Value, StreamError> {
        let v: Value = serde_json::from_slice(body).map_err(|_| Invalid("json"))?;
        let events = requested(v.get("events_requested"))?;
        let status = match v.get("status").and_then(Value::as_str) {
            None => "enabled",
            Some(s @ ("enabled" | "paused")) => s,
            Some(_) => return Err(Invalid("status").into()),
        };
        let description = v.get("description").and_then(Value::as_str);
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let done = t
            .update_subscription(realm, id, &events, status, description)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        if !done {
            return Err(StreamError::NotFound);
        }
        self.get(tenant, realm, id).await
    }

    /// Disables a stream; its pending deliveries fail (OP-73: nothing is deleted).
    ///
    /// # Errors
    /// [`StreamError`].
    pub async fn disable(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: [u8; 16],
    ) -> Result<(), StreamError> {
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let done = t.disable_subscription(realm, id).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        if done {
            Ok(())
        } else {
            Err(StreamError::NotFound)
        }
    }

    /// RFC 8936 poll by the stream's bearer credential: settles what the receiver acknowledged
    /// or reported, then returns up to `maxEvents` pending SETs, each signed now with the
    /// realm's key.
    ///
    /// # Errors
    /// [`StreamError`].
    pub async fn poll<S: TokenSigner, C: Clock>(
        &self,
        signer: &S,
        clock: &C,
        tenant: TenantId,
        realm: RealmId,
        token: &str,
        body: &[u8],
    ) -> Result<Value, StreamError> {
        let req = parse_poll(body)?;
        let s = self.by_token(tenant, realm, token).await?;
        if s.channel != Channel::SsfPoll.name() {
            return Err(StreamError::NotFound);
        }
        let (_, alg) = realm_signing(&self.db.app, tenant, realm)
            .await?
            .ok_or(StreamError::NotFound)?;
        let now = clock.now().map_err(down)?;
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        t.settle_polled(realm, s.id, &req.ack, &req.errors)
            .await
            .map_err(down)?;
        let rows = t
            .pollable(realm, s.id, req.max_events.saturating_add(1))
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        let more = rows.len() > usize::try_from(req.max_events).unwrap_or(usize::MAX);
        let mut sets = Vec::with_capacity(rows.len());
        for r in rows
            .iter()
            .take(usize::try_from(req.max_events).unwrap_or(0))
        {
            let token = signer.sign(realm, alg, SET_TYP, &r.payload, now).await?;
            sets.push((r.event_id.clone(), token));
        }
        Ok(poll_response(&sets, more))
    }
}
