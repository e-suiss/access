//! A stream's status and verification by its own bearer credential (SSF 1.0 §8.1.2, §8.1.4).
//! A verification SET goes through the stream's own delivery like any event; it shows the
//! stream delivers and is never a safety channel (§9.16.2, PI-9).

use access_kernel::json::b64url_encode;
use access_store::events::{DeliveryRow, SubscriptionRow};
use access_store::identity::{RealmId, TenantId, TenantTx};

use super::{StreamError, Streams};
use crate::app::down;
use crate::domain::Invalid;
use crate::domain::catalog::uuid;
use crate::domain::control::{
    StatusUpdate, VERIFICATION_EVENT, VerifyRequest, status_json, verification_claims,
};
use crate::domain::stream::Channel;
use crate::ports::{Random, Sealer};

fn status_of(s: &SubscriptionRow) -> &str {
    if s.disabled { "disabled" } else { &s.status }
}

fn named(s: &SubscriptionRow, stream_id: &str) -> Result<(), StreamError> {
    if uuid(&s.id) == stream_id {
        Ok(())
    } else {
        Err(StreamError::NotFound)
    }
}

impl<K: Sealer, R: Random> Streams<K, R> {
    /// The status of the stream `s`, which the request names as `stream_id`.
    ///
    /// # Errors
    /// [`StreamError::NotFound`] for another stream's id.
    pub fn status(
        &self,
        s: &SubscriptionRow,
        stream_id: &str,
    ) -> Result<serde_json::Value, StreamError> {
        named(s, stream_id)?;
        Ok(status_json(stream_id, status_of(s)))
    }

    /// Sets the status of the stream `s`: `disabled` ends it (OP-73: the row stays).
    ///
    /// # Errors
    /// [`StreamError`].
    pub async fn set_status(
        &self,
        tenant: TenantId,
        realm: RealmId,
        s: &SubscriptionRow,
        update: &StatusUpdate,
    ) -> Result<serde_json::Value, StreamError> {
        named(s, &update.stream_id)?;
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let done = if update.status == "disabled" {
            t.disable_subscription(realm, s.id).await.map_err(down)?
        } else {
            t.update_subscription(
                realm,
                s.id,
                &s.events,
                &update.status,
                s.description.as_deref(),
            )
            .await
            .map_err(down)?
        };
        t.commit().await.map_err(down)?;
        if !done {
            return Err(StreamError::NotFound);
        }
        Ok(status_json(&update.stream_id, &update.status))
    }

    /// The status of the stream `id` the platform client `client_id` owns (SSF 1.0 §8.1.2.1,
    /// OP-149 m.26 (c)).
    ///
    /// # Errors
    /// [`StreamError::NotFound`] for a stream it does not own.
    pub async fn status_owned(
        &self,
        tenant: TenantId,
        realm: RealmId,
        client_id: &str,
        id: [u8; 16],
    ) -> Result<serde_json::Value, StreamError> {
        let s = self.owned_row(tenant, realm, client_id, id).await?;
        Ok(status_json(&uuid(&s.id), status_of(&s)))
    }

    /// Sets the status of the stream `id` the platform client `client_id` owns, with the rules
    /// of a stream's own `/ssf/status` (SSF 1.0 §8.1.2.2, OP-149 m.26 (c)): `disabled` ends it
    /// and the row stays (OP-73).
    ///
    /// # Errors
    /// [`StreamError`]; a stream it does not own, or one already disabled, is not found.
    pub async fn set_status_owned(
        &self,
        tenant: TenantId,
        realm: RealmId,
        client_id: &str,
        id: [u8; 16],
        update: &StatusUpdate,
    ) -> Result<serde_json::Value, StreamError> {
        let s = self.owned_row(tenant, realm, client_id, id).await?;
        if s.disabled {
            return Err(StreamError::NotFound);
        }
        self.set_status(tenant, realm, &s, update).await
    }

    /// Queues a verification SET on the stream `s` at `now` (SSF 1.0 §8.1.4): its subject is the
    /// stream and it echoes the request's `state`. A webhook stream has no SSF verification.
    ///
    /// # Errors
    /// [`StreamError`].
    pub async fn verify(
        &self,
        tenant: TenantId,
        realm: RealmId,
        s: &SubscriptionRow,
        request: &VerifyRequest,
        now: u64,
    ) -> Result<(), StreamError> {
        named(s, &request.stream_id)?;
        if s.disabled || Channel::from_name(&s.channel).is_none_or(|c| c == Channel::Webhook) {
            return Err(Invalid("stream").into());
        }
        let issuer = self.issuer(tenant, realm).await?;
        let mut raw = [0_u8; 16];
        self.random.fill(&mut raw)?;
        let jti = b64url_encode(&raw);
        let claims = verification_claims(
            &issuer,
            &s.audience,
            &jti,
            &request.stream_id,
            request.state.as_deref(),
            now / 1000,
        );
        let row = DeliveryRow {
            tenant: *tenant.as_bytes(),
            realm: s.realm,
            subscription: s.id,
            channel: s.channel.clone(),
            event_id: jti,
            event_type: String::from(VERIFICATION_EVENT),
            payload: serde_json::to_vec(&claims).map_err(down)?,
            occurred_ms: i64::try_from(now).map_err(down)?,
            attempts: 0,
            state: String::from("pending"),
            last_reason: None,
        };
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        t.enqueue_delivery(&row, now).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(())
    }
}
