//! Event subscriptions and their delivery queue (OP-149 m.4, m.7, §9.16, OP-73): streams of a
//! realm, one channel each, and one delivery per event and subscription, deduplicated by the
//! event id. Nothing is deleted: a subscription ends with `disabled_at`, a delivery ends in a
//! final state.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{RealmId, TenantId, TenantTx};
use crate::scope::{DomainId, DomainTx};

/// A subscription's webhook secret, sealed under its own DEK wrapped by the realm KEK.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedKey {
    /// Id of the wrapping KEK.
    pub kek_id: String,
    /// The wrapped DEK.
    pub wrapped_dek: Vec<u8>,
    /// AEAD nonce.
    pub nonce: [u8; 12],
    /// Ciphertext.
    pub ciphertext: Vec<u8>,
}

impl core::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedKey")
            .field("kek_id", &self.kek_id)
            .finish_non_exhaustive()
    }
}

/// One subscription as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionRow {
    /// Its realm.
    pub realm: [u8; 16],
    /// Its id.
    pub id: [u8; 16],
    /// `webhook`, `ssf_push` or `ssf_poll`.
    pub channel: String,
    /// Where pushes go; `None` for poll.
    pub endpoint: Option<String>,
    /// The SET `aud`.
    pub audience: String,
    /// Event type URNs it receives.
    pub events: Vec<String>,
    /// Free text from the subscriber.
    pub description: Option<String>,
    /// The webhook secret.
    pub secret: Option<SealedKey>,
    /// Digest of a poll stream's bearer credential.
    pub token_digest: Option<[u8; 32]>,
    /// `enabled` or `paused`.
    pub status: String,
    /// Whether it has ended.
    pub disabled: bool,
}

/// One queued delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRow {
    /// Tenant.
    pub tenant: [u8; 16],
    /// Realm.
    pub realm: [u8; 16],
    /// Subscription.
    pub subscription: [u8; 16],
    /// Channel.
    pub channel: String,
    /// The event id, the dedup key.
    pub event_id: String,
    /// Event type URN.
    pub event_type: String,
    /// The unsigned event as the transmitter built it.
    pub payload: Vec<u8>,
    /// When the event happened, Unix ms.
    pub occurred_ms: i64,
    /// Attempts so far.
    pub attempts: i32,
    /// Current state.
    pub state: String,
    /// Why it failed or was last retried, when it did.
    pub last_reason: Option<String>,
}

/// What became of one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark<'a> {
    /// The receiver took it.
    Delivered {
        /// Its status.
        status: u16,
    },
    /// Try again at `retry_at_ms`.
    Retry {
        /// Next attempt, Unix ms.
        retry_at_ms: u64,
        /// The receiver's status, when it answered.
        status: Option<u16>,
    },
    /// Given up: `rejected`, `refused`, `unreachable` or `receiver`.
    Failed {
        /// Reason code.
        reason: &'a str,
        /// The receiver's status, when it answered.
        status: Option<u16>,
    },
}

fn uuid(b: &[u8; 16]) -> Uuid {
    Uuid::from_bytes(*b)
}

fn ms(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn status(s: Option<u16>) -> Option<i32> {
    s.map(i32::from)
}

struct Raw {
    realm_id: Uuid,
    subscription_id: Uuid,
    channel: String,
    endpoint: Option<String>,
    audience: String,
    events: Vec<String>,
    description: Option<String>,
    secret_kek_id: Option<String>,
    secret_wrapped_dek: Option<Vec<u8>>,
    secret_nonce: Option<Vec<u8>>,
    secret_ciphertext: Option<Vec<u8>>,
    token_digest: Option<Vec<u8>>,
    status: String,
    disabled: bool,
}

impl Raw {
    fn row(self) -> Result<SubscriptionRow, StoreError> {
        let secret = match (
            self.secret_kek_id,
            self.secret_wrapped_dek,
            self.secret_nonce,
            self.secret_ciphertext,
        ) {
            (Some(kek_id), Some(wrapped_dek), Some(nonce), Some(ciphertext)) => Some(SealedKey {
                kek_id,
                wrapped_dek,
                nonce: <[u8; 12]>::try_from(nonce.as_slice()).map_err(|_| StoreError::Corrupt)?,
                ciphertext,
            }),
            (None, None, None, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(SubscriptionRow {
            realm: *self.realm_id.as_bytes(),
            id: *self.subscription_id.as_bytes(),
            channel: self.channel,
            endpoint: self.endpoint,
            audience: self.audience,
            events: self.events,
            description: self.description,
            secret,
            token_digest: self
                .token_digest
                .map(|d| <[u8; 32]>::try_from(d.as_slice()).map_err(|_| StoreError::Corrupt))
                .transpose()?,
            status: self.status,
            disabled: self.disabled,
        })
    }
}

impl TenantTx {
    /// Stores a new subscription of `realm` in this tenant.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_subscription(&mut self, s: &SubscriptionRow) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO access.event_subscription
                (tenant_id, realm_id, subscription_id, channel, endpoint, audience, events,
                 description, secret_kek_id, secret_wrapped_dek, secret_nonce, secret_ciphertext,
                 token_digest, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            uuid(self.tenant.as_bytes()),
            uuid(&s.realm),
            uuid(&s.id),
            s.channel,
            s.endpoint,
            s.audience,
            &s.events,
            s.description,
            s.secret.as_ref().map(|k| k.kek_id.clone()),
            s.secret.as_ref().map(|k| k.wrapped_dek.clone()),
            s.secret.as_ref().map(|k| k.nonce.to_vec()),
            s.secret.as_ref().map(|k| k.ciphertext.clone()),
            s.token_digest.map(|d| d.to_vec()),
            s.status,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The subscription `id` of `realm`, ended or not.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn subscription(
        &mut self,
        realm: RealmId,
        id: [u8; 16],
    ) -> Result<Option<SubscriptionRow>, StoreError> {
        let raw = sqlx::query_as!(
            Raw,
            r#"SELECT realm_id, subscription_id, channel, endpoint, audience, events, description,
                      secret_kek_id, secret_wrapped_dek, secret_nonce, secret_ciphertext,
                      token_digest, status, disabled_at IS NOT NULL AS "disabled!"
                 FROM access.event_subscription WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3"#,
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            uuid(&id)
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        raw.map(Raw::row).transpose()
    }

    /// The live poll subscription of `realm` whose bearer credential has `digest`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn subscription_by_token(
        &mut self,
        realm: RealmId,
        digest: &[u8; 32],
    ) -> Result<Option<SubscriptionRow>, StoreError> {
        let raw = sqlx::query_as!(
            Raw,
            r#"SELECT realm_id, subscription_id, channel, endpoint, audience, events, description,
                      secret_kek_id, secret_wrapped_dek, secret_nonce, secret_ciphertext,
                      token_digest, status, disabled_at IS NOT NULL AS "disabled!"
                 FROM access.event_subscription WHERE tenant_id = $1 AND realm_id = $2 AND token_digest = $3 AND disabled_at IS NULL"#,
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            digest.as_slice()
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        raw.map(Raw::row).transpose()
    }

    /// The live subscriptions of every realm of this tenant.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn live_subscriptions(&mut self) -> Result<Vec<SubscriptionRow>, StoreError> {
        let raws = sqlx::query_as!(
            Raw,
            r#"SELECT realm_id, subscription_id, channel, endpoint, audience, events, description,
                      secret_kek_id, secret_wrapped_dek, secret_nonce, secret_ciphertext,
                      token_digest, status, disabled_at IS NOT NULL AS "disabled!"
                 FROM access.event_subscription WHERE tenant_id = $1 AND disabled_at IS NULL ORDER BY realm_id, subscription_id"#,
            uuid(self.tenant.as_bytes())
        )
        .fetch_all(&mut *self.tx)
        .await?;
        raws.into_iter().map(Raw::row).collect()
    }

    /// Replaces a live subscription's requested events, status and description.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn update_subscription(
        &mut self,
        realm: RealmId,
        id: [u8; 16],
        events: &[String],
        status: &str,
        description: Option<&str>,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "UPDATE access.event_subscription
                SET events = $4, status = $5, description = $6, updated_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3
                AND disabled_at IS NULL",
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            uuid(&id),
            events,
            status,
            description,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Ends a subscription (OP-73: no delete); its pending deliveries fail as `receiver`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn disable_subscription(
        &mut self,
        realm: RealmId,
        id: [u8; 16],
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "UPDATE access.event_subscription SET disabled_at = now(), updated_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3
                AND disabled_at IS NULL",
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            uuid(&id),
        )
        .execute(&mut *self.tx)
        .await?;
        sqlx::query!(
            "UPDATE access.event_delivery SET state = 'failed', last_reason = 'receiver',
                    updated_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3
                AND state = 'pending'",
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            uuid(&id),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Queues one event for one subscription, due at `due_ms`; `false` when it is already
    /// queued (dedup by event id).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn enqueue_delivery(
        &mut self,
        d: &DeliveryRow,
        due_ms: u64,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "INSERT INTO access.event_delivery
                (tenant_id, realm_id, subscription_id, channel, event_id, event_type, payload,
                 occurred_at, next_attempt_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8::bigint / 1000.0),
                     to_timestamp($9::bigint / 1000.0))
             ON CONFLICT (tenant_id, realm_id, subscription_id, event_id) DO NOTHING",
            uuid(self.tenant.as_bytes()),
            uuid(&d.realm),
            uuid(&d.subscription),
            d.channel,
            d.event_id,
            d.event_type,
            d.payload,
            d.occurred_ms,
            ms(due_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// One delivery.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn delivery(
        &mut self,
        realm: RealmId,
        subscription: [u8; 16],
        event_id: &str,
    ) -> Result<Option<DeliveryRow>, StoreError> {
        let row = sqlx::query!(
            r#"SELECT channel, event_type, payload, attempts, state, last_reason,
                      (extract(epoch FROM occurred_at) * 1000)::bigint AS "occurred_ms!"
                 FROM access.event_delivery
                WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3 AND event_id = $4"#,
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            uuid(&subscription),
            event_id,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| DeliveryRow {
            tenant: *self.tenant.as_bytes(),
            realm: *realm.as_bytes(),
            subscription,
            channel: r.channel,
            event_id: String::from(event_id),
            event_type: r.event_type,
            payload: r.payload,
            occurred_ms: r.occurred_ms,
            attempts: r.attempts,
            state: r.state,
            last_reason: r.last_reason,
        }))
    }

    /// Records one attempt of a pending delivery.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn mark_delivery(
        &mut self,
        realm: RealmId,
        subscription: [u8; 16],
        event_id: &str,
        mark: Mark<'_>,
    ) -> Result<bool, StoreError> {
        let (state, retry_at, code, reason) = match mark {
            Mark::Delivered { status: s } => ("delivered", None, Some(s), None),
            Mark::Retry {
                retry_at_ms,
                status: s,
            } => ("pending", Some(ms(retry_at_ms)?), s, None),
            Mark::Failed { reason, status: s } => ("failed", None, s, Some(reason)),
        };
        let done = sqlx::query!(
            "UPDATE access.event_delivery
                SET state = $5, attempts = attempts + 1, last_status = $6, last_reason = $7,
                    next_attempt_at = coalesce(to_timestamp($8::bigint / 1000.0), next_attempt_at),
                    updated_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3 AND event_id = $4
                AND state = 'pending'",
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            uuid(&subscription),
            event_id,
            state,
            status(code),
            reason,
            retry_at,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Up to `limit` pending deliveries of a poll subscription, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn pollable(
        &mut self,
        realm: RealmId,
        subscription: [u8; 16],
        limit: u32,
    ) -> Result<Vec<DeliveryRow>, StoreError> {
        let rows = sqlx::query!(
            r#"SELECT event_id, event_type, payload, attempts, state, last_reason,
                      (extract(epoch FROM occurred_at) * 1000)::bigint AS "occurred_ms!"
                 FROM access.event_delivery
                WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3
                  AND channel = 'ssf_poll' AND state = 'pending'
                ORDER BY created_at, event_id LIMIT $4"#,
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            uuid(&subscription),
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| DeliveryRow {
                tenant: *self.tenant.as_bytes(),
                realm: *realm.as_bytes(),
                subscription,
                channel: String::from("ssf_poll"),
                event_id: r.event_id,
                event_type: r.event_type,
                payload: r.payload,
                occurred_ms: r.occurred_ms,
                attempts: r.attempts,
                state: r.state,
                last_reason: r.last_reason,
            })
            .collect())
    }

    /// Settles polled deliveries the receiver acknowledged (`acknowledged`) or reported an
    /// error for (`failed`, reason `receiver`) (RFC 8936 §2.4, §2.5).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn settle_polled(
        &mut self,
        realm: RealmId,
        subscription: [u8; 16],
        acked: &[String],
        errors: &[String],
    ) -> Result<u64, StoreError> {
        let done = sqlx::query!(
            "UPDATE access.event_delivery
                SET state = CASE WHEN event_id = ANY($4) THEN 'acknowledged' ELSE 'failed' END,
                    last_reason = CASE WHEN event_id = ANY($4) THEN NULL ELSE 'receiver' END,
                    attempts = attempts + 1, updated_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3
                AND channel = 'ssf_poll' AND state = 'pending'
                AND (event_id = ANY($4) OR event_id = ANY($5))",
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
            uuid(&subscription),
            acked,
            errors,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected())
    }
}

/// A pending push delivery, as the transmitter finds it across tenants.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Due {
    /// Tenant.
    pub tenant: TenantId,
    /// Realm.
    pub realm: RealmId,
    /// Subscription.
    pub subscription: [u8; 16],
}

/// Pending push deliveries whose next attempt is at or before `now_ms`, oldest first: their
/// tenant, realm, subscription and event id. Read as `access_outbox_reader`.
///
/// # Errors
/// [`StoreError`].
pub async fn due(
    reader: &PgPool,
    now_ms: u64,
    limit: u32,
) -> Result<Vec<(Due, String)>, StoreError> {
    let rows = sqlx::query!(
        "SELECT tenant_id, realm_id, subscription_id, event_id FROM access.event_delivery
          WHERE state = 'pending' AND channel <> 'ssf_poll'
            AND next_attempt_at <= to_timestamp($1::bigint / 1000.0)
          ORDER BY next_attempt_at, created_at LIMIT $2",
        ms(now_ms)?,
        i64::from(limit),
    )
    .fetch_all(reader)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                Due {
                    tenant: TenantId::from_bytes(*r.tenant_id.as_bytes()),
                    realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
                    subscription: *r.subscription_id.as_bytes(),
                },
                r.event_id,
            )
        })
        .collect())
}

/// The transmitter's cursor in a domain's authority outbox: `(pos, idx)` of the last event it
/// queued, `(0, 0)` before the first.
///
/// # Errors
/// [`StoreError`].
pub async fn domain_cursor(app: &PgPool, domain: &DomainId) -> Result<(u64, u32), StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    let row = sqlx::query!(
        "SELECT pos, idx FROM access.event_domain_cursor WHERE domain_id = $1",
        domain.as_bytes().as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map_or(Ok((0, 0)), |r| {
        Ok((
            u64::try_from(r.pos).map_err(|_| StoreError::Corrupt)?,
            u32::try_from(r.idx).map_err(|_| StoreError::Corrupt)?,
        ))
    })
}

/// Moves the domain cursor forward to `at`; never back.
///
/// # Errors
/// [`StoreError`].
pub async fn advance_domain_cursor(
    app: &PgPool,
    domain: &DomainId,
    at: (u64, u32),
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    sqlx::query!(
        "INSERT INTO access.event_domain_cursor (domain_id, pos, idx) VALUES ($1, $2, $3)
         ON CONFLICT (domain_id) DO UPDATE SET pos = EXCLUDED.pos, idx = EXCLUDED.idx,
                updated_at = now()
          WHERE (event_domain_cursor.pos, event_domain_cursor.idx) < (EXCLUDED.pos, EXCLUDED.idx)",
        domain.as_bytes().as_slice(),
        ms(at.0)?,
        i32::try_from(at.1).map_err(|_| StoreError::Range)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}
