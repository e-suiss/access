//! Inline hook and webhook registrations, webhook deliveries and their attempt log (TN-135,
//! TN-136, OP-151 m.3 (i), (j)). A registration is written only against a decision bound in the
//! same transaction (EI-25); nothing is deleted (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::events::SealedKey;
use crate::identity::{RealmId, TenantId, TenantTx};
use crate::idp::Bound;

fn uuid(b: &[u8; 16]) -> Uuid {
    Uuid::from_bytes(*b)
}

fn ms(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((uuid(t.tenant.as_bytes()), uuid(realm.as_bytes())))
}

fn sealed(
    kek_id: String,
    wrapped_dek: Vec<u8>,
    nonce: &[u8],
    ciphertext: Vec<u8>,
) -> Result<SealedKey, StoreError> {
    Ok(SealedKey {
        kek_id,
        wrapped_dek,
        nonce: <[u8; 12]>::try_from(nonce).map_err(|_| StoreError::Corrupt)?,
        ciphertext,
    })
}

fn key32(v: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, StoreError> {
    v.map(|b| <[u8; 32]>::try_from(b.as_slice()).map_err(|_| StoreError::Corrupt))
        .transpose()
}

/// An inline hook registration as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookRow {
    /// Its id.
    pub id: [u8; 16],
    /// `pre_registration`, `token_issuance` or `post_login`.
    pub point: String,
    /// The tenant's HTTPS endpoint.
    pub url: String,
    /// `refuse` or `continue_without_claims`.
    pub on_no_answer: String,
    /// What it may receive besides pseudonymous ids: `email`.
    pub disclose: Vec<String>,
    /// `ed25519` or `hmac`.
    pub signing: String,
    /// The signing key, sealed.
    pub key: SealedKey,
    /// The Ed25519 public key.
    pub public_key: Option<[u8; 32]>,
    /// Whether it is live.
    pub active: bool,
}

/// Registers a hook against `bound` (`idp.hook.register`).
///
/// # Errors
/// [`StoreError`]; another live hook at the same point is a unique violation.
pub async fn insert_hook(t: &mut TenantTx, bound: &Bound, h: &HookRow) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_hooks
            (tenant_id, realm_id, hook_id, point, url, on_no_answer, disclose, signing, key_kek_id,
             key_wrapped_dek, key_nonce, key_ciphertext, public_key, domain_id, decision_pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        tenant,
        realm,
        uuid(&h.id),
        h.point,
        h.url,
        h.on_no_answer,
        &h.disclose,
        h.signing,
        h.key.kek_id,
        h.key.wrapped_dek,
        h.key.nonce.as_slice(),
        h.key.ciphertext,
        h.public_key.as_ref().map(<[u8; 32]>::as_slice),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Retires a live hook against `bound` (`idp.hook.retire`); `false` when none is live.
///
/// # Errors
/// [`StoreError`].
pub async fn retire_hook(t: &mut TenantTx, bound: &Bound, id: &[u8; 16]) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_hooks SET status = 'retired', retired_at = now(), domain_id = $4,
                decision_pos = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND hook_id = $3 AND status = 'active'",
        tenant,
        realm,
        uuid(id),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// The live hook at `point` of this realm.
///
/// # Errors
/// [`StoreError`].
pub async fn live_hook(t: &mut TenantTx, point: &str) -> Result<Option<HookRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT hook_id, point, url, on_no_answer, disclose, signing, key_kek_id, key_wrapped_dek,
                key_nonce, key_ciphertext, public_key, status
           FROM access.idp_hooks
          WHERE tenant_id = $1 AND realm_id = $2 AND point = $3 AND status = 'active'",
        tenant,
        realm,
        point,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(HookRow {
            id: *r.hook_id.as_bytes(),
            point: r.point,
            url: r.url,
            on_no_answer: r.on_no_answer,
            disclose: r.disclose,
            signing: r.signing,
            key: sealed(r.key_kek_id, r.key_wrapped_dek, &r.key_nonce, r.key_ciphertext)?,
            public_key: key32(r.public_key)?,
            active: r.status == "active",
        })
    })
    .transpose()
}

/// A webhook registration as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookRow {
    /// Its realm.
    pub realm: [u8; 16],
    /// Its id.
    pub id: [u8; 16],
    /// The tenant's HTTPS endpoint.
    pub url: String,
    /// Event names it receives.
    pub events: Vec<String>,
    /// `ed25519` or `hmac`.
    pub signing: String,
    /// Whether it is live.
    pub active: bool,
}

/// One signing key of a webhook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookKeyRow {
    /// Its id.
    pub id: [u8; 16],
    /// `ed25519` or `hmac`.
    pub signing: String,
    /// The key, sealed.
    pub key: SealedKey,
    /// The Ed25519 public key.
    pub public_key: Option<[u8; 32]>,
    /// The end of its validity after a rotation, Unix ms; `None` for the current key.
    pub not_after_ms: Option<u64>,
}

/// Registers a webhook with its first key against `bound` (`idp.webhook.register`).
///
/// # Errors
/// [`StoreError`].
pub async fn insert_webhook(
    t: &mut TenantTx,
    bound: &Bound,
    w: &WebhookRow,
    key: &WebhookKeyRow,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_webhooks
            (tenant_id, realm_id, webhook_id, url, events, signing, domain_id, decision_pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        tenant,
        realm,
        uuid(&w.id),
        w.url,
        &w.events,
        w.signing,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    insert_key(t, bound, &w.id, key).await
}

async fn insert_key(
    t: &mut TenantTx,
    bound: &Bound,
    webhook: &[u8; 16],
    k: &WebhookKeyRow,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_webhook_keys
            (tenant_id, realm_id, webhook_id, key_id, signing, key_kek_id, key_wrapped_dek,
             key_nonce, key_ciphertext, public_key, domain_id, decision_pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        tenant,
        realm,
        uuid(webhook),
        uuid(&k.id),
        k.signing,
        k.key.kek_id,
        k.key.wrapped_dek,
        k.key.nonce.as_slice(),
        k.key.ciphertext,
        k.public_key.as_ref().map(<[u8; 32]>::as_slice),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Replaces a live webhook's URL and events against `bound` (`idp.webhook.update`); with
/// `rotate`, the current key stays valid until `old_until_ms` and `rotate` becomes current.
/// `false` when no such live webhook exists.
///
/// # Errors
/// [`StoreError`].
pub async fn update_webhook(
    t: &mut TenantTx,
    bound: &Bound,
    w: &WebhookRow,
    rotate: Option<(&WebhookKeyRow, u64)>,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_webhooks SET url = $4, events = $5, domain_id = $6, decision_pos = $7,
                updated_at = now()
          WHERE tenant_id = $1 AND realm_id = $2 AND webhook_id = $3 AND status = 'active'",
        tenant,
        realm,
        uuid(&w.id),
        w.url,
        &w.events,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    if done != 1 {
        return Ok(false);
    }
    if let Some((key, old_until_ms)) = rotate {
        sqlx::query!(
            "UPDATE access.idp_webhook_keys
                SET not_after = to_timestamp($4::bigint / 1000.0), domain_id = $5, decision_pos = $6
              WHERE tenant_id = $1 AND realm_id = $2 AND webhook_id = $3 AND not_after IS NULL",
            tenant,
            realm,
            uuid(&w.id),
            ms(old_until_ms)?,
            bound.domain.as_bytes().as_slice(),
            bound.position,
        )
        .execute(&mut *t.tx)
        .await?;
        insert_key(t, bound, &w.id, key).await?;
    }
    Ok(true)
}

/// Retires a live webhook against `bound` (`idp.webhook.retire`); its pending deliveries end
/// `failed` as `retired` when the courier reaches them. `false` when none is live.
///
/// # Errors
/// [`StoreError`].
pub async fn retire_webhook(
    t: &mut TenantTx,
    bound: &Bound,
    id: &[u8; 16],
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_webhooks SET status = 'retired', retired_at = now(), domain_id = $4,
                decision_pos = $5, updated_at = now()
          WHERE tenant_id = $1 AND realm_id = $2 AND webhook_id = $3 AND status = 'active'",
        tenant,
        realm,
        uuid(id),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// One webhook of this realm, live or retired.
///
/// # Errors
/// [`StoreError`].
pub async fn webhook(t: &mut TenantTx, id: &[u8; 16]) -> Result<Option<WebhookRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT realm_id, webhook_id, url, events, signing, status FROM access.idp_webhooks
          WHERE tenant_id = $1 AND realm_id = $2 AND webhook_id = $3",
        tenant,
        realm,
        uuid(id),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(row.map(|r| WebhookRow {
        realm: *r.realm_id.as_bytes(),
        id: *r.webhook_id.as_bytes(),
        url: r.url,
        events: r.events,
        signing: r.signing,
        active: r.status == "active",
    }))
}

/// The keys of a webhook valid at `now_ms`: the current one and a rotated one in its overlap.
///
/// # Errors
/// [`StoreError`].
pub async fn webhook_keys(
    t: &mut TenantTx,
    id: &[u8; 16],
    now_ms: u64,
) -> Result<Vec<WebhookKeyRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        r#"SELECT key_id, signing, key_kek_id, key_wrapped_dek, key_nonce, key_ciphertext,
                  public_key, (extract(epoch FROM not_after) * 1000)::bigint AS not_after_ms
             FROM access.idp_webhook_keys
            WHERE tenant_id = $1 AND realm_id = $2 AND webhook_id = $3
              AND (not_after IS NULL OR not_after > to_timestamp($4::bigint / 1000.0))
            ORDER BY not_after NULLS FIRST, created_at DESC"#,
        tenant,
        realm,
        uuid(id),
        ms(now_ms)?,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(WebhookKeyRow {
                id: *r.key_id.as_bytes(),
                signing: r.signing,
                key: sealed(r.key_kek_id, r.key_wrapped_dek, &r.key_nonce, r.key_ciphertext)?,
                public_key: key32(r.public_key)?,
                not_after_ms: r
                    .not_after_ms
                    .map(|v| u64::try_from(v).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
            })
        })
        .collect()
}

/// The live webhooks of this tenant, every realm.
///
/// # Errors
/// [`StoreError`].
pub async fn live_webhooks(t: &mut TenantTx) -> Result<Vec<WebhookRow>, StoreError> {
    let rows = sqlx::query!(
        "SELECT realm_id, webhook_id, url, events, signing FROM access.idp_webhooks
          WHERE tenant_id = $1 AND status = 'active'
          ORDER BY realm_id, webhook_id",
        uuid(t.tenant.as_bytes()),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| WebhookRow {
            realm: *r.realm_id.as_bytes(),
            id: *r.webhook_id.as_bytes(),
            url: r.url,
            events: r.events,
            signing: r.signing,
            active: true,
        })
        .collect())
}

/// One queued webhook delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookDelivery {
    /// Realm.
    pub realm: [u8; 16],
    /// Webhook.
    pub webhook: [u8; 16],
    /// The event id: the dedup key and `webhook-id`.
    pub event_id: String,
    /// Event type URN.
    pub event_type: String,
    /// The unsigned event.
    pub payload: Vec<u8>,
    /// When the event happened, Unix ms.
    pub occurred_ms: u64,
    /// When it was queued, Unix ms.
    pub queued_ms: u64,
    /// Attempts so far.
    pub attempts: u32,
    /// `pending`, `delivered`, `exhausted` or `failed`.
    pub state: String,
}

/// What became of one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt<'a> {
    /// `delivered`, `retry`, `exhausted` or `failed`.
    pub outcome: &'a str,
    /// The receiver's status, when it answered.
    pub status: Option<u16>,
    /// How long the exchange took, ms, when it was sent.
    pub latency_ms: Option<u32>,
    /// Why it was not delivered: `status`, `unreachable`, `refused`, `retired` or `unsigned`.
    pub reason: Option<&'a str>,
    /// The next attempt for a retry, Unix ms.
    pub retry_at_ms: Option<u64>,
}

impl TenantTx {
    /// Queues one event for one webhook, due at `due_ms`; `false` when it is already queued.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn enqueue_webhook(
        &mut self,
        d: &WebhookDelivery,
        due_ms: u64,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "INSERT INTO access.idp_webhook_deliveries
                (tenant_id, realm_id, webhook_id, event_id, event_type, payload, occurred_at,
                 next_attempt_at)
             VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7::bigint / 1000.0),
                     to_timestamp($8::bigint / 1000.0))
             ON CONFLICT (tenant_id, realm_id, webhook_id, event_id) DO NOTHING",
            uuid(self.tenant.as_bytes()),
            uuid(&d.realm),
            uuid(&d.webhook),
            d.event_id,
            d.event_type,
            d.payload,
            ms(d.occurred_ms)?,
            ms(due_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// One webhook delivery of this realm.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn webhook_delivery(
        &mut self,
        webhook: &[u8; 16],
        event_id: &str,
    ) -> Result<Option<WebhookDelivery>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            r#"SELECT event_type, payload, attempts, state,
                      (extract(epoch FROM occurred_at) * 1000)::bigint AS "occurred_ms!",
                      (extract(epoch FROM created_at) * 1000)::bigint AS "queued_ms!"
                 FROM access.idp_webhook_deliveries
                WHERE tenant_id = $1 AND realm_id = $2 AND webhook_id = $3 AND event_id = $4"#,
            tenant,
            realm,
            uuid(webhook),
            event_id,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(WebhookDelivery {
                realm: *realm.as_bytes(),
                webhook: *webhook,
                event_id: String::from(event_id),
                event_type: r.event_type,
                payload: r.payload,
                occurred_ms: u64::try_from(r.occurred_ms).map_err(|_| StoreError::Corrupt)?,
                queued_ms: u64::try_from(r.queued_ms).map_err(|_| StoreError::Corrupt)?,
                attempts: u32::try_from(r.attempts).map_err(|_| StoreError::Corrupt)?,
                state: r.state,
            })
        })
        .transpose()
    }

    /// Records one attempt of a pending delivery and logs it; `false` when it was not pending.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_webhook_attempt(
        &mut self,
        webhook: &[u8; 16],
        event_id: &str,
        a: &Attempt<'_>,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let state = match a.outcome {
            "retry" => "pending",
            other => other,
        };
        let latency = a
            .latency_ms
            .map(|l| i32::try_from(l).map_err(|_| StoreError::Range))
            .transpose()?;
        let retry_at = a.retry_at_ms.map(ms).transpose()?;
        let attempt = sqlx::query_scalar!(
            "UPDATE access.idp_webhook_deliveries
                SET state = $5, attempts = attempts + 1, last_status = $6, last_latency_ms = $7,
                    last_reason = $8,
                    next_attempt_at = coalesce(to_timestamp($9::bigint / 1000.0), next_attempt_at),
                    updated_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND webhook_id = $3 AND event_id = $4
                AND state = 'pending'
          RETURNING attempts",
            tenant,
            realm,
            uuid(webhook),
            event_id,
            state,
            a.status.map(i32::from),
            latency,
            a.reason,
            retry_at,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some(attempt) = attempt else {
            return Ok(false);
        };
        sqlx::query!(
            "INSERT INTO access.idp_webhook_attempts
                (tenant_id, realm_id, webhook_id, event_id, attempt, outcome, status, latency_ms,
                 reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            tenant,
            realm,
            uuid(webhook),
            event_id,
            attempt,
            a.outcome,
            a.status.map(i32::from),
            latency,
            a.reason,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(true)
    }

    /// The attempt log of one delivery, first attempt first: outcome, status and latency.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn webhook_attempts(
        &mut self,
        webhook: &[u8; 16],
        event_id: &str,
    ) -> Result<Vec<(String, Option<u16>, Option<u32>)>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT outcome, status, latency_ms FROM access.idp_webhook_attempts
              WHERE tenant_id = $1 AND realm_id = $2 AND webhook_id = $3 AND event_id = $4
              ORDER BY attempt",
            tenant,
            realm,
            uuid(webhook),
            event_id,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    r.outcome,
                    r.status
                        .map(|s| u16::try_from(s).map_err(|_| StoreError::Corrupt))
                        .transpose()?,
                    r.latency_ms
                        .map(|l| u32::try_from(l).map_err(|_| StoreError::Corrupt))
                        .transpose()?,
                ))
            })
            .collect()
    }
}

/// A due webhook delivery, as the courier finds it across tenants.
#[derive(Clone, PartialEq, Eq)]
pub struct DueWebhook {
    /// Tenant.
    pub tenant: TenantId,
    /// Realm.
    pub realm: RealmId,
    /// Webhook.
    pub webhook: [u8; 16],
    /// Event id.
    pub event_id: String,
}

/// Pending webhook deliveries due at or before `now_ms`, oldest first. Read as
/// `access_outbox_reader`.
///
/// # Errors
/// [`StoreError`].
pub async fn due_webhooks(
    reader: &PgPool,
    now_ms: u64,
    limit: u32,
) -> Result<Vec<DueWebhook>, StoreError> {
    let rows = sqlx::query!(
        "SELECT tenant_id, realm_id, webhook_id, event_id FROM access.idp_webhook_deliveries
          WHERE state = 'pending' AND next_attempt_at <= to_timestamp($1::bigint / 1000.0)
          ORDER BY next_attempt_at, created_at LIMIT $2",
        ms(now_ms)?,
        i64::from(limit),
    )
    .fetch_all(reader)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DueWebhook {
            tenant: TenantId::from_bytes(*r.tenant_id.as_bytes()),
            realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
            webhook: *r.webhook_id.as_bytes(),
            event_id: r.event_id,
        })
        .collect())
}
