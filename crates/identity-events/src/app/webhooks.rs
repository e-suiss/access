//! Webhooks (TN-136, OP-151 m.3 (i)): registrations written against their `idp.webhook.*`
//! decision, the fan-out from the identity outbox into one delivery per live webhook that asked
//! for the event, and the courier that signs and sends them.
//!
//! - The fan-out has its own cursor ([`CONSUMER`]); it moves only after the deliveries are
//!   stored, and the event id is the dedup key, so no event is lost or doubled (TI-7).
//! - The courier treats every delivery on its own: one failing endpoint never delays the others.
//!   Each attempt is logged with its status and latency, never a body.
//! - Nothing here is an input to a decision (INV-24): stopping the courier changes no outcome.

use std::time::Duration;

use access_crypto::webhook::{WebhookSecret, WebhookSigningKey};
use access_identity_hooks::app::{ShownKey, WriteError, new_key};
use access_identity_hooks::domain::Signing;
use access_identity_hooks::ports::KeyVault;
use access_store::extensions::{
    self as store, Attempt, WebhookDelivery, WebhookKeyRow, WebhookRow,
};
use access_store::identity::{self, RealmId, TenantId, TenantTx};
use access_store::idp::Bound;
use serde_json::Value;

use crate::app::{Db, down, realm_signing};
use crate::domain::catalog::{IdentityEvent, OUTBOX_PREFIX, Ready, urn, uuid};
use crate::domain::set::{CLOUDEVENT_CONTENT_TYPE, cloud_event, set_claims};
use crate::domain::webhook::{
    DELIVERY_TIMEOUT_MS, ROTATION_OVERLAP_MS, WebhookChange, next_attempt,
};
use crate::ports::{Clock, PostError, Transport, Unavailable};

/// The fan-out's cursor name in `access_ops.outbox_cursor`.
pub const CONSUMER: &str = "webhooks";

/// Events read, or deliveries sent, per step (PD).
pub const BATCH: u32 = 100;

/// Idle poll interval (PD).
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// What a written webhook change shows once.
#[derive(Debug)]
pub enum Written {
    /// Registered or rotated: the new key's public key (`whpk_…`) or HMAC secret (`whsec_…`).
    Key(ShownKey),
    /// Updated without a new key, or retired.
    Done,
}

fn key_row(
    vault: &(impl KeyVault + ?Sized),
    t: &TenantTx,
    id: [u8; 16],
    signing: Signing,
) -> Result<(WebhookKeyRow, ShownKey), WriteError> {
    let realm = t.realm().ok_or(WriteError::Unavailable)?;
    let (key, public_key, shown) = new_key(vault, t.tenant(), realm, &id, signing)?;
    Ok((
        WebhookKeyRow {
            id,
            signing: String::from(signing.name()),
            key,
            public_key,
            not_after_ms: None,
        },
        shown,
    ))
}

fn fresh_id() -> Result<[u8; 16], WriteError> {
    access_crypto::random::bytes::<16>().map_err(|_| WriteError::Unavailable)
}

/// Writes a webhook change against the decision `bound` in this transaction (EI-25, MD-14). A
/// registration or a rotation makes a fresh key, sealed; a rotated key stays valid for
/// [`ROTATION_OVERLAP_MS`] after `now_ms`.
///
/// # Errors
/// [`WriteError`]; the caller rolls its transaction back.
pub async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &WebhookChange,
    vault: &(impl KeyVault + ?Sized),
    now_ms: u64,
    allow_private: bool,
) -> Result<Written, WriteError> {
    change
        .check(allow_private)
        .map_err(|i| WriteError::Invalid(access_identity_hooks::domain::Invalid(i.0)))?;
    let realm = *t.realm().ok_or(WriteError::Unavailable)?.as_bytes();
    match change {
        WebhookChange::Register { id, spec } => {
            let (key, shown) = key_row(vault, t, fresh_id()?, spec.signing)?;
            let row = WebhookRow {
                realm,
                id: *id,
                url: spec.url.clone(),
                events: spec.events.clone(),
                signing: String::from(spec.signing.name()),
                active: true,
            };
            store::insert_webhook(t, bound, &row, &key).await?;
            Ok(Written::Key(shown))
        }
        WebhookChange::Update {
            id,
            url,
            events,
            rotate,
        } => {
            let current = store::webhook(t, id)
                .await?
                .filter(|w| w.active)
                .ok_or(WriteError::Conflict)?;
            let signing = Signing::from_name(&current.signing).ok_or(WriteError::Unavailable)?;
            let row = WebhookRow {
                url: url.clone(),
                events: events.clone(),
                ..current
            };
            let (shown, done) = if *rotate {
                let (key, shown) = key_row(vault, t, fresh_id()?, signing)?;
                let until = now_ms.saturating_add(ROTATION_OVERLAP_MS);
                let done = store::update_webhook(t, bound, &row, Some((&key, until))).await?;
                (Some(shown), done)
            } else {
                (None, store::update_webhook(t, bound, &row, None).await?)
            };
            match (done, shown) {
                (false, _) => Err(WriteError::Conflict),
                (true, Some(s)) => Ok(Written::Key(s)),
                (true, None) => Ok(Written::Done),
            }
        }
        WebhookChange::Retire { id } => {
            if store::retire_webhook(t, bound, id).await? {
                Ok(Written::Done)
            } else {
                Err(WriteError::Conflict)
            }
        }
    }
}

/// Turns identity outbox events into webhook deliveries.
pub struct WebhookFanout<C> {
    db: Db,
    clock: C,
}

impl<C: Clock + Send + Sync> WebhookFanout<C> {
    /// A fan-out over `db`.
    pub const fn new(db: Db, clock: C) -> Self {
        Self { db, clock }
    }

    /// Queues the identity outbox past the cursor, up to one batch; returns deliveries queued.
    ///
    /// # Errors
    /// [`Unavailable`]; the cursor has not passed an event whose deliveries are not stored.
    pub async fn step(&self) -> Result<u32, Unavailable> {
        let at = identity::cursor(&self.db.reader, CONSUMER)
            .await
            .map_err(down)?;
        let batch = identity::poll(&self.db.reader, at, BATCH)
            .await
            .map_err(down)?;
        let mut queued = 0_u32;
        for ev in &batch {
            if ev.kind.starts_with(OUTBOX_PREFIX) {
                match IdentityEvent::from_outbox(&ev.kind, &ev.payload) {
                    Ok(e) => {
                        // OP-67 m.1, §17.8.2
                        let span = access_telemetry::trace::consumed(
                            CONSUMER,
                            ev.trace_parent.as_deref(),
                            Some(ev.age_ms),
                        );
                        let ready = e.ready();
                        let n =
                            tracing::Instrument::instrument(self.queue(ev.tenant, &ready), span)
                                .await?;
                        queued = queued.saturating_add(n);
                    }
                    Err(e) => tracing::warn!(error = %e, "identity event unreadable; passed"),
                }
            }
            identity::ack(&self.db.reader, CONSUMER, ev.cursor())
                .await
                .map_err(down)?;
        }
        Ok(queued)
    }

    /// Steps until `stop` resolves, sleeping while idle.
    pub async fn run(&self, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        while !*stop.borrow() {
            let queued = self.step().await.unwrap_or_else(|Unavailable| {
                tracing::warn!("webhook fan-out step failed");
                0
            });
            if queued == 0 {
                let _ = tokio::time::timeout(POLL_INTERVAL, stop.changed()).await;
            }
        }
    }

    /// One delivery per live webhook of `tenant` that asked for the event; an event that names
    /// its realm reaches only that realm's webhooks.
    async fn queue(&self, tenant: TenantId, ready: &Ready) -> Result<u32, Unavailable> {
        let now = self.clock.now().map_err(down)?;
        let event_realm = ready.payload.get("realm").and_then(Value::as_str);
        let mut t = TenantTx::begin_tenant(&self.db.app, tenant)
            .await
            .map_err(down)?;
        let hooks = store::live_webhooks(&mut t).await.map_err(down)?;
        let mut queued = 0_u32;
        let payload = serde_json::to_vec(&ready.payload).map_err(down)?;
        for w in hooks.iter().filter(|w| {
            w.events.iter().any(|n| n == ready.name)
                && event_realm.is_none_or(|r| r == uuid(&w.realm))
        }) {
            let d = WebhookDelivery {
                realm: w.realm,
                webhook: w.id,
                event_id: ready.id.clone(),
                event_type: urn(ready.name),
                payload: payload.clone(),
                occurred_ms: ready.at,
                queued_ms: now,
                attempts: 0,
                state: String::from("pending"),
            };
            if t.enqueue_webhook(&d, now).await.map_err(down)? {
                queued = queued.saturating_add(1);
            }
        }
        t.commit().await.map_err(down)?;
        Ok(queued)
    }
}

/// What one [`WebhookCourier::step`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// Taken by the receiver.
    pub delivered: u32,
    /// To be tried again.
    pub retried: u32,
    /// Given up: exhausted, or the webhook was retired.
    pub ended: u32,
}

enum Sent {
    Reply(u16, u32),
    Unreachable(Option<u32>),
    Refused,
    Retired,
    Unsigned,
}

/// Sends due webhook deliveries.
pub struct WebhookCourier<T, V, C> {
    db: Db,
    transport: T,
    vault: V,
    clock: C,
}

impl<T, V, C> WebhookCourier<T, V, C>
where
    T: Transport,
    V: KeyVault,
    C: Clock + Send + Sync,
{
    /// A courier over its ports.
    pub const fn new(db: Db, transport: T, vault: V, clock: C) -> Self {
        Self {
            db,
            transport,
            vault,
            clock,
        }
    }

    /// Sends what is due, up to one batch, each delivery on its own.
    ///
    /// # Errors
    /// [`Unavailable`] when the queue or the clock cannot be read.
    pub async fn step(&self) -> Result<Step, Unavailable> {
        let now = self.clock.now().map_err(down)?;
        let due = store::due_webhooks(&self.db.reader, now, BATCH)
            .await
            .map_err(down)?;
        let mut step = Step::default();
        for d in due {
            match self
                .deliver(d.tenant, d.realm, &d.webhook, &d.event_id)
                .await
            {
                Ok(Some("delivered")) => step.delivered = step.delivered.saturating_add(1),
                Ok(Some("retry")) => step.retried = step.retried.saturating_add(1),
                Ok(Some(_)) => step.ended = step.ended.saturating_add(1),
                Ok(None) => {}
                Err(Unavailable) => tracing::warn!("webhook delivery not recorded; retried"),
            }
        }
        Ok(step)
    }

    /// Steps until `stop` resolves, sleeping while idle.
    pub async fn run(&self, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        while !*stop.borrow() {
            let busy = self
                .step()
                .await
                .is_ok_and(|s| s.delivered > 0 || s.ended > 0);
            if !busy {
                let _ = tokio::time::timeout(POLL_INTERVAL, stop.changed()).await;
            }
        }
    }

    async fn deliver(
        &self,
        tenant: TenantId,
        realm: RealmId,
        webhook: &[u8; 16],
        event_id: &str,
    ) -> Result<Option<&'static str>, Unavailable> {
        let now = self.clock.now().map_err(down)?;
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let d = t.webhook_delivery(webhook, event_id).await.map_err(down)?;
        let w = store::webhook(&mut t, webhook).await.map_err(down)?;
        let keys = store::webhook_keys(&mut t, webhook, now)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        let (Some(d), Some(w)) = (d, w) else {
            return Ok(None);
        };
        if d.state != "pending" {
            return Ok(None);
        }
        let sent = if w.active {
            self.send(tenant, realm, &w, &d, &keys, now).await
        } else {
            Sent::Retired
        };
        let after = self.clock.now().map_err(down)?;
        let attempt = judge(&sent, &d, after);
        if attempt.outcome == "exhausted" {
            tracing::warn!(
                event = "webhook.exhausted",
                attempts = d.attempts.saturating_add(1),
                reason = attempt.reason.unwrap_or("status"),
                "webhook delivery given up"
            );
        }
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        t.record_webhook_attempt(webhook, event_id, &attempt)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(Some(attempt.outcome))
    }

    async fn send(
        &self,
        tenant: TenantId,
        realm: RealmId,
        w: &WebhookRow,
        d: &WebhookDelivery,
        keys: &[WebhookKeyRow],
        now: u64,
    ) -> Sent {
        let Ok(Some(body)) = self.body(tenant, realm, w, d, now).await else {
            return Sent::Unsigned;
        };
        let ts = now / 1000;
        let mut signatures = Vec::with_capacity(keys.len());
        for k in keys {
            let Ok(raw) = self.vault.open(tenant, realm, &k.id, &k.key) else {
                continue;
            };
            let sig = match Signing::from_name(&k.signing) {
                Some(Signing::Ed25519) => WebhookSigningKey::from_seed(&raw)
                    .ok()
                    .map(|s| s.sign(&d.event_id, ts, &body)),
                Some(Signing::Hmac) => WebhookSecret::from_bytes(raw.to_vec())
                    .ok()
                    .map(|s| s.sign(&d.event_id, ts, &body)),
                None => None,
            };
            signatures.extend(sig);
        }
        if signatures.is_empty() {
            return Sent::Unsigned;
        }
        let headers = vec![
            ("webhook-id", d.event_id.clone()),
            ("webhook-timestamp", ts.to_string()),
            ("webhook-signature", signatures.join(" ")),
        ];
        let start = self.clock.now().unwrap_or(now);
        let answer = tokio::time::timeout(
            Duration::from_millis(DELIVERY_TIMEOUT_MS),
            self.transport
                .post(&w.url, CLOUDEVENT_CONTENT_TYPE, &headers, &body),
        )
        .await;
        let latency = self
            .clock
            .now()
            .ok()
            .map(|end| u32::try_from(end.saturating_sub(start)).unwrap_or(u32::MAX));
        match answer {
            Ok(Ok(r)) => Sent::Reply(r.status, latency.unwrap_or(0)),
            Ok(Err(PostError::Refused)) => Sent::Refused,
            Ok(Err(PostError::Unreachable)) | Err(_) => Sent::Unreachable(latency),
        }
    }

    /// The signed body: the event's SET claims (`aud` the webhook) as the `data` of a structured
    /// `CloudEvent`, the same envelope every Suiss webhook carries (E42).
    async fn body(
        &self,
        tenant: TenantId,
        realm: RealmId,
        w: &WebhookRow,
        d: &WebhookDelivery,
        now: u64,
    ) -> Result<Option<Vec<u8>>, Unavailable> {
        let Some((issuer, _)) = realm_signing(&self.db.app, tenant, realm).await? else {
            return Ok(None);
        };
        let Some(name) = crate::domain::catalog::name_of(&d.event_type) else {
            return Ok(None);
        };
        let payload: Value = serde_json::from_slice(&d.payload).map_err(down)?;
        let ready = Ready {
            id: d.event_id.clone(),
            name,
            at: d.occurred_ms,
            sub_id: subject(&payload),
            payload,
        };
        let claims = set_claims(&ready, issuer.as_str(), &uuid(&w.id), now / 1000);
        let external = self.db.tenant(tenant)?;
        cloud_event(&claims, &external, realm.as_bytes(), d.occurred_ms)
            .map(Some)
            .map_err(down)
    }
}

fn subject(p: &Value) -> String {
    [
        "account",
        "agent",
        "client_id",
        "organization",
        "tenant",
        "realm",
    ]
    .into_iter()
    .find_map(|k| p.get(k).and_then(Value::as_str))
    .map(String::from)
    .unwrap_or_default()
}

/// What an attempt's result records: `2xx` is delivered; a retired webhook or a delivery that
/// cannot be signed ends `failed`; anything else is retried until the schedule gives up.
fn judge(sent: &Sent, d: &WebhookDelivery, now: u64) -> Attempt<'static> {
    let retry =
        |status: Option<u16>, latency_ms: Option<u32>, reason: &'static str| match next_attempt(
            d.attempts.saturating_add(1),
            d.queued_ms,
            now,
        ) {
            Some(at) => Attempt {
                outcome: "retry",
                status,
                latency_ms,
                reason: Some(reason),
                retry_at_ms: Some(at),
            },
            None => Attempt {
                outcome: "exhausted",
                status,
                latency_ms,
                reason: Some(reason),
                retry_at_ms: None,
            },
        };
    match sent {
        Sent::Reply(status, latency) if (200..=299).contains(status) => Attempt {
            outcome: "delivered",
            status: Some(*status),
            latency_ms: Some(*latency),
            reason: None,
            retry_at_ms: None,
        },
        Sent::Reply(status, latency) => retry(Some(*status), Some(*latency), "status"),
        Sent::Unreachable(latency) => retry(None, *latency, "unreachable"),
        Sent::Refused => retry(None, None, "refused"),
        Sent::Unsigned => retry(None, None, "unsigned"),
        Sent::Retired => Attempt {
            outcome: "failed",
            status: None,
            latency_ms: None,
            reason: Some("retired"),
            retry_at_ms: None,
        },
    }
}
