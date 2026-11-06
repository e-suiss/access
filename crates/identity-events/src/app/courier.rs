//! The push courier (OP-149 m.4, m.7): sends due deliveries over their subscription's channel.
//!
//! - Webhook: the stored SET claims as the `data` of a structured `CloudEvent`, signed per
//!   Standard Webhooks with the subscription's secret.
//! - SSF push (RFC 8935): the SET signed with the realm's key when it is sent.
//! - At least once: a delivery stays `pending` until a `2xx`; a transient failure is tried
//!   again with backoff, per delivery, so one dead endpoint delays only its own events. After
//!   [`MAX_ATTEMPTS`] it is `failed` as `unreachable`. A refusal that will not change (a final
//!   status, an endpoint the SSRF guard refuses) fails at once. Rows stay (OP-73).

use std::time::Duration;

use access_crypto::webhook::WebhookSecret;
use access_identity_account::notify::delivery::Backoff;
use access_store::events::{self as store, DeliveryRow, Mark, SubscriptionRow};
use access_store::identity::{RealmId, TenantId, TenantTx};
use serde_json::Value;

use crate::app::{Db, realm_signing};
use crate::domain::set::{CLOUDEVENT_CONTENT_TYPE, SET_CONTENT_TYPE, SET_TYP, cloud_event};
use crate::domain::stream::{Answer, Channel, classify};
use crate::ports::{Clock, PostError, Sealer, TokenSigner, Transport, Unavailable};

/// Deliveries sent per step (PD).
pub const BATCH: u32 = 100;

/// Attempts per delivery before it fails as `unreachable` (PD): about a day with the default
/// backoff ceiling.
pub const MAX_ATTEMPTS: i32 = 16;

/// Idle poll interval (OP-20, PD).
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// What one [`Courier::step`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// Taken by the receiver.
    pub delivered: u32,
    /// To be tried again.
    pub retried: u32,
    /// Given up.
    pub failed: u32,
}

/// Names the failed stage of a step and what failed, then stands for the unavailability (OP-67).
fn fault<E: std::fmt::Debug>(stage: &'static str) -> impl FnOnce(E) -> Unavailable {
    move |e| {
        tracing::warn!(stage, error = ?e, "event courier fault");
        Unavailable
    }
}

/// Names the failed stage of a port that only says it is unavailable.
fn at(stage: &'static str) -> impl FnOnce(Unavailable) -> Unavailable {
    move |Unavailable| {
        tracing::warn!(stage, "event courier fault");
        Unavailable
    }
}

/// The due queue → receiver courier.
pub struct Courier<T, S, K, C> {
    db: Db,
    transport: T,
    signer: S,
    sealer: K,
    clock: C,
    backoff: Backoff,
}

#[derive(Clone, Copy)]
enum Sent {
    Reply(u16, Option<u64>),
    Refused,
    Unreachable,
}

impl<T, S, K, C> Courier<T, S, K, C>
where
    T: Transport,
    S: TokenSigner,
    K: Sealer,
    C: Clock + Send + Sync,
{
    /// A courier over its ports.
    pub const fn new(
        db: Db,
        transport: T,
        signer: S,
        sealer: K,
        clock: C,
        backoff: Backoff,
    ) -> Self {
        Self {
            db,
            transport,
            signer,
            sealer,
            clock,
            backoff,
        }
    }

    /// Sends what is due, up to one batch.
    ///
    /// # Errors
    /// [`Unavailable`] when storage or the clock fails.
    pub async fn step(&self) -> Result<Step, Unavailable> {
        let now = self.clock.now().map_err(fault("clock"))?;
        let due = store::due(&self.db.reader, now, BATCH)
            .await
            .map_err(fault("due"))?;
        let mut step = Step::default();
        for (d, id) in due {
            match self
                .deliver(d.tenant, d.realm, d.subscription, &id, now)
                .await?
            {
                Some(Mark::Delivered { .. }) => step.delivered = step.delivered.saturating_add(1),
                Some(Mark::Retry { .. }) => step.retried = step.retried.saturating_add(1),
                Some(Mark::Failed { .. }) => step.failed = step.failed.saturating_add(1),
                None => {}
            }
        }
        Ok(step)
    }

    /// Steps until `stop` resolves, sleeping while idle.
    pub async fn run(&self, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        while !*stop.borrow() {
            let wait = match self.step().await {
                Ok(s) if s.delivered > 0 || s.failed > 0 => Duration::ZERO,
                Ok(_) => POLL_INTERVAL,
                Err(Unavailable) => {
                    tracing::warn!("event courier step failed; the fault above names the stage");
                    Duration::from_millis(self.backoff.base_ms)
                }
            };
            if !wait.is_zero() {
                let _ = tokio::time::timeout(wait, stop.changed()).await;
            }
        }
    }

    async fn deliver(
        &self,
        tenant: TenantId,
        realm: RealmId,
        sub: [u8; 16],
        id: &str,
        now: u64,
    ) -> Result<Option<Mark<'static>>, Unavailable> {
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(fault("begin"))?;
        let row = t.delivery(realm, sub, id).await.map_err(fault("read"))?;
        let s = t.subscription(realm, sub).await.map_err(fault("read"))?;
        t.commit().await.map_err(fault("read"))?;
        let (Some(row), Some(s)) = (row, s) else {
            return Ok(None);
        };
        let mark = if s.disabled {
            Mark::Failed {
                reason: "receiver",
                status: None,
            }
        } else if s.status == "paused" {
            Mark::Retry {
                retry_at_ms: now.saturating_add(self.backoff.max_ms),
                status: None,
            }
        } else {
            // OP-149 m.4 at-least-once: a delivery that cannot be built or signed now is this
            // delivery's transient failure, not the batch's; the others are still sent
            let sent = self
                .send(tenant, realm, &row, &s, now)
                .await
                .unwrap_or_else(|Unavailable| {
                    tracing::warn!(
                        realm = %uuid_text(realm.as_bytes()),
                        subscription = %hex(&sub),
                        channel = %s.channel,
                        delivery = %id,
                        "event delivery could not be built or signed; retried with backoff"
                    );
                    Sent::Unreachable
                });
            self.judge(sent, row.attempts, now)
        };
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(fault("begin"))?;
        t.mark_delivery(realm, sub, id, mark)
            .await
            .map_err(fault("mark"))?;
        t.commit().await.map_err(fault("mark"))?;
        Ok(Some(mark))
    }

    fn judge(&self, sent: Sent, attempts: i32, now: u64) -> Mark<'static> {
        let tries = attempts.saturating_add(1);
        let retry = |status: Option<u16>, after: Option<u64>| {
            if tries >= MAX_ATTEMPTS {
                Mark::Failed {
                    reason: "unreachable",
                    status,
                }
            } else {
                let wait = self
                    .backoff
                    .wait_ms(u32::try_from(tries).unwrap_or(u32::MAX), after);
                Mark::Retry {
                    retry_at_ms: now.saturating_add(wait),
                    status,
                }
            }
        };
        match sent {
            Sent::Reply(status, after) => match classify(status, after) {
                Answer::Delivered => Mark::Delivered { status },
                Answer::Transient { retry_after_ms } => retry(Some(status), retry_after_ms),
                Answer::Rejected => Mark::Failed {
                    reason: "rejected",
                    status: Some(status),
                },
            },
            Sent::Refused => Mark::Failed {
                reason: "refused",
                status: None,
            },
            Sent::Unreachable => retry(None, None),
        }
    }

    /// Builds the request of the subscription's channel and posts it.
    async fn send(
        &self,
        tenant: TenantId,
        realm: RealmId,
        row: &DeliveryRow,
        s: &SubscriptionRow,
        now: u64,
    ) -> Result<Sent, Unavailable> {
        let Some(endpoint) = s.endpoint.as_deref() else {
            return Ok(Sent::Refused);
        };
        let (content_type, headers, body) = match Channel::from_name(&s.channel) {
            Some(Channel::Webhook) => {
                let sealed = s.secret.as_ref().ok_or(Unavailable).map_err(at("secret"))?;
                let raw = self
                    .sealer
                    .open(tenant, realm, &s.id, sealed)
                    .map_err(at("unseal"))?;
                let secret = WebhookSecret::from_bytes(raw.to_vec()).map_err(fault("secret"))?;
                let claims: Value =
                    serde_json::from_slice(&row.payload).map_err(fault("payload"))?;
                let occurred = u64::try_from(row.occurred_ms).map_err(fault("payload"))?;
                let external = self.db.tenant(tenant).map_err(at("tenant-id"))?;
                let body = cloud_event(&claims, &external, realm.as_bytes(), occurred)
                    .map_err(fault("cloud-event"))?;
                let ts = now / 1000;
                let signature = secret.sign(&row.event_id, ts, &body);
                (
                    CLOUDEVENT_CONTENT_TYPE,
                    vec![
                        ("webhook-id", row.event_id.clone()),
                        ("webhook-timestamp", ts.to_string()),
                        ("webhook-signature", signature),
                    ],
                    body,
                )
            }
            Some(Channel::SsfPush) => {
                let Some((_, alg)) = realm_signing(&self.db.app, tenant, realm)
                    .await
                    .map_err(at("realm"))?
                else {
                    return Ok(Sent::Unreachable);
                };
                let token = self
                    .signer
                    .sign(realm, alg, SET_TYP, &row.payload, now)
                    .await
                    .map_err(at("sign"))?;
                (
                    SET_CONTENT_TYPE,
                    vec![("Accept", String::from("application/json"))],
                    token.into_bytes(),
                )
            }
            Some(Channel::SsfPoll) | None => return Ok(Sent::Refused),
        };
        Ok(
            match self
                .transport
                .post(endpoint, content_type, &headers, &body)
                .await
            {
                Ok(r) => Sent::Reply(r.status, r.retry_after_ms),
                Err(PostError::Refused) => Sent::Refused,
                Err(PostError::Unreachable) => Sent::Unreachable,
            },
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn uuid_text(b: &[u8; 16]) -> String {
    let h = hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
