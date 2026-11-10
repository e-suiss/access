//! The courier: the outbox consumer that hands Relay messages to Relay (OP-131, E42 m.5).
//!
//! - It reads `identity_outbox` in `(xid, id)` order past its own cursor `relay` and moves
//!   the cursor only after Relay took an event, so delivery is at least once; Relay
//!   deduplicates by the `CloudEvents` id (`Idempotency-Key`).
//! - A transient failure stops the courier at that event and it waits with backoff: later
//!   events are not sent first, so a subject's messages keep their order, and nothing is
//!   dropped while Relay is down.
//! - An event that can never be delivered (unreadable, shredded subject, expired, refused by
//!   Relay) is recorded in `relay_undelivered` and passed; its outbox row stays (OP-73).
//! - Other outbox kinds belong to other consumers and are passed.
//! - Only the node holding the courier lease sends, and the cursor moves only under the
//!   lease's epoch (OP-156 m.3 (c), [`lease`](crate::notify::lease)).

use std::sync::Mutex;
use std::time::Duration;

use access_crypto::opaque_id::IdKey;
use access_store::identity::{Cursor, OutboxEvent, RealmId, TenantId};
use access_store::relay::Undelivered;
use suiss_crypto::envelope::Dek;

use crate::app::SUBJECT_PREFIX;
use crate::notify::NotifyError;
use crate::notify::delivery::{Backoff, SendFailure, Undeliverable, cloud_event};
use crate::notify::envelope::{EventId, parse};
use crate::notify::lease::{RETRY, TTL, Term};
use crate::notify::message::KIND_PREFIX;
use crate::notify::ports::{CourierStore, RealmKeys, RelayPort, SubjectKey};
use crate::ports::Clock;

/// The courier's cursor name in `access_ops.outbox_cursor`.
pub const CONSUMER: &str = "relay";

/// Outbox events read per poll (PD).
pub const BATCH: u32 = 100;

/// Idle poll interval (OP-20, PD).
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// What one [`Courier::step`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// Events Relay took.
    pub delivered: u32,
    /// Events recorded as undeliverable.
    pub undelivered: u32,
    /// Events of other consumers.
    pub skipped: u32,
    /// Set when Relay failed transiently: wait this long, then step again.
    pub wait_ms: Option<u64>,
    /// Set when the lease's term ended before the batch did: renew before stepping again.
    pub lapsed: bool,
}

enum Outcome {
    Delivered,
    Skipped,
    Undeliverable(Option<EventId>, [u8; 16], [u8; 16], Undeliverable),
    Retry(Option<u64>),
}

/// The outbox → Relay consumer.
pub struct Courier<S, R, K, C> {
    store: S,
    relay: R,
    keys: K,
    clock: C,
    ids: IdKey,
    backoff: Backoff,
    failures: Mutex<(Cursor, u32)>,
}

impl<S, R, K, C> Courier<S, R, K, C>
where
    S: CourierStore,
    R: RelayPort,
    K: RealmKeys,
    C: Clock,
{
    /// A courier; `ids` forms external subject ids (OP-137).
    pub fn new(store: S, relay: R, keys: K, clock: C, ids: IdKey, backoff: Backoff) -> Self {
        Self {
            store,
            relay,
            keys,
            clock,
            ids,
            backoff,
            failures: Mutex::new((Cursor::default(), 0)),
        }
    }

    /// The port to Relay.
    pub const fn relay(&self) -> &R {
        &self.relay
    }

    /// The storage port.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Takes or renews the courier lease for `holder`.
    ///
    /// # Errors
    /// [`NotifyError`] when storage fails.
    pub async fn hold(
        &self,
        holder: &str,
        ttl: std::time::Duration,
    ) -> Result<Option<Term>, NotifyError> {
        let asked = self.clock.now_ms();
        Ok(self
            .store
            .lease(holder, ttl)
            .await?
            .map(|l| Term::new(l, asked, ttl)))
    }

    /// Delivers what the outbox holds past the cursor, up to one batch, under `term`. It stops
    /// before the next send once the term has ended.
    ///
    /// # Errors
    /// [`NotifyError::LeaseLost`] when another node took the lease; [`NotifyError`] when
    /// storage fails. The cursor has not passed an undelivered event.
    pub async fn step(&self, term: &Term) -> Result<Step, NotifyError> {
        let at = self.store.cursor().await?;
        let batch = self.store.poll(at, BATCH).await?;
        let mut step = Step::default();
        for event in &batch {
            if !term.live(self.clock.now_ms()) {
                step.lapsed = true;
                return Ok(step);
            }
            // OP-67 m.1, §17.8.2
            let span = access_telemetry::trace::consumed(
                CONSUMER,
                event.trace_parent.as_deref(),
                Some(event.age_ms),
            );
            match tracing::Instrument::instrument(self.deliver(event), span).await? {
                Outcome::Delivered => step.delivered = step.delivered.saturating_add(1),
                Outcome::Skipped => step.skipped = step.skipped.saturating_add(1),
                Outcome::Undeliverable(id, tenant, realm, why) => {
                    self.record(event, id, tenant, realm, why).await?;
                    step.undelivered = step.undelivered.saturating_add(1);
                }
                Outcome::Retry(retry_after_ms) => {
                    step.wait_ms = Some(self.failed(event.cursor(), retry_after_ms));
                    return Ok(step);
                }
            }
            self.store.ack(&term.lease, event.cursor()).await?;
        }
        Ok(step)
    }

    /// Steps as `holder` until `stop` resolves: only while it holds the courier lease, which it
    /// renews when half of [`TTL`] is left and gives up when it stops. Without the lease it asks
    /// again every [`RETRY`].
    pub async fn run(&self, holder: &str, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        let mut term: Option<Term> = None;
        while !*stop.borrow() {
            if term
                .as_ref()
                .is_none_or(|t| t.due(self.clock.now_ms(), TTL))
            {
                term = match self.hold(holder, TTL).await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(error = %e, "relay courier lease failed");
                        None
                    }
                };
            }
            let wait = match &term {
                None => RETRY,
                Some(t) => match self.step(t).await {
                    Ok(Step {
                        wait_ms: Some(ms), ..
                    }) => Duration::from_millis(ms),
                    Ok(Step { lapsed: true, .. }) => Duration::ZERO,
                    Ok(s) if s.delivered > 0 || s.undelivered > 0 || s.skipped > 0 => {
                        Duration::ZERO
                    }
                    Ok(_) => POLL_INTERVAL,
                    Err(NotifyError::LeaseLost) => {
                        tracing::warn!("relay courier lease lost; another node sends");
                        term = None;
                        RETRY
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "relay courier step failed");
                        Duration::from_millis(self.backoff.base_ms)
                    }
                },
            };
            if !wait.is_zero() {
                let _ = tokio::time::timeout(wait, stop.changed()).await;
            }
        }
        if let Some(t) = term
            && let Err(e) = self.store.release(&t.lease).await
        {
            tracing::warn!(error = %e, "relay courier lease release failed");
        }
    }

    /// The age in ms of the oldest message waiting for Relay; `None` when none waits.
    ///
    /// # Errors
    /// [`NotifyError`] when storage fails.
    pub async fn lag_ms(&self) -> Result<Option<u64>, NotifyError> {
        self.store.lag_ms().await
    }

    fn failed(&self, at: Cursor, retry_after_ms: Option<u64>) -> u64 {
        let mut f = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if f.0 == at {
            f.1 = f.1.saturating_add(1);
        } else {
            *f = (at, 1);
        }
        self.backoff.wait_ms(f.1, retry_after_ms)
    }

    async fn record(
        &self,
        event: &OutboxEvent,
        id: Option<EventId>,
        tenant: [u8; 16],
        realm: [u8; 16],
        why: Undeliverable,
    ) -> Result<(), NotifyError> {
        tracing::warn!(kind = %event.kind, reason = why.reason(), "relay message undeliverable");
        let Some(id) = id else {
            return Ok(());
        };
        self.store
            .undelivered(
                TenantId::from_bytes(tenant),
                RealmId::from_bytes(realm),
                &Undelivered {
                    event_id: id.0,
                    at: event.cursor(),
                    kind: &event.kind,
                    reason: why.reason(),
                    relay_status: why.relay_status(),
                },
            )
            .await
    }

    async fn deliver(&self, event: &OutboxEvent) -> Result<Outcome, NotifyError> {
        if !event.kind.starts_with(KIND_PREFIX) {
            return Ok(Outcome::Skipped);
        }
        let Ok(env) = parse(&event.payload) else {
            return Ok(Outcome::Undeliverable(
                None,
                [0; 16],
                [0; 16],
                Undeliverable::Malformed,
            ));
        };
        let h = env.header;
        let gone = |why| {
            Ok(Outcome::Undeliverable(
                Some(h.event),
                h.tenant,
                h.realm,
                why,
            ))
        };
        let tenant = TenantId::from_bytes(h.tenant);
        let realm = RealmId::from_bytes(h.realm);
        let (kek_id, wrapped) = match self.store.subject_key(tenant, realm, h.subject).await? {
            SubjectKey::Missing => return gone(Undeliverable::NoSubject),
            SubjectKey::Shredded => return gone(Undeliverable::Shredded),
            SubjectKey::Wrapped { kek_id, wrapped } => (kek_id, wrapped),
        };
        let Some(kek) = self.keys.kek(tenant, realm, &kek_id) else {
            tracing::warn!("relay courier: realm key unavailable; the message waits");
            return Ok(Outcome::Retry(None));
        };
        let dek: Dek = match kek.unwrap(&wrapped) {
            Ok(d) => d,
            Err(_) => return gone(Undeliverable::Malformed),
        };
        let Ok(message) = env.open(&event.kind, &dek) else {
            return gone(Undeliverable::Malformed);
        };
        if message
            .body
            .expires_at_ms()
            .is_some_and(|e| self.clock.now_ms() >= e)
        {
            return gone(Undeliverable::Expired);
        }
        let external = self
            .ids
            .encode(SUBJECT_PREFIX, h.subject)
            .map_err(|_| NotifyError::Seal)?;
        let Ok(ce) = cloud_event(&h, &external, &message) else {
            return gone(Undeliverable::Malformed);
        };
        match self.relay.send(&ce).await {
            Ok(()) => Ok(Outcome::Delivered),
            Err(SendFailure::Rejected { status }) => gone(Undeliverable::Rejected { status }),
            Err(SendFailure::Transient { retry_after_ms }) => Ok(Outcome::Retry(retry_after_ms)),
        }
    }
}
