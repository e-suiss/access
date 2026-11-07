//! The back-channel logout courier (OIDC Back-Channel Logout 1.0, §10.4.6, OP-131): the
//! outbox consumer that tells clients a session ended.
//!
//! - A session that ends, by RP-initiated logout, sign-out or a `session_epoch` step, revokes
//!   its grants and queues one notice in the same transaction (G57, TN-50). Revocation does
//!   not rest on delivery (MD-7).
//! - The courier reads `identity_outbox` past its own cursor and moves it only after every
//!   grant of a notice was delivered or recorded, so delivery is at least once.
//! - The logout token is signed when it is sent, so a delay never sends an expired one.
//! - A client that does not answer is tried again with backoff; the other clients of the
//!   notice are not held back. After [`MAX_ATTEMPTS`] the grant is recorded as
//!   `unreachable` and the courier goes on, so one dead endpoint cannot stop logout for every
//!   realm.
//! - A refusal that will not change (`4xx`, `501`, an endpoint the SSRF guard refuses, a grant
//!   or client that is gone) is recorded once and passed; the outbox row stays (OP-73).

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use access_identity_account::notify::delivery::Backoff;
use access_kernel::json::b64url_encode;
use access_store::backchannel::{LogoutUndelivered, logout_grants};
use access_store::identity::{Cursor, OutboxEvent};

use crate::domain::client::Client;
use crate::domain::tokens::{LOGOUT_OUTBOX, LOGOUT_TYP, logout_token_claims};
use crate::ports::Unavailable;
use crate::ports::dpop::Clock;
use crate::ports::oauth::{
    LogoutDelivery, LogoutQueue, OAuthDb, OAuthTx, PostFailure, Random, TokenSigner,
};

/// The courier's cursor name in `access_ops.outbox_cursor`.
pub const CONSUMER: &str = "backchannel";

/// Outbox events read per poll (PD).
pub const BATCH: u32 = 100;

/// Attempts per grant before it is recorded as `unreachable` (PD): with the default backoff
/// about four minutes.
pub const MAX_ATTEMPTS: u32 = 8;

/// Idle poll interval (OP-20, PD).
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// What one [`Courier::step`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// Logout tokens a client took.
    pub delivered: u32,
    /// Grants recorded as undelivered.
    pub undelivered: u32,
    /// Events of other consumers.
    pub skipped: u32,
    /// Set when a client failed transiently: wait this long, then step again.
    pub wait_ms: Option<u64>,
}

/// Where the courier stands within the notice it is working on.
#[derive(Default)]
struct Progress {
    at: Cursor,
    attempts: u32,
    done: BTreeSet<[u8; 16]>,
}

/// What became of one grant.
enum Sent {
    Delivered,
    Passed(&'static str, Option<u16>),
    Retry(Option<u64>),
}

/// The outbox → client back-channel consumer.
pub struct Courier<D, S, R, C, Q, P> {
    db: D,
    signer: S,
    random: R,
    clock: C,
    queue: Q,
    delivery: P,
    backoff: Backoff,
    progress: Mutex<Progress>,
}

impl<D, S, R, C, Q, P> Courier<D, S, R, C, Q, P>
where
    D: OAuthDb,
    S: TokenSigner,
    R: Random,
    C: Clock + Send + Sync,
    Q: LogoutQueue,
    P: LogoutDelivery,
{
    /// A courier over its ports.
    pub fn new(
        db: D,
        signer: S,
        random: R,
        clock: C,
        queue: Q,
        delivery: P,
        backoff: Backoff,
    ) -> Self {
        Self {
            db,
            signer,
            random,
            clock,
            queue,
            delivery,
            backoff,
            progress: Mutex::new(Progress::default()),
        }
    }

    /// The delivery port.
    pub const fn delivery(&self) -> &P {
        &self.delivery
    }

    /// Delivers what the outbox holds past the cursor, up to one batch.
    ///
    /// # Errors
    /// [`Unavailable`] when storage or the signer fails; the cursor has not passed an
    /// undelivered notice.
    pub async fn step(&self) -> Result<Step, Unavailable> {
        let at = self.queue.cursor().await?;
        let batch = self.queue.poll(at, BATCH).await?;
        let mut step = Step::default();
        for event in &batch {
            if event.kind == LOGOUT_OUTBOX {
                // OP-67 m.1, §17.8.2
                let span = access_telemetry::trace::consumed(
                    CONSUMER,
                    event.trace_parent.as_deref(),
                    Some(event.age_ms),
                );
                let noticed =
                    tracing::Instrument::instrument(self.notice(event, &mut step), span).await;
                if let Some(wait) = noticed? {
                    step.wait_ms = Some(wait);
                    return Ok(step);
                }
            } else {
                step.skipped = step.skipped.saturating_add(1);
            }
            self.queue.ack(event.cursor()).await?;
        }
        Ok(step)
    }

    /// Steps until `stop` resolves, sleeping while idle or backing off.
    pub async fn run(&self, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        while !*stop.borrow() {
            let wait = match self.step().await {
                Ok(Step {
                    wait_ms: Some(ms), ..
                }) => Duration::from_millis(ms),
                Ok(s) if s.delivered > 0 || s.undelivered > 0 || s.skipped > 0 => Duration::ZERO,
                Ok(_) => POLL_INTERVAL,
                Err(Unavailable) => {
                    tracing::warn!("back-channel courier step failed");
                    Duration::from_millis(self.backoff.base_ms)
                }
            };
            if !wait.is_zero() {
                let _ = tokio::time::timeout(wait, stop.changed()).await;
            }
        }
    }

    fn progress(&self) -> std::sync::MutexGuard<'_, Progress> {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Works one notice; `Some(wait)` when a grant must be tried again.
    async fn notice(
        &self,
        event: &OutboxEvent,
        step: &mut Step,
    ) -> Result<Option<u64>, Unavailable> {
        let Some(grants) = logout_grants(&event.payload) else {
            tracing::warn!("back-channel notice unreadable; passed");
            return Ok(None);
        };
        let attempts = {
            let mut p = self.progress();
            if p.at != event.cursor() {
                *p = Progress {
                    at: event.cursor(),
                    ..Progress::default()
                };
            }
            p.attempts = p.attempts.saturating_add(1);
            p.attempts
        };
        let mut retry: Option<Option<u64>> = None;
        for grant in grants {
            if self.progress().done.contains(&grant) {
                continue;
            }
            let outcome = match self.send(event, grant).await? {
                Sent::Retry(_) if attempts >= MAX_ATTEMPTS => Sent::Passed("unreachable", None),
                other => other,
            };
            match outcome {
                Sent::Delivered => step.delivered = step.delivered.saturating_add(1),
                Sent::Passed(reason, status) => {
                    tracing::warn!(reason, "back-channel logout undelivered");
                    let record = LogoutUndelivered {
                        grant,
                        at: event.cursor(),
                        reason,
                        client_status: status,
                    };
                    self.queue
                        .undelivered(event.tenant, event.realm, &record)
                        .await?;
                    step.undelivered = step.undelivered.saturating_add(1);
                }
                Sent::Retry(after) => {
                    retry = Some(retry.flatten().max(after));
                    continue;
                }
            }
            self.progress().done.insert(grant);
        }
        Ok(retry.map(|after| self.backoff.wait_ms(attempts, after)))
    }

    /// Signs a fresh logout token for `grant` and posts it to its client.
    async fn send(&self, event: &OutboxEvent, grant: [u8; 16]) -> Result<Sent, Unavailable> {
        let now = self.clock.now().map_err(|_| Unavailable)?;
        let mut tx = self.db.begin(event.tenant, event.realm).await?;
        let Some(g) = tx.grant(grant).await? else {
            tx.commit().await?;
            return Ok(Sent::Passed("missing", None));
        };
        let client = tx
            .client_by_uuid(g.client)
            .await?
            .and_then(Client::from_row);
        let issuer = tx.issuer().await?;
        let (Some(client), Some(issuer)) = (client, issuer) else {
            tx.commit().await?;
            return Ok(Sent::Passed("missing", None));
        };
        let Some(uri) = client.backchannel_logout_uri.clone() else {
            tx.commit().await?;
            return Ok(Sent::Passed("missing", None));
        };
        let alg = tx.jose_alg().await?;
        let mut candidate = [0_u8; 32];
        self.random.fill(&mut candidate)?;
        let sub = tx
            .pairwise(g.subject, client.sector(), &b64url_encode(&candidate))
            .await?;
        tx.commit().await?;
        let mut jti = [0_u8; 16];
        self.random.fill(&mut jti)?;
        let claims = logout_token_claims(
            &issuer,
            &client.id,
            &sub,
            &b64url_encode(&g.sid),
            &b64url_encode(&jti),
            now,
        );
        let token = self
            .signer
            .sign(event.realm, alg, LOGOUT_TYP, &claims, now)
            .await?;
        Ok(match self.delivery.post(&uri, &token).await {
            Ok(()) => Sent::Delivered,
            Err(PostFailure::Rejected { status }) => Sent::Passed("rejected", Some(status)),
            Err(PostFailure::Refused) => Sent::Passed("refused", None),
            Err(PostFailure::Transient { retry_after_ms }) => Sent::Retry(retry_after_ms),
        })
    }
}
