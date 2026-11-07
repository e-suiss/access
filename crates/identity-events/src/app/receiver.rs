//! The SSF receiver (TN-42, §9.16.2 k.4, OP-151 m.3 (l)): SETs pushed to
//! `/ssf/inbound/{stream}` (RFC 8935) or polled from transmitters that only offer RFC 8936,
//! each verified against the transmitter `idp.upstream.register` declared, taken once by its
//! `jti`, and turned into Claims or a session end of the subject it names.
//!
//! - An inbound event is a Claim, never authority: it narrows or does nothing, it never revokes
//!   a Grant and it never widens (PI-9, CI-2).
//! - `session-revoked` ends the subject's sessions, dropping their actor binding, and steps its
//!   `session_epoch` (MD-7).
//! - Delivery is best effort: a transmitter that falls silent is shown as delayed, and decisions
//!   keep using declared validity windows (§8.13, L18, INV-24).

use std::collections::BTreeMap;
use std::time::Duration;

use access_identity_account::domain::claims::{
    Bind, ClaimOrder, Content, RISK_SIGNAL, SIGNAL_TTL_MS, account_status,
};
use access_identity_account::domain::signal::{Initiator, Signal};
use access_identity_oauth::app::resolve;
use access_identity_oauth::domain::jwt::parse_jwks;
use access_identity_oauth::ports::Directory;
use access_identity_oauth::ports::oauth::ClientKeys;
use access_kernel::model::EqValue;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::ssf::TransmitterRow;
use access_store::{Pool, tenancy};
use serde_json::{Map, Value, json};

use crate::app::{Db, down};
use crate::domain::inbound::{
    CONTENT_TYPE, Effect, Expect, MAX_SET, Reject, TransmitterConfig, delayed_since, effect,
    subject_digest, verify,
};
use crate::ports::{Clock, PollClient, Sealer, Unavailable};

/// Most SETs one poll asks for (PD).
pub const POLL_BATCH: u32 = 100;

/// Most poll rounds of one transmitter per step (PD).
pub const POLL_ROUNDS: u32 = 10;

/// How often the poll client steps (PD).
pub const POLL_EVERY: Duration = Duration::from_secs(60);

/// What an inbound push is answered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundReply {
    /// `202`.
    Accepted,
    /// `400` with the RFC 8935 error body.
    Refused(Reject),
    /// `404`: no live push transmitter there.
    NotFound,
    /// `413`.
    TooLarge,
    /// `503`.
    Unavailable,
}

/// A transmitter as the management surface shows it (§8.13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransmitterHealth {
    /// Its id.
    pub id: [u8; 16],
    /// Its issuer.
    pub issuer: String,
    /// When it was last heard from, Unix ms.
    pub last_seen_ms: Option<u64>,
    /// Since when it is delayed, Unix ms.
    pub delayed_since_ms: Option<u64>,
}

/// The receiver of every realm.
pub struct Receiver<D, K, S, C> {
    directory: D,
    db: Db,
    keys: K,
    sealer: S,
    clock: C,
}

fn parse_id(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || s.len() != 36 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let pair = hex.get(i.checked_mul(2)?..i.checked_mul(2)?.checked_add(2)?)?;
        *o = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn risk_order(subject: [u8; 16], value: &str, at: u64) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: String::from(RISK_SIGNAL),
        at,
        ttl_ms: SIGNAL_TTL_MS,
        content: Content::Scalar(EqValue::Text(String::from(value))),
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: None,
        retract: false,
    }
}

async fn order(t: &mut TenantTx, o: &ClaimOrder) -> Result<(), Unavailable> {
    let bytes = o.to_bytes().map_err(down)?;
    t.outbox(&o.kind(), &bytes).await.map_err(down)
}

/// What an effect writes, in the transaction that takes the SET (TN-42).
async fn apply(
    t: &mut TenantTx,
    subject: [u8; 16],
    e: Effect,
    now: u64,
) -> Result<(), Unavailable> {
    match e {
        // §9.16.2 k.4, MD-7
        Effect::EndSessions => {
            t.end_sessions(subject).await.map_err(down)?;
            let id = access_identity_account::app::signal::fresh_id().map_err(down)?;
            let s = Signal::session_revoked(id, subject, Initiator::Policy, now);
            access_identity_account::app::signal::emit_tenant(t, &s)
                .await
                .map_err(down)
        }
        // TN-42, CI-2
        Effect::Risk(value) => order(t, &risk_order(subject, value, now)).await,
        Effect::Suspended => order(t, &account_status(subject, "suspended", now)).await,
        Effect::None => Ok(()),
    }
}

impl<D, K, S, C> Receiver<D, K, S, C>
where
    D: Directory,
    K: ClientKeys,
    S: Sealer,
    C: Clock,
{
    /// A receiver over its services.
    pub const fn new(directory: D, db: Db, keys: K, sealer: S, clock: C) -> Self {
        Self {
            directory,
            db,
            keys,
            sealer,
            clock,
        }
    }

    async fn row(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: [u8; 16],
    ) -> Result<Option<TransmitterRow>, Unavailable> {
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let row = t.transmitter(id).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(row.filter(|r| !r.disabled))
    }

    /// An RFC 8935 push to `/ssf/inbound/{stream}` of the realm the request reached.
    pub async fn push(
        &self,
        authority: &str,
        slug: Option<&str>,
        stream: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> InboundReply {
        if body.len() > MAX_SET {
            return InboundReply::TooLarge;
        }
        let realm = match resolve(&self.directory, authority, slug).await {
            Ok(Some(r)) => r,
            Ok(None) => return InboundReply::NotFound,
            Err(_) => return InboundReply::Unavailable,
        };
        let Some(id) = parse_id(stream) else {
            return InboundReply::NotFound;
        };
        let row = match self.row(realm.tenant, realm.realm, id).await {
            Ok(Some(r)) if r.delivery == "push" => r,
            Ok(_) => return InboundReply::NotFound,
            Err(_) => return InboundReply::Unavailable,
        };
        let media = content_type
            .and_then(|c| c.split(';').next())
            .map(str::trim);
        if !media.is_some_and(|m| m.eq_ignore_ascii_case(CONTENT_TYPE)) {
            return InboundReply::Refused(Reject::Request);
        }
        match self.take(realm.tenant, realm.realm, &row, body).await {
            Ok(Ok(())) => InboundReply::Accepted,
            Ok(Err(r)) => InboundReply::Refused(r),
            Err(_) => InboundReply::Unavailable,
        }
    }

    /// Verifies one SET of `row` and takes it once (TN-42): a replayed `jti` is accepted and
    /// does nothing; an event about a subject the realm cannot link does nothing either.
    ///
    /// # Errors
    /// [`Unavailable`]: the keys, the clock or storage failed; nothing was taken.
    pub async fn take(
        &self,
        tenant: TenantId,
        realm: RealmId,
        row: &TransmitterRow,
        token: &[u8],
    ) -> Result<Result<(), Reject>, Unavailable> {
        let doc = self.keys.fetch(&row.jwks_uri).await?;
        let Ok(keys) = parse_jwks(&doc) else {
            return Ok(Err(Reject::Key));
        };
        let now = self.clock.now().map_err(down)?;
        let expect = Expect {
            issuer: &row.issuer,
            audience: &row.audience,
            events: &row.events,
            now_ms: now,
        };
        let set = match verify(token, &keys, &expect) {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let subject = match &set.subject {
            Some((iss, sub)) => t
                .upstream_subject(&subject_digest(iss, sub))
                .await
                .map_err(down)?,
            None => None,
        };
        let e = subject.map_or(Effect::None, |_| effect(set.kind, &set.body));
        let outcome = if e == Effect::None {
            "ignored"
        } else {
            "applied"
        };
        if t.take_inbound(row.id, &set.jti, &set.event_type, outcome)
            .await
            .map_err(down)?
            && let Some(subject) = subject
        {
            apply(&mut t, subject, e, now).await?;
        }
        t.transmitter_seen(row.id, now).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(Ok(()))
    }

    /// One RFC 8936 poll step of a poll transmitter: asks for SETs, takes each, and acknowledges
    /// the taken ones and reports the refused ones in the next request, until the transmitter
    /// has no more. Returns the SETs taken.
    ///
    /// # Errors
    /// [`Unavailable`]; what was taken stays taken and is acknowledged on the next step.
    pub async fn poll_once<P: PollClient>(
        &self,
        client: &P,
        tenant: TenantId,
        realm: RealmId,
        row: &TransmitterRow,
    ) -> Result<u32, Unavailable> {
        let (Some(url), Some(sealed)) = (&row.poll_endpoint, &row.secret) else {
            return Ok(0);
        };
        let credential = self.sealer.open(tenant, realm, &row.id, sealed)?;
        let bearer = core::str::from_utf8(&credential).map_err(down)?;
        let (mut acks, mut errs) = (Vec::<String>::new(), Map::new());
        let mut taken = 0_u32;
        for round in 0..=POLL_ROUNDS {
            let last = round == POLL_ROUNDS;
            let body = json!({
                "ack": acks,
                "setErrs": errs,
                "maxEvents": if last { 0 } else { POLL_BATCH },
                "returnImmediately": true,
            });
            let raw = serde_json::to_vec(&body).map_err(down)?;
            let (status, answer) = client.poll(url, bearer, &raw).await.map_err(down)?;
            if status != 200 {
                return Err(Unavailable);
            }
            (acks, errs) = (Vec::new(), Map::new());
            let v: Value = serde_json::from_slice(&answer).map_err(down)?;
            let sets = v
                .get("sets")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for (jti, token) in &sets {
                let compact = token.as_str().unwrap_or_default();
                match self.take(tenant, realm, row, compact.as_bytes()).await? {
                    Ok(()) => {
                        acks.push(jti.clone());
                        taken = taken.saturating_add(1);
                    }
                    Err(r) => {
                        errs.insert(jti.clone(), r.body());
                    }
                }
            }
            let more = v.get("moreAvailable").and_then(Value::as_bool) == Some(true);
            if last || (!more && acks.is_empty() && errs.is_empty()) {
                break;
            }
        }
        let now = self.clock.now().map_err(down)?;
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        t.transmitter_seen(row.id, now).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(taken)
    }

    /// Polls every live poll transmitter of every live realm once.
    ///
    /// # Errors
    /// [`Unavailable`] when the realms cannot be read; one transmitter's failure is logged and
    /// does not stop the others.
    pub async fn poll_all<P: PollClient>(
        &self,
        client: &P,
        router: &Pool,
    ) -> Result<u32, Unavailable> {
        let mut taken = 0_u32;
        for r in tenancy::routes(router).await.map_err(down)? {
            let mut t = TenantTx::begin(&self.db.app, r.tenant, r.realm)
                .await
                .map_err(down)?;
            let rows = t.transmitters().await.map_err(down)?;
            t.commit().await.map_err(down)?;
            for row in rows.iter().filter(|x| !x.disabled && x.delivery == "poll") {
                if let Ok(n) = self.poll_once(client, r.tenant, r.realm, row).await {
                    taken = taken.saturating_add(n);
                } else {
                    tracing::warn!("ssf transmitter poll failed");
                }
            }
        }
        Ok(taken)
    }

    /// Polls every [`POLL_EVERY`] until `stop` resolves.
    pub async fn run<P: PollClient>(
        &self,
        client: &P,
        router: &Pool,
        stop: &tokio::sync::watch::Receiver<bool>,
    ) {
        let mut stop = stop.clone();
        while !*stop.borrow() {
            if self.poll_all(client, router).await.is_err() {
                tracing::warn!("ssf poll step failed");
            }
            let _ = tokio::time::timeout(POLL_EVERY, stop.changed()).await;
        }
    }

    /// The realm's transmitters with their delay state, for the management surface (§8.13).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn health(
        &self,
        tenant: TenantId,
        realm: RealmId,
    ) -> Result<Vec<TransmitterHealth>, Unavailable> {
        let now = self.clock.now().map_err(down)?;
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let rows = t.transmitters().await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(rows
            .into_iter()
            .filter(|r| !r.disabled)
            .map(|r| TransmitterHealth {
                id: r.id,
                delayed_since_ms: delayed_since(
                    r.last_seen_ms,
                    r.created_ms,
                    r.expected_interval_s,
                    now,
                ),
                issuer: r.issuer,
                last_seen_ms: r.last_seen_ms,
            })
            .collect())
    }
}

/// Declares an inbound transmitter in `t`, as the `idp.upstream.register` Exercise `exercise`
/// carries its SSF fields; a poll transmitter's credential is sealed under the realm KEK.
///
/// # Errors
/// [`Unavailable`].
pub async fn declare<S: Sealer>(
    t: &mut TenantTx,
    sealer: &S,
    id: [u8; 16],
    cfg: &TransmitterConfig,
    poll_credential: Option<&[u8]>,
    exercise: Option<[u8; 32]>,
) -> Result<(), Unavailable> {
    let realm = t.realm().ok_or(Unavailable)?;
    let secret = match (&cfg.poll_endpoint, poll_credential) {
        (Some(_), Some(c)) => Some(sealer.seal(t.tenant(), realm, &id, c)?),
        (None, None) => None,
        _ => return Err(Unavailable),
    };
    let row = TransmitterRow {
        id,
        issuer: cfg.issuer.clone(),
        jwks_uri: cfg.jwks_uri.clone(),
        audience: cfg.audience.clone(),
        events: cfg.events.clone(),
        delivery: String::from(if cfg.poll_endpoint.is_some() {
            "poll"
        } else {
            "push"
        }),
        poll_endpoint: cfg.poll_endpoint.clone(),
        secret,
        expected_interval_s: cfg.expected_interval_s,
        exercise,
        last_seen_ms: None,
        created_ms: 0,
        disabled: false,
    };
    t.register_transmitter(&row).await.map_err(down)
}
