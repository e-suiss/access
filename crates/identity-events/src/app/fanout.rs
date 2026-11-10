//! The fan-out (OP-149 m.4, m.7): each event of the identity outbox and of a domain's
//! authority outbox becomes one unsigned SET per live subscription of its tenant that asked for
//! its type. The cursor moves only after the deliveries are stored, and a repeated step stores
//! nothing twice (the event id is the key), so no event is lost or doubled. [`Fanout::run`]
//! steps the identity outbox and the outbox of every live realm's governing domain.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use access_internal_api::events::{Event, Kind, POSITION_FIELD, Position, Subject};
use access_store::authority;
use access_store::events::{self as store, DeliveryRow, SubscriptionRow};
use access_store::identity::{self, RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::{Pool, idp, tenancy};

use crate::app::courier::POLL_INTERVAL;
use crate::app::{Db, down, realm_signing};
use access_identity_account::domain::signal::{Initiator, OUTBOX_PREFIX as SIGNAL_PREFIX, Signal};
use access_kernel::json::b64url_decode;
use serde_json::{Value, json};

use crate::domain::catalog::{IdentityEvent, OUTBOX_PREFIX, Ready, authority_ready, urn};
use crate::domain::mapping::{Profile, counterpart, counterpart_body, forms, signal_uri};
use crate::domain::set::{Envelope, derived_id, set_claims, set_tenant, standard_claims};
use crate::ports::{Clock, Unavailable};

/// The fan-out's cursor name in `access_ops.outbox_cursor`.
pub const CONSUMER: &str = "events";

/// Events read per step (PD).
pub const BATCH: u32 = 100;

/// How often [`Fanout::run`] reads the governing domains again (PD).
pub const DOMAINS_REFRESH: Duration = Duration::from_secs(30);

/// Turns outbox events into deliveries.
pub struct Fanout<C> {
    db: Db,
    clock: C,
    wake: Option<std::sync::Arc<tokio::sync::Notify>>,
}

impl<C: Clock + Send + Sync> Fanout<C> {
    /// A fan-out over `db`.
    pub const fn new(db: Db, clock: C) -> Self {
        Self {
            db,
            clock,
            wake: None,
        }
    }

    /// While idle, [`Fanout::run`] also wakes when `wake` is notified: the doorbell (OP-23,
    /// OP-156 m.3 (j)). It still reads from its cursors, and still polls without a ring.
    #[must_use]
    pub fn with_wake(mut self, wake: std::sync::Arc<tokio::sync::Notify>) -> Self {
        self.wake = Some(wake);
        self
    }

    /// Queues the identity outbox past the cursor, up to one batch; returns deliveries queued.
    ///
    /// # Errors
    /// [`Unavailable`]; the cursor has not passed an event whose deliveries are not stored.
    pub async fn identity_step(&self) -> Result<u32, Unavailable> {
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
                        let mut ready = e.ready();
                        // OP-22, OP-156 m.3 (j)
                        position(&mut ready.payload, identity_position(ev));
                        let n =
                            tracing::Instrument::instrument(self.queue(ev.tenant, &ready), span)
                                .await?;
                        queued = queued.saturating_add(n);
                    }
                    Err(e) => tracing::warn!(error = %e, "identity event unreadable; passed"),
                }
            } else if ev.kind.starts_with(SIGNAL_PREFIX) {
                match Signal::from_outbox(&ev.kind, &ev.payload) {
                    Ok(s) => {
                        let n = self
                            .queue_signal(ev.tenant, ev.realm, &s, identity_position(ev))
                            .await?;
                        queued = queued.saturating_add(n);
                    }
                    Err(e) => tracing::warn!(error = %e, "identity signal unreadable; passed"),
                }
            }
            identity::ack(&self.db.reader, CONSUMER, ev.cursor())
                .await
                .map_err(down)?;
        }
        Ok(queued)
    }

    /// Queues `domain`'s authority outbox past its cursor, up to one batch.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn domain_step(&self, domain: &DomainId) -> Result<u32, Unavailable> {
        self.domain_step_in(domain, None).await
    }

    /// [`Fanout::domain_step`]; with the router role, an admitted `party.compromised` first
    /// raises the `session_epoch` of the Party's subject in each realm the domain governs, so
    /// its sessions and identity tokens end (OP-21, §7.9.2.4, OP-150 m.2).
    ///
    /// # Errors
    /// [`Unavailable`]; the cursor has not passed an event whose effects are not stored.
    pub async fn domain_step_in(
        &self,
        domain: &DomainId,
        router: Option<&Pool>,
    ) -> Result<u32, Unavailable> {
        let Some(tenant) = authority::domain_tenant(&self.db.app, domain)
            .await
            .map_err(down)?
        else {
            return Ok(0);
        };
        let tenant = TenantId::from_bytes(tenant);
        let at = store::domain_cursor(&self.db.app, domain)
            .await
            .map_err(down)?;
        let rows = authority::read_outbox(&self.db.app, domain, at, BATCH)
            .await
            .map_err(down)?;
        let mut queued = 0_u32;
        for r in &rows {
            match Event::from_bytes(&r.event) {
                Ok(e) => {
                    if let (Some(router), Kind::PartyCompromised, Subject::Party(p)) =
                        (router, e.kind, e.subject)
                    {
                        self.end_party_sessions(router, tenant, domain, &p.0)
                            .await?;
                    }
                    if let (Some(router), Kind::InstanceTerminated, Subject::Instance(i)) =
                        (router, e.kind, e.subject)
                    {
                        self.device_ended(router, tenant, domain, &i.0, e.at)
                            .await?;
                    }
                    let mut ready = authority_ready(&e, &r.event_id);
                    // OP-22, OP-156 m.3 (j)
                    position(&mut ready.payload, Position::authority(r.pos, r.idx));
                    // OP-67 m.1
                    let span = access_telemetry::trace::consumed(
                        "authority-events",
                        r.trace_parent.as_deref(),
                        None,
                    );
                    let n =
                        tracing::Instrument::instrument(self.queue(tenant, &ready), span).await?;
                    queued = queued.saturating_add(n);
                }
                Err(e) => tracing::warn!(error = %e, "authority event unreadable; passed"),
            }
            store::advance_domain_cursor(&self.db.app, domain, (r.pos, r.idx))
                .await
                .map_err(down)?;
        }
        Ok(queued)
    }

    /// Raises the `session_epoch` of the subject bound to `party` in every live realm of
    /// `tenant` that `domain` governs (OP-21): its login sessions and grants end. Repeating it
    /// only raises the epoch again.
    async fn end_party_sessions(
        &self,
        router: &Pool,
        tenant: TenantId,
        domain: &DomainId,
        party: &[u8; 16],
    ) -> Result<(), Unavailable> {
        for r in tenancy::tenant_routes(router, &[tenant])
            .await
            .map_err(down)?
        {
            let mut t = TenantTx::begin(&self.db.app, r.tenant, r.realm)
                .await
                .map_err(down)?;
            let governed = idp::governance(&mut t)
                .await
                .map_err(down)?
                .is_some_and(|g| g.domain == *domain);
            if governed
                && let Some(subject) = idp::party_subject(&mut t, party).await.map_err(down)?
            {
                t.end_sessions(subject).await.map_err(down)?;
                // TN-41, MD-7
                let at = t.server_time().await.map_err(down)?;
                let id = access_identity_account::app::signal::fresh_id().map_err(down)?;
                let s = Signal::session_revoked(id, subject, Initiator::Policy, at);
                access_identity_account::app::signal::emit_tenant(&mut t, &s)
                    .await
                    .map_err(down)?;
            }
            t.commit().await.map_err(down)?;
        }
        Ok(())
    }

    /// TN-41: the CAEP `device-compliance-change` of a device Instance that ended, in every
    /// live realm of `tenant` that `domain` governs and that knows the Instance as a device key.
    async fn device_ended(
        &self,
        router: &Pool,
        tenant: TenantId,
        domain: &DomainId,
        instance: &[u8; 16],
        at: u64,
    ) -> Result<(), Unavailable> {
        for r in tenancy::tenant_routes(router, &[tenant])
            .await
            .map_err(down)?
        {
            let mut t = TenantTx::begin(&self.db.app, r.tenant, r.realm)
                .await
                .map_err(down)?;
            let governed = idp::governance(&mut t)
                .await
                .map_err(down)?
                .is_some_and(|g| g.domain == *domain);
            if governed && let Some(subject) = t.device_subject(instance).await.map_err(down)? {
                let id = access_identity_account::app::signal::fresh_id().map_err(down)?;
                let s = Signal::device_compliance(id, subject, false, at);
                access_identity_account::app::signal::emit_tenant(&mut t, &s)
                    .await
                    .map_err(down)?;
            }
            t.commit().await.map_err(down)?;
        }
        Ok(())
    }

    /// The governing domains of the live realms, read through the router role (`router`) and
    /// each realm's own scope.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn domains(&self, router: &Pool) -> Result<Vec<DomainId>, Unavailable> {
        let mut out = BTreeSet::new();
        for r in tenancy::routes(router).await.map_err(down)? {
            let mut t = TenantTx::begin(&self.db.app, r.tenant, r.realm)
                .await
                .map_err(down)?;
            let g = idp::governance(&mut t).await.map_err(down)?;
            t.commit().await.map_err(down)?;
            if let Some(g) = g {
                out.insert(*g.domain.as_bytes());
            }
        }
        Ok(out.into_iter().map(DomainId::from_bytes).collect())
    }

    /// Steps the identity outbox and every governing domain's outbox until `stop` resolves,
    /// sleeping while idle; the domains are read again every [`DOMAINS_REFRESH`].
    pub async fn run(&self, router: &Pool, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        let mut domains = Vec::new();
        let mut read_at: Option<Instant> = None;
        while !*stop.borrow() {
            if read_at.is_none_or(|t| t.elapsed() >= DOMAINS_REFRESH) {
                if let Ok(d) = self.domains(router).await {
                    domains = d;
                    read_at = Some(Instant::now());
                } else {
                    tracing::warn!("governing domains not read");
                }
            }
            let mut queued = 0_u32;
            if let Ok(n) = self.identity_step().await {
                queued = queued.saturating_add(n);
            } else {
                tracing::warn!("identity event fan-out step failed");
            }
            for d in &domains {
                if let Ok(n) = self.domain_step_in(d, Some(router)).await {
                    queued = queued.saturating_add(n);
                } else {
                    tracing::warn!("authority event fan-out step failed");
                }
            }
            if queued == 0 {
                self.idle(&mut stop).await;
            }
        }
    }

    /// Waits one poll interval, or until `stop` changes or the doorbell rings.
    async fn idle(&self, stop: &mut tokio::sync::watch::Receiver<bool>) {
        let rang = async {
            match &self.wake {
                Some(w) => w.notified().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = tokio::time::timeout(POLL_INTERVAL, stop.changed()) => {}
            () = rang => {}
        }
    }

    /// One delivery per live subscription of `tenant` that asked for the event's type or its
    /// CAEP counterpart, and per live platform product subscription of another tenant (OP-149
    /// m.17 (e)); the stream's profile decides which forms it gets (§9.16). Every SET of a
    /// platform product's subscription names the event's tenant in `access_tenant`, its own
    /// tenant's events included (OP-149 m.26 (d)).
    async fn queue(&self, tenant: TenantId, ready: &Ready) -> Result<u32, Unavailable> {
        let now = self.clock.now().map_err(down)?;
        let own = urn(ready.name);
        let standard = counterpart(ready.name).map(signal_uri);
        let wants = |events: &[String]| {
            events.contains(&own) || standard.as_ref().is_some_and(|s| events.contains(s))
        };
        // OP-132 m.5
        let mut t = TenantTx::begin_tenant_wide(&self.db.app, tenant)
            .await
            .map_err(down)?;
        let subs = t.live_subscriptions().await.map_err(down)?;
        t.commit().await.map_err(down)?;
        let mut by_realm: BTreeMap<([u8; 16], [u8; 16]), Vec<SubscriptionRow>> = BTreeMap::new();
        for s in subs.into_iter().filter(|s| wants(&s.events)) {
            by_realm
                .entry((*tenant.as_bytes(), s.realm))
                .or_default()
                .push(s);
        }
        for p in store::platform_subscriptions(&self.db.reader)
            .await
            .map_err(down)?
        {
            if p.tenant == tenant || !wants(&p.events) {
                continue;
            }
            let mut t = TenantTx::begin(&self.db.app, p.tenant, p.realm)
                .await
                .map_err(down)?;
            let s = t.subscription(p.realm, p.id).await.map_err(down)?;
            t.commit().await.map_err(down)?;
            if let Some(s) = s.filter(|s| !s.disabled) {
                by_realm
                    .entry((*p.tenant.as_bytes(), *p.realm.as_bytes()))
                    .or_default()
                    .push(s);
            }
        }
        let raw_id = b64url_decode(&ready.id).map_err(down)?;
        let mut queued = 0_u32;
        for ((owner, realm), subs) in by_realm {
            let (owner, realm) = (TenantId::from_bytes(owner), RealmId::from_bytes(realm));
            let Some((issuer, _)) = realm_signing(&self.db.app, owner, realm).await? else {
                continue;
            };
            let mut t = TenantTx::begin(&self.db.app, owner, realm)
                .await
                .map_err(down)?;
            let profiles = profiles(&mut t, realm).await?;
            for s in subs {
                let profile = profiles.get(&s.id).copied().unwrap_or_default();
                for form in forms(ready.name, profile, &s.events) {
                    let (mut claims, event_id) = if form == own {
                        (
                            set_claims(ready, issuer.as_str(), &s.audience, now / 1000),
                            ready.id.clone(),
                        )
                    } else {
                        let jti = derived_id("access/set-counterpart/v1", &raw_id, form.as_bytes());
                        let body = counterpart(ready.name).map_or_else(
                            || json!({}),
                            |k| counterpart_body(k, ready.name, ready.at),
                        );
                        let env = Envelope {
                            iss: issuer.as_str(),
                            aud: &s.audience,
                            iat_s: now / 1000,
                            jti: &jti,
                            txn: &ready.id,
                        };
                        let sub_id = json!({"format": "opaque", "id": ready.sub_id});
                        (standard_claims(&env, &form, &sub_id, body), jti)
                    };
                    if form != own
                        && let (Some(p), Some(c)) =
                            (ready.payload.get(POSITION_FIELD), claims.as_object_mut())
                    {
                        // OP-22, OP-156 m.3 (j)
                        c.insert(String::from(POSITION_FIELD), p.clone());
                    }
                    if owner != tenant || s.platform_product.is_some() {
                        set_tenant(&mut claims, &self.db.tenant(tenant)?);
                    }
                    let row = delivery_row(owner, &s, event_id, form, &claims, ready.at)?;
                    if t.enqueue_delivery(&row, now).await.map_err(down)? {
                        queued = queued.saturating_add(1);
                    }
                }
            }
            t.commit().await.map_err(down)?;
        }
        Ok(queued)
    }

    /// One CAEP or RISC SET per live stream of the signal's realm that asked for its type
    /// (TN-41, TN-43). The subject is named by the stream's receiver's own pairwise `sub`
    /// (RFC 9493 `iss_sub`), and only when the subject already has one there: a receiver never
    /// learns of a subject it was not given (MD-10). A realm-wide signal names the realm issuer
    /// (CR-27). Each copy has its own `jti` and `txn`, so receivers cannot link them (TI-RT10).
    async fn queue_signal(
        &self,
        tenant: TenantId,
        realm: RealmId,
        signal: &Signal,
        at: Position,
    ) -> Result<u32, Unavailable> {
        let now = self.clock.now().map_err(down)?;
        let uri = signal_uri(signal.kind);
        let Some((issuer, _)) = realm_signing(&self.db.app, tenant, realm).await? else {
            return Ok(0);
        };
        let mut t = TenantTx::begin(&self.db.app, tenant, realm)
            .await
            .map_err(down)?;
        let subs = t.live_subscriptions().await.map_err(down)?;
        let mut queued = 0_u32;
        for s in subs
            .iter()
            .filter(|s| s.realm == *realm.as_bytes() && s.events.contains(&uri))
        {
            let sub_id = match signal.subject {
                None => json!({"format": "uri", "uri": issuer.as_str()}),
                Some(subject) => {
                    let Some(client) = idp::client(&mut t, &s.audience)
                        .await
                        .map_err(down)?
                        .filter(|c| c.active)
                    else {
                        continue;
                    };
                    let Some(sub) = t
                        .existing_pairwise(subject, client.client_uuid)
                        .await
                        .map_err(down)?
                    else {
                        continue;
                    };
                    json!({"format": "iss_sub", "iss": issuer.as_str(), "sub": sub})
                }
            };
            let jti = derived_id("access/signal-set/v1", &signal.id, &s.id);
            let txn = derived_id("access/signal-txn/v1", &signal.id, &s.id);
            let env = Envelope {
                iss: issuer.as_str(),
                aud: &s.audience,
                iat_s: now / 1000,
                jti: &jti,
                txn: &txn,
            };
            let mut claims = standard_claims(&env, &uri, &sub_id, signal.event_body());
            if let Some(c) = claims.as_object_mut() {
                // OP-22, OP-156 m.3 (j)
                c.insert(String::from(POSITION_FIELD), position_json(at));
            }
            let row = delivery_row(tenant, s, jti, uri.clone(), &claims, signal.at)?;
            if t.enqueue_delivery(&row, now).await.map_err(down)? {
                queued = queued.saturating_add(1);
            }
        }
        t.commit().await.map_err(down)?;
        Ok(queued)
    }
}

/// `{"pos": …, "idx": …}`.
#[must_use]
pub fn position_json(p: Position) -> Value {
    json!({"pos": p.pos, "idx": p.idx})
}

/// Adds `access_position` to an event body (OP-22, OP-156 m.3 (j)).
pub fn position(payload: &mut Value, p: Position) {
    if let Some(m) = payload.as_object_mut() {
        m.insert(String::from(POSITION_FIELD), position_json(p));
    }
}

/// The position of an identity outbox event: its transaction and row, the order the outbox
/// delivers in.
#[must_use]
pub fn identity_position(ev: &identity::OutboxEvent) -> Position {
    Position {
        pos: ev.xid,
        idx: u64::try_from(ev.id).unwrap_or(0),
    }
}

/// The profiles of `realm`'s streams; a stream without one is [`Profile::Both`].
async fn profiles(
    t: &mut TenantTx,
    realm: RealmId,
) -> Result<BTreeMap<[u8; 16], Profile>, Unavailable> {
    Ok(t.stream_profiles(realm)
        .await
        .map_err(down)?
        .into_iter()
        .map(|p| {
            (
                p.subscription,
                Profile::parse(&p.profile).unwrap_or_default(),
            )
        })
        .collect())
}

fn delivery_row(
    owner: TenantId,
    s: &SubscriptionRow,
    event_id: String,
    event_type: String,
    claims: &Value,
    at: u64,
) -> Result<DeliveryRow, Unavailable> {
    Ok(DeliveryRow {
        tenant: *owner.as_bytes(),
        realm: s.realm,
        subscription: s.id,
        channel: s.channel.clone(),
        event_id,
        event_type,
        payload: serde_json::to_vec(claims).map_err(down)?,
        occurred_ms: i64::try_from(at).map_err(down)?,
        attempts: 0,
        state: String::from("pending"),
        last_reason: None,
    })
}
