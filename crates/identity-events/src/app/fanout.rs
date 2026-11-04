//! The fan-out (OP-149 m.4, m.7): each event of the identity outbox and of a domain's
//! authority outbox becomes one unsigned SET per live subscription of its tenant that asked for
//! its type. The cursor moves only after the deliveries are stored, and a repeated step stores
//! nothing twice (the event id is the key), so no event is lost or doubled. [`Fanout::run`]
//! steps the identity outbox and the outbox of every live realm's governing domain.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use access_internal_api::events::Event;
use access_store::authority;
use access_store::events::{self as store, DeliveryRow, SubscriptionRow};
use access_store::identity::{self, RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::{Pool, idp, tenancy};

use crate::app::courier::POLL_INTERVAL;
use crate::app::{Db, down, realm_signing};
use crate::domain::catalog::{IdentityEvent, OUTBOX_PREFIX, Ready, authority_ready, urn};
use crate::domain::set::{set_claims, set_tenant};
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
}

impl<C: Clock + Send + Sync> Fanout<C> {
    /// A fan-out over `db`.
    pub const fn new(db: Db, clock: C) -> Self {
        Self { db, clock }
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
                        queued = queued.saturating_add(self.queue(ev.tenant, &e.ready()).await?);
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

    /// Queues `domain`'s authority outbox past its cursor, up to one batch.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn domain_step(&self, domain: &DomainId) -> Result<u32, Unavailable> {
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
                    let ready = authority_ready(&e, &r.event_id);
                    queued = queued.saturating_add(self.queue(tenant, &ready).await?);
                }
                Err(e) => tracing::warn!(error = %e, "authority event unreadable; passed"),
            }
            store::advance_domain_cursor(&self.db.app, domain, (r.pos, r.idx))
                .await
                .map_err(down)?;
        }
        Ok(queued)
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
                if let Ok(n) = self.domain_step(d).await {
                    queued = queued.saturating_add(n);
                } else {
                    tracing::warn!("authority event fan-out step failed");
                }
            }
            if queued == 0 {
                let _ = tokio::time::timeout(POLL_INTERVAL, stop.changed()).await;
            }
        }
    }

    /// One delivery per live subscription of `tenant` that asked for the event's type, and per
    /// live platform product subscription of another tenant (OP-149 m.17 (e)); the latter's
    /// SET names the event's tenant.
    async fn queue(&self, tenant: TenantId, ready: &Ready) -> Result<u32, Unavailable> {
        let now = self.clock.now().map_err(down)?;
        let urn = urn(ready.name);
        let mut t = TenantTx::begin_tenant(&self.db.app, tenant)
            .await
            .map_err(down)?;
        let subs = t.live_subscriptions().await.map_err(down)?;
        t.commit().await.map_err(down)?;
        let mut by_realm: BTreeMap<([u8; 16], [u8; 16]), Vec<SubscriptionRow>> = BTreeMap::new();
        for s in subs.into_iter().filter(|s| s.events.contains(&urn)) {
            by_realm
                .entry((*tenant.as_bytes(), s.realm))
                .or_default()
                .push(s);
        }
        for p in store::platform_subscriptions(&self.db.reader)
            .await
            .map_err(down)?
        {
            if p.tenant == tenant || !p.events.contains(&urn) {
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
        let mut queued = 0_u32;
        for ((owner, realm), subs) in by_realm {
            let (owner, realm) = (TenantId::from_bytes(owner), RealmId::from_bytes(realm));
            let Some((issuer, _)) = realm_signing(&self.db.app, owner, realm).await? else {
                continue;
            };
            let mut t = TenantTx::begin(&self.db.app, owner, realm)
                .await
                .map_err(down)?;
            for s in subs {
                let mut claims = set_claims(ready, issuer.as_str(), &s.audience, now / 1000);
                if owner != tenant {
                    set_tenant(&mut claims, tenant.as_bytes());
                }
                let payload = serde_json::to_vec(&claims).map_err(down)?;
                let row = DeliveryRow {
                    tenant: *owner.as_bytes(),
                    realm: s.realm,
                    subscription: s.id,
                    channel: s.channel.clone(),
                    event_id: ready.id.clone(),
                    event_type: urn.clone(),
                    payload,
                    occurred_ms: i64::try_from(ready.at).map_err(down)?,
                    attempts: 0,
                    state: String::from("pending"),
                    last_reason: None,
                };
                if t.enqueue_delivery(&row, now).await.map_err(down)? {
                    queued = queued.saturating_add(1);
                }
            }
            t.commit().await.map_err(down)?;
        }
        Ok(queued)
    }
}
