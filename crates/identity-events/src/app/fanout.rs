//! The fan-out (OP-149 m.4, m.7): each event of the identity outbox and of a domain's
//! authority outbox becomes one unsigned SET per live subscription of its tenant that asked for
//! its type. The cursor moves only after the deliveries are stored, and a repeated step stores
//! nothing twice (the event id is the key), so no event is lost or doubled.

use std::collections::BTreeMap;

use access_internal_api::events::Event;
use access_store::authority;
use access_store::events::{self as store, DeliveryRow, SubscriptionRow};
use access_store::identity::{self, RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;

use crate::app::{Db, down, realm_signing};
use crate::domain::catalog::{IdentityEvent, OUTBOX_PREFIX, Ready, authority_ready, urn};
use crate::domain::set::set_claims;
use crate::ports::{Clock, Unavailable};

/// The fan-out's cursor name in `access_ops.outbox_cursor`.
pub const CONSUMER: &str = "events";

/// Events read per step (PD).
pub const BATCH: u32 = 100;

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

    /// One delivery per live subscription of `tenant` that asked for the event's type.
    async fn queue(&self, tenant: TenantId, ready: &Ready) -> Result<u32, Unavailable> {
        let now = self.clock.now().map_err(down)?;
        let urn = urn(ready.name);
        let mut t = TenantTx::begin_tenant(&self.db.app, tenant)
            .await
            .map_err(down)?;
        let subs = t.live_subscriptions().await.map_err(down)?;
        t.commit().await.map_err(down)?;
        let mut by_realm: BTreeMap<[u8; 16], Vec<SubscriptionRow>> = BTreeMap::new();
        for s in subs.into_iter().filter(|s| s.events.contains(&urn)) {
            by_realm.entry(s.realm).or_default().push(s);
        }
        let mut queued = 0_u32;
        for (realm, subs) in by_realm {
            let realm = RealmId::from_bytes(realm);
            let Some((issuer, _)) = realm_signing(&self.db.app, tenant, realm).await? else {
                continue;
            };
            let mut t = TenantTx::begin(&self.db.app, tenant, realm)
                .await
                .map_err(down)?;
            for s in subs {
                let claims = set_claims(ready, issuer.as_str(), &s.audience, now / 1000);
                let payload = serde_json::to_vec(&claims).map_err(down)?;
                let row = DeliveryRow {
                    tenant: *tenant.as_bytes(),
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
