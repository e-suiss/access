//! Adapters of the core's ports (OP-63) and the domains one process leads (OP-141 m.18).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_authority_sequencer::SequencerError;
use access_authority_sequencer::adapters::PgLog;
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::ports::Clock;
use access_crypto::event_id::{EventKey, label};
use access_crypto::token::TokenKey;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::fold;
use access_kernel::meta::{self, GrantState};
use access_kernel::model::{Id, ResourceSelector, SubjectSelector};
use access_kernel::record::RecordEnvelope;
use access_kernel::verify::cose::PublicKey;
use access_store::authority::read_log;
use access_store::authority::{
    NonceRow, StateRow, counter, domain_tenant, find_nonce, state_of, state_prefix,
};
use access_store::derived::{GrantRow, advance, cursor};
use access_store::scope::DomainId;
use access_store::{Pool, StoreError};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::pkcs11::KeyStore;

use crate::CoreError;
use crate::app::{Authority, Incoming, Response};
use crate::ports::{Binding, Keys, Reader, Row, Salts};
use crate::query::{Hit, Query, page_after, page_body};

/// Reads one domain's state and nonces through the application role.
#[derive(Clone)]
pub struct PgReader {
    pool: Pool,
    domain: DomainId,
}

impl PgReader {
    /// A reader of `domain` over `pool`.
    #[must_use]
    pub const fn new(pool: Pool, domain: DomainId) -> Self {
        Self { pool, domain }
    }
}

fn row(r: StateRow) -> Result<Row, CoreError> {
    let value = r
        .value
        .as_deref()
        .map(|b| dcbor::decode(b, Limits::CEILING))
        .transpose()
        .map_err(|_| CoreError::Store(access_store::StoreError::Corrupt))?;
    Ok((r.key, value, r.version))
}

impl Reader for PgReader {
    async fn fetch(&self, keys: &[Vec<u8>]) -> Result<Vec<Row>, CoreError> {
        let rows = state_of(&self.pool, &self.domain, keys).await?;
        keys.iter()
            .map(|k| match rows.iter().find(|r| &r.key == k) {
                None => Ok((k.clone(), None, 0)),
                Some(r) => {
                    let value = r
                        .value
                        .as_deref()
                        .map(|b| dcbor::decode(b, Limits::CEILING))
                        .transpose()
                        .map_err(|_| CoreError::Store(access_store::StoreError::Corrupt))?;
                    Ok((k.clone(), value, r.version))
                }
            })
            .collect()
    }

    async fn scan(&self, prefix: &[u8]) -> Result<Vec<Row>, CoreError> {
        state_prefix(&self.pool, &self.domain, prefix)
            .await?
            .into_iter()
            .map(row)
            .collect()
    }

    async fn grants_in(
        &self,
        namespace: &str,
        after: Option<Id>,
        limit: u32,
    ) -> Result<Vec<Id>, CoreError> {
        Ok(access_store::derived::grants_in(
            &self.pool,
            &self.domain,
            namespace,
            after.map(|a| a.0),
            limit,
        )
        .await?
        .into_iter()
        .map(Id)
        .collect())
    }

    async fn grants_for(
        &self,
        party: &Id,
        after: Option<Id>,
        limit: u32,
    ) -> Result<Vec<Id>, CoreError> {
        Ok(access_store::derived::grants_for(
            &self.pool,
            &self.domain,
            &party.0,
            after.map(|a| a.0),
            limit,
        )
        .await?
        .into_iter()
        .map(Id)
        .collect())
    }

    async fn counter(&self, key: &[u8]) -> Result<u64, CoreError> {
        Ok(counter(&self.pool, &self.domain, key).await?)
    }

    async fn nonce(&self, nonce: &[u8]) -> Result<Option<NonceRow>, CoreError> {
        Ok(find_nonce(&self.pool, &self.domain, nonce).await?)
    }
}

/// Salts from the operating system's random source (OP-106 m.15, OP-141 m.18 (e)).
#[derive(Clone, Copy, Debug, Default)]
pub struct OsSalts;

impl Salts for OsSalts {
    fn salt(&mut self) -> Result<[u8; 32], CoreError> {
        access_crypto::random::bytes().map_err(|_| CoreError::Unavailable("random"))
    }
}

/// No key is bound until the identity plane binds actors (OP-141 m.18 (f)).
#[derive(Clone, Copy, Debug, Default)]
pub struct Unbound;

impl Binding for Unbound {
    fn bound(&self, _kid: &[u8; 32]) -> Option<(Id, PublicKey)> {
        None
    }
}

impl Keys for KeyStore {
    fn event_key(&self, domain: &Digest) -> Result<EventKey, CoreError> {
        self.mac(&label(&domain.0))
            .map(EventKey::token)
            .map_err(|_| CoreError::Unavailable("event-key"))
    }

    fn token_key(&self, domain: &Digest) -> Result<TokenKey, CoreError> {
        self.aead(&access_crypto::token::label(&domain.0))
            .map(TokenKey::token)
            .map_err(|_| CoreError::Unavailable("token-key"))
    }
}

/// Kind of the consistency token (OP-141 m.22 (f)).
const CONSISTENCY: &str = "consistency";

/// What the domains share: the two pools, the keys, the lease holder and the ports. Each
/// domain gets its own copy of `clock`, `binding` and `salts`.
pub struct Setup<K, B, S, C> {
    /// The `access_sequencer` pool.
    pub sequencer: Pool,
    /// The `access_app` pool.
    pub app: Pool,
    /// The event-id keys.
    pub keys: K,
    /// This process as a lease holder.
    pub holder: String,
    /// Lease length (OP-130 m.6).
    pub ttl: Duration,
    /// Actor-binding.
    pub binding: B,
    /// Field salts.
    pub salts: S,
    /// Trusted time (OP-129 m.1).
    pub clock: C,
    /// The `access_deriver` pool (OP-141 m.22 (k)).
    pub deriver: Pool,
}

struct Led<B: Binding, S: Salts, C> {
    core: Authority<PgLog, PgReader, B, S>,
    clock: C,
    tokens: TokenKey,
}

type Slot<B, S, C> = Arc<tokio::sync::Mutex<Option<Led<B, S, C>>>>;
type Guard<B, S, C> = tokio::sync::OwnedMutexGuard<Option<Led<B, S, C>>>;

/// Kind of the page token (OP-141 m.22 (b)).
const PAGE_TOKEN: &str = "page";

/// The domains this process leads, each taken on its first request (OP-141 m.18 (a)).
pub struct Domains<K, B: Binding, S: Salts, C> {
    setup: Setup<K, B, S, C>,
    led: Mutex<HashMap<Digest, Slot<B, S, C>>>,
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// No domain led yet.
    #[must_use]
    pub fn new(setup: Setup<K, B, S, C>) -> Self {
        Self {
            setup,
            led: Mutex::new(HashMap::new()),
        }
    }

    fn slots(&self) -> Vec<Slot<B, S, C>> {
        self.led
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    fn slot(&self, domain: Digest) -> Result<Slot<B, S, C>, CoreError> {
        let mut led = self
            .led
            .lock()
            .map_err(|_| CoreError::Unavailable("domains"))?;
        Ok(led.entry(domain).or_default().clone())
    }

    fn forget(&self, domain: &Digest, slot: &Slot<B, S, C>) {
        if let Ok(mut led) = self.led.lock()
            && led.get(domain).is_some_and(|s| Arc::ptr_eq(s, slot))
        {
            led.remove(domain);
        }
    }

    async fn lead(&self, domain: Digest) -> Result<Led<B, S, C>, CoreError> {
        let s = &self.setup;
        let id = DomainId::from_bytes(domain.0);
        let tenant = domain_tenant(&s.sequencer, &id)
            .await?
            .ok_or(CoreError::Unavailable("unknown-domain"))?;
        let key = s.keys.event_key(&domain)?;
        let tokens = s.keys.token_key(&domain)?;
        let log = PgLog::new(s.sequencer.clone(), domain, tenant, s.holder.clone(), s.ttl);
        let leader = match Leader::acquire(log, domain, key).await {
            Ok(leader) => leader,
            Err(SequencerError::Store(StoreError::LeaseHeld)) => {
                return Err(CoreError::Unavailable("lease-held"));
            }
            Err(e) => return Err(e.into()),
        };
        let reader = PgReader::new(s.app.clone(), id);
        Ok(Led {
            core: Authority::new(leader, reader, s.binding.clone(), s.salts.clone(), domain),
            clock: s.clock.clone(),
            tokens,
        })
    }

    /// Decides `inc` on its domain's leader, taking the lease first if needed. A failed
    /// commit or store read drops the leader; the next request takes the lease again.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] when the domain cannot be led here.
    pub async fn exercise(&self, inc: &Incoming) -> Result<Response, CoreError> {
        let domain = inc.request.domain;
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        // OP-141 m.22 (f): a reader ahead of this head gets no answer
        if let Some(t) = &inc.request.consistency {
            let seen = led
                .tokens
                .open(&domain.0, CONSISTENCY, t)
                .ok()
                .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
                .map(u64::from_be_bytes)
                .ok_or(CoreError::Protocol("consistency_token"))?;
            if seen > led.core.head() {
                return Err(CoreError::Unavailable("consistency"));
            }
        }
        // OP-129 m.1
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let mut result = led.core.exercise(inc, now).await;
        // OP-141 m.22 (e), (f)
        if let Ok(r) = &mut result {
            r.consistency = Some(
                led.tokens
                    .seal(&domain.0, CONSISTENCY, &led.core.head().to_be_bytes())
                    .map_err(|_| CoreError::Unavailable("token-key"))?,
            );
        }
        if let Ok(r) = &mut result
            && let Some(pos) = r.record
        {
            r.basis_ref = Some(
                led.tokens
                    .seal(&domain.0, "basis_ref", &pos.to_be_bytes())
                    .map_err(|_| CoreError::Unavailable("token-key"))?,
            );
        }
        if matches!(result, Err(CoreError::Sequencer(_) | CoreError::Store(_))) {
            *guard = None;
        }
        result
    }

    /// The slot of `domain` with its leader, taking the lease first if needed.
    async fn leading(&self, domain: Digest) -> Result<Guard<B, S, C>, CoreError> {
        let slot = self.slot(domain)?;
        let mut guard = slot.clone().lock_owned().await;
        if guard.is_none() {
            match self.lead(domain).await {
                Ok(led) => *guard = Some(led),
                Err(e) => {
                    drop(guard);
                    self.forget(&domain, &slot);
                    return Err(e);
                }
            }
        }
        Ok(guard)
    }

    /// One page of `query` on the request's domain; the page token is opaque (OP-141 m.22
    /// (b), (d)).
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Protocol`] for a page token that is not this domain's.
    pub async fn search(
        &self,
        inc: &Incoming,
        query: &Query,
        page: Option<&str>,
    ) -> Result<(Vec<Hit>, Option<String>), CoreError> {
        let domain = inc.request.domain;
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let after = page
            .map(|t| {
                led.tokens
                    .open(&domain.0, PAGE_TOKEN, t)
                    .ok()
                    .and_then(|b| page_after(&b))
                    .ok_or(CoreError::Protocol("page"))
            })
            .transpose()?;
        let found = led.core.search(inc, query, after, now).await?;
        let next = found
            .next
            .map(|n| led.tokens.seal(&domain.0, PAGE_TOKEN, &page_body(&n)))
            .transpose()
            .map_err(|_| CoreError::Unavailable("token-key"))?;
        Ok((found.hits, next))
    }

    /// Brings the derived index of every domain led here up to its head (OP-141 m.22 (g)); the
    /// failures are returned and left for the next round.
    pub async fn derive(&self) -> Vec<CoreError> {
        let domains: Vec<Digest> = self
            .led
            .lock()
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        let mut failed = Vec::new();
        for d in domains {
            if let Err(error) = derive(&self.setup.deriver, d).await {
                failed.push(error);
            }
        }
        failed
    }

    /// Extends every held lease; a domain whose lease is lost is dropped (OP-130 m.6).
    pub async fn renew(&self) {
        for slot in self.slots() {
            let mut guard = slot.lock().await;
            if let Some(led) = guard.as_ref()
                && led.core.renew().await.is_err()
            {
                *guard = None;
            }
        }
    }

    /// Releases every held lease, for a planned shutdown (OP-31).
    pub async fn release(&self) {
        for slot in self.slots() {
            if let Some(led) = slot.lock().await.take() {
                let _ = led.core.release().await;
            }
        }
    }
}

/// Records the deriver reads per step (OP-141 m.22 (g), PD).
pub const DERIVE_STEP: u64 = 256;

fn grant_row(id: [u8; 16], g: &GrantState, pos: u64) -> GrantRow {
    let (holder_kind, holder) = match &g.content.holder {
        SubjectSelector::Party(p) => ("party", Some(p.0)),
        SubjectSelector::Pred(_) => ("pred", None),
        SubjectSelector::Public => ("public", None),
        SubjectSelector::Foreign { .. } => ("foreign", None),
    };
    let namespace = match &g.content.authority.authority.resource {
        ResourceSelector::Exact(r) => r.namespace.clone(),
        ResourceSelector::Structural(s) => s.namespace.clone(),
    };
    GrantRow {
        grant: id,
        holder_kind,
        holder,
        namespace,
        ended: g.ended.is_some(),
        pos,
    }
}

/// Brings the derived index of `domain` up to its head, reading the log as `access_deriver`
/// from the index's cursor (CMP-9, OP-141 m.22 (g)); returns the position applied. The index is
/// a projection of the log alone (TI-16, INV-33).
///
/// # Errors
/// [`CoreError::Store`]; `Stale` when another deriver moved the cursor first.
pub async fn derive(deriver: &Pool, domain: Digest) -> Result<u64, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let head = access_store::authority::read_head(deriver, &id).await?.pos;
    let mut at = cursor(deriver, &id).await?;
    while at < head {
        let to = head.min(at.saturating_add(DERIVE_STEP));
        let mut rows: BTreeMap<[u8; 16], GrantRow> = BTreeMap::new();
        for r in read_log(deriver, &id, at.saturating_add(1), to).await? {
            let record = RecordEnvelope::from_bytes(&r.envelope)
                .map_err(|_| CoreError::Store(StoreError::Corrupt))?;
            for (key, value) in
                fold::effects(&record).map_err(|_| CoreError::Store(StoreError::Corrupt))?
            {
                let Ok(Value::Array(k)) = dcbor::decode(&key, Limits::CEILING) else {
                    continue;
                };
                let (Some(Value::Text(kind)), Some(Value::Bytes(g))) = (k.first(), k.get(1)) else {
                    continue;
                };
                if kind != meta::kind::GRANT {
                    continue;
                }
                let (Ok(g), Some(state)) = (
                    <[u8; 16]>::try_from(g.as_slice()),
                    value.as_ref().and_then(|v| GrantState::from_value(v).ok()),
                ) else {
                    continue;
                };
                rows.insert(g, grant_row(g, &state, r.pos));
            }
        }
        let rows: Vec<GrantRow> = rows.into_values().collect();
        advance(deriver, &id, at, to, &rows).await?;
        at = to;
    }
    Ok(at)
}
