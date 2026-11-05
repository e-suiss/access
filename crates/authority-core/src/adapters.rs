//! Adapters of the core's ports (OP-63) and the domains one process leads (OP-141 m.18).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_authority_sequencer::SequencerError;
use access_authority_sequencer::adapters::{PgLog, create_genesis};
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::ports::Clock;
use access_crypto::event_id::{EventKey, label};
use access_crypto::token::TokenKey;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::fold;
use access_kernel::meta::{self, GrantState};
use access_kernel::model::{Id, ResourceSelector, SubjectSelector, TrustedTime};
use access_kernel::record::{Opened, RecordEnvelope};
use access_kernel::verify::cose::PublicKey;
use access_store::authority::position_at;
use access_store::authority::read_log;
use access_store::authority::{
    NonceRow, ReceiptRow, StateRow, counter, domain_tenant, find_nonce, keep_receipt, receipt,
    state_of, state_prefix,
};
use access_store::derived::{GrantRow, KeyChange, advance_with, cursor, keys_of};
use access_store::scope::DomainId;
use access_store::{Pool, StoreError};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::pkcs11::KeyStore;

use crate::CoreError;
use crate::app::{Authority, Compromise, Incoming, Response};
use crate::keys;
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

    async fn log(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, CoreError> {
        Ok(read_log(&self.pool, &self.domain, from, to)
            .await?
            .into_iter()
            .map(|r| r.envelope)
            .collect())
    }

    async fn recorded_at(&self, pos: u64) -> Result<Option<u64>, CoreError> {
        Ok(read_log(&self.pool, &self.domain, pos, pos)
            .await?
            .first()
            .map(|r| r.recorded_at))
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

    async fn nonce_opened(&self, nonce: &[u8]) -> Result<Option<u64>, CoreError> {
        Ok(access_store::authority::nonce_opened(&self.pool, &self.domain, nonce).await?)
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

    fn pseudonym_key(
        &self,
        domain: &Digest,
    ) -> Result<access_crypto::pseudonym::PseudonymKey, CoreError> {
        let label = access_crypto::pseudonym::label(&domain.0);
        self.mac(&label)
            .or_else(|_| self.generate_mac(&label))
            .map(access_crypto::pseudonym::PseudonymKey::token)
            .map_err(|_| CoreError::Unavailable("pseudonym-key"))
    }

    fn open_domain(&self, domain: &Digest) -> Result<(), CoreError> {
        let event = label(&domain.0);
        if self.mac(&event).is_err() {
            self.generate_mac(&event)
                .map_err(|_| CoreError::Unavailable("event-key"))?;
        }
        let token = access_crypto::token::label(&domain.0);
        if self.aead(&token).is_err() {
            self.generate_aead(&token)
                .map_err(|_| CoreError::Unavailable("token-key"))?;
        }
        Ok(())
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
    /// The authority signer's socket; without one, receipts are not signed (OP-143 m.5).
    pub signer: Option<std::path::PathBuf>,
}

struct Led<B: Binding, S: Salts, C> {
    core: Authority<PgLog, PgReader, B, S>,
    clock: C,
    tokens: TokenKey,
    signer_open: bool,
}

type Slot<B, S, C> = Arc<tokio::sync::Mutex<Option<Led<B, S, C>>>>;
type Guard<B, S, C> = tokio::sync::OwnedMutexGuard<Option<Led<B, S, C>>>;

/// Hard deadline of one search page (§9.7.1, EA).
pub const SEARCH_DEADLINE: Duration = Duration::from_secs(1);

/// How long a metadata request waits for the signer (PD).
pub const SIGNER_DEADLINE: Duration = Duration::from_secs(2);

/// Kind of the page token (OP-141 m.22 (b)).
const PAGE_TOKEN: &str = "page";

/// The domains this process leads, each taken on its first request (OP-141 m.18 (a)).
pub struct Domains<K, B: Binding, S: Salts, C> {
    setup: Setup<K, B, S, C>,
    led: Mutex<HashMap<Digest, Slot<B, S, C>>>,
}

impl<K: Keys, B: Binding, S: Salts, C> Domains<K, B, S, C> {
    /// Opens a new domain of `tenant` (TN-111): writes its Genesis, then makes its event-id and
    /// token keys (OP-141 m.18 (d), m.22 (d), OP-149 m.22 (g)), so every domain this returns can
    /// be led. When making a key fails, the new domain is returned to nobody and stays unused.
    ///
    /// # Errors
    /// [`CoreError`].
    pub async fn create(
        &self,
        tenant: [u8; 16],
        fields: BTreeMap<String, Opened>,
        recorded_at: TrustedTime,
    ) -> Result<Digest, CoreError> {
        let domain = create_genesis(&self.setup.sequencer, tenant, fields, recorded_at).await?;
        self.setup.keys.open_domain(&domain)?;
        // SAI-46, OP-146 m.16 (m)
        if let Some(path) = &self.setup.signer
            && !open_keyring(path, domain).await
        {
            return Err(CoreError::Unavailable("signer"));
        }
        Ok(domain)
    }
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
        let pseudonyms = s.keys.pseudonym_key(&domain)?;
        let log = PgLog::new(s.sequencer.clone(), domain, tenant, s.holder.clone(), s.ttl);
        let leader = match Leader::acquire(log, domain, key).await {
            Ok(leader) => leader,
            Err(SequencerError::Store(StoreError::LeaseHeld)) => {
                return Err(CoreError::Unavailable("lease-held"));
            }
            Err(e) => return Err(e.into()),
        };
        let reader = PgReader::new(s.app.clone(), id);
        // SAI-46: started without holding the lease's connection; the first signed artefact
        // opens the keyring again if this has not finished
        if let Some(path) = s.signer.clone() {
            tokio::spawn(async move {
                open_keyring(&path, domain).await;
            });
        }
        let signer_open = false;
        Ok(Led {
            core: Authority::new(leader, reader, s.binding.clone(), s.salts.clone(), domain)
                .with_pseudonyms(pseudonyms),
            clock: s.clock.clone(),
            tokens,
            signer_open,
        })
    }

    /// Explains the recorded decision at `record` on its domain's leader (OP-141 m.36).
    ///
    /// # Errors
    /// As [`Authority::explain_recorded`].
    pub async fn explain_recorded(
        &self,
        inc: &Incoming,
        record: u64,
        scope: crate::app::Scope,
    ) -> Result<Response, CoreError> {
        let mut guard = self.leading(inc.request.domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let result = led.core.explain_recorded(inc, record, scope, now).await;
        if matches!(result, Err(CoreError::Sequencer(_) | CoreError::Store(_))) {
            *guard = None;
        }
        result
    }

    /// Decides `inc` on its domain's leader, taking the lease first if needed. A failed
    /// commit or store read drops the leader; the next request takes the lease again.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] when the domain cannot be led here.
    pub async fn exercise(&self, inc: &Incoming) -> Result<Response, CoreError> {
        self.decide(inc, None).await
    }

    /// The single-subject eligibility check of `inc` for `subject` on its domain's leader: a
    /// `check` that records nothing (OP-149 m.10).
    ///
    /// # Errors
    /// As [`Authority::eligible`].
    pub async fn eligible(&self, inc: &Incoming, subject: Id) -> Result<Response, CoreError> {
        self.decide(inc, Some(subject)).await
    }

    async fn decide(&self, inc: &Incoming, subject: Option<Id>) -> Result<Response, CoreError> {
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
        let mut result = match subject {
            None => led.core.exercise(inc, now).await,
            Some(s) => led.core.eligible(inc, s, now).await,
        };
        // OP-141 m.22 (e), (f)
        if let Ok(r) = &mut result {
            r.consistency = Some(
                led.tokens
                    .seal(&domain.0, CONSISTENCY, &led.core.head().to_be_bytes())
                    .map_err(|_| CoreError::Unavailable("token-key"))?,
            );
        }
        // §9.8, L2-RCP-2: signed after the commit; without a signer the receipt waits
        if let (Ok(r), Some(path)) = (&mut result, &self.setup.signer)
            && let Some(payload) = r.receipt.clone()
        {
            r.signed_receipt = sign_artefact(path, led, domain, Artefact::Receipt, payload, now)
                .await
                .ok();
        }
        // OP-149 m.9: kept for GET /access/v1/exercises/{id}; without it the answer comes from state
        if let Ok(r) = &result
            && let (Some(payload), Some(exercise), Some(pos)) = (&r.receipt, r.exercise, r.record)
        {
            let row = ReceiptRow {
                exercise: exercise.0,
                pos,
                payload: payload.clone(),
                signed: r.signed_receipt.clone(),
            };
            let _ =
                keep_receipt(&self.setup.sequencer, &DomainId::from_bytes(domain.0), &row).await;
        }
        if let (Ok(r), Some(path)) = (&mut result, &self.setup.signer)
            && let Some(payload) = r.pap.clone()
        {
            r.signed_pap = sign_artefact(path, led, domain, Artefact::Pap, payload, now)
                .await
                .ok();
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
        // §9.7.1: past the deadline there is no answer, never a partial list
        let found = tokio::time::timeout(SEARCH_DEADLINE, led.core.search(inc, query, after, now))
            .await
            .map_err(|_| CoreError::Unavailable("deadline"))??;
        let next = found
            .next
            .map(|n| led.tokens.seal(&domain.0, PAGE_TOKEN, &page_body(&n)))
            .transpose()
            .map_err(|_| CoreError::Unavailable("token-key"))?;
        Ok((found.hits, next))
    }

    /// The current binding-signed Domain Metadata of `domain` from the signer (§9.15.1,
    /// OP-143 m.4). The keyring is not opened here: a domain the signer has not opened, an
    /// unreachable signer or no signer at all gives none.
    pub async fn metadata(&self, domain: Digest) -> Option<Vec<u8>> {
        use access_authority_signer::adapters::call;
        use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
        let path = self.setup.signer.as_deref()?;
        let request = SignRequest::Metadata(domain);
        match tokio::time::timeout(SIGNER_DEADLINE, call(path, &request)).await {
            Ok(Ok(SignResponse::Metadata(cose))) => Some(cose),
            _ => None,
        }
    }

    /// The keys `kids` of `domain` at `as_of` (OP-149 m.5): the derived index is brought up to
    /// the head first, the `party_compromise` overlay is read on the leader, and with `sign` the
    /// payload is signed under usage `key-lookup`. Nothing is recorded.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] for more than [`keys::MAX_KIDS`] kids or a time before the
    /// domain's Genesis; [`CoreError::Unavailable`] for a position past the head.
    pub async fn lookup_keys(
        &self,
        domain: Digest,
        kids: &[[u8; 32]],
        as_of: keys::AsOf,
        sign: bool,
    ) -> Result<KeyAnswer, CoreError> {
        if kids.is_empty() || kids.len() > keys::MAX_KIDS {
            return Err(CoreError::Protocol("kids"));
        }
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let id = DomainId::from_bytes(domain.0);
        match derive(&self.setup.deriver, domain).await {
            Ok(_) | Err(CoreError::Store(StoreError::Stale)) => {}
            Err(e) => return Err(e),
        }
        let head = led.core.head();
        let pos = match as_of {
            keys::AsOf::Head => head,
            keys::AsOf::Position(p) if p <= head => p,
            keys::AsOf::Position(_) => return Err(CoreError::Unavailable("consistency")),
            keys::AsOf::Time(t) => position_at(&self.setup.app, &id, t)
                .await?
                .ok_or(CoreError::Protocol("as_of"))?
                .min(head),
        };
        if cursor(&self.setup.app, &id).await? < pos {
            return Err(CoreError::Unavailable("index"));
        }
        let rows = keys_of(&self.setup.app, &id, kids).await?;
        let mut compromises: BTreeMap<[u8; 16], Vec<Compromise>> = BTreeMap::new();
        for r in &rows {
            if let std::collections::btree_map::Entry::Vacant(slot) = compromises.entry(r.party) {
                slot.insert(led.core.compromises(&Id(r.party), now).await?);
            }
        }
        let mut lookup = keys::Lookup {
            domain,
            pos,
            iat: now,
            keys: Vec::with_capacity(kids.len()),
            unknown: Vec::new(),
        };
        for kid in kids {
            let found = rows.iter().find(|r| r.kid == *kid).and_then(|r| {
                let c = compromises.get(&r.party).map_or(&[][..], Vec::as_slice);
                keys::entry(r, pos, c)
            });
            match found {
                Some(e) => lookup.keys.push(e),
                None => lookup.unknown.push(*kid),
            }
        }
        let consistency = led
            .tokens
            .seal(&domain.0, CONSISTENCY, &head.to_be_bytes())
            .map_err(|_| CoreError::Unavailable("token-key"))?;
        let signed = match (sign, &self.setup.signer) {
            (true, Some(path)) => {
                let payload = keys::payload(&lookup);
                Some(
                    sign_artefact(path, led, domain, Artefact::KeyLookup, payload, now)
                        .await
                        .map_err(CoreError::Unavailable)?,
                )
            }
            (true, None) => return Err(CoreError::Unavailable("signer")),
            (false, _) => None,
        };
        Ok(KeyAnswer {
            lookup,
            consistency,
            signed,
        })
    }

    /// The head of `domain` as an opaque consistency token (OP-141 m.22 (f)): an answer read
    /// after it reflects at least that head.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the domain cannot be led here.
    pub async fn consistency(&self, domain: Digest) -> Result<String, CoreError> {
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        led.tokens
            .seal(&domain.0, CONSISTENCY, &led.core.head().to_be_bytes())
            .map_err(|_| CoreError::Unavailable("token-key"))
    }

    /// The allowed Exercise `exercise` of `domain` (OP-149 m.9): the receipt the decision
    /// point issued when it was kept, else what the state records of it. `None` for an
    /// Exercise the domain never allowed.
    ///
    /// # Errors
    /// [`CoreError`].
    pub async fn exercise_record(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> Result<Option<ExerciseRecord>, CoreError> {
        let id = DomainId::from_bytes(domain.0);
        if let Some(r) = receipt(&self.setup.app, &id, &exercise.0).await? {
            let parsed = access_kernel::receipt::Receipt::from_bytes(&r.payload)
                .map_err(|_| CoreError::Store(StoreError::Corrupt))?;
            return Ok(Some(ExerciseRecord {
                exercise,
                position: r.pos,
                intent: parsed.intent,
                instance: parsed.instance,
                receipt: Some(r.payload),
                signed_receipt: r.signed,
            }));
        }
        let key = meta::exercise_key(meta::kind::EXERCISE, &exercise);
        let rows = state_of(&self.setup.app, &id, &[key]).await?;
        let Some(value) = rows.into_iter().find_map(|r| r.value) else {
            return Ok(None);
        };
        let s = meta::ExerciseState::from_bytes(&value)
            .map_err(|_| CoreError::Store(StoreError::Corrupt))?;
        Ok(Some(ExerciseRecord {
            exercise,
            position: s.since,
            intent: s.intent,
            instance: Some(s.actor),
            receipt: None,
            signed_receipt: None,
        }))
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

/// An allowed Exercise as `GET /access/v1/exercises/{id}` shows it (OP-149 m.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExerciseRecord {
    /// The `ExerciseID`.
    pub exercise: Digest,
    /// Position of the allowing decision record.
    pub position: u64,
    /// The intent digest it was allowed for.
    pub intent: Digest,
    /// The actor Instance; `None` for an anonymous actor.
    pub instance: Option<Id>,
    /// The unsigned receipt payload, when kept.
    pub receipt: Option<Vec<u8>>,
    /// The signed receipt and its key excerpt, when the signer signed it.
    pub signed_receipt: Option<(Vec<u8>, Vec<u8>)>,
}

/// A key lookup answer (OP-149 m.5).
#[derive(Clone, Debug)]
pub struct KeyAnswer {
    /// The keys at the answer's position.
    pub lookup: keys::Lookup,
    /// The head it was answered at, as an opaque token (OP-141 m.22 (f)).
    pub consistency: String,
    /// The signed `key-lookup` payload and its key excerpt, when asked for.
    pub signed: Option<(Vec<u8>, Vec<u8>)>,
}

/// What a decision point asks the signer to sign.
#[derive(Clone, Copy)]
enum Artefact {
    Receipt,
    Pap,
    KeyLookup,
}

/// The signer's stable error codes; a code not listed reads as `signer-error`.
const SIGNER_CODES: [&str; 7] = [
    "signer-binding",
    "signer-unknown-domain",
    "signer-time",
    "signer-no-key",
    "signer-usage",
    "signer-encode",
    "signer-note",
];

/// The stable reason of a signer's refusal (OP-149 m.5): a domain's first operational key
/// signs only `T_publish_lead` after it is published (SAI-46), and until then the signer
/// answers `signer-no-key`.
fn signer_reason(code: &str) -> &'static str {
    SIGNER_CODES
        .into_iter()
        .find(|c| *c == code)
        .unwrap_or("signer-error")
}

/// Opens the keyring of `domain` in the signer at `path`, so that its key schedule runs; the
/// signer keeps an open keyring as it is (OP-143 m.4).
async fn open_keyring(path: &std::path::Path, domain: Digest) -> bool {
    use access_authority_signer::adapters::call;
    use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
    let open = SignRequest::Open(Box::new(access_authority_signer::domain::default_template(
        domain,
    )));
    matches!(call(path, &open).await, Ok(SignResponse::Opened))
}

/// Asks the signer at `path` to sign an artefact payload, opening the domain's keyring first
/// (L2-RCP-2, L2-PAP-2).
///
/// # Errors
/// The signer's stable reason, or `signer-unreachable`.
async fn sign_artefact<B: Binding, S: Salts, C>(
    path: &std::path::Path,
    led: &mut Led<B, S, C>,
    domain: Digest,
    artefact: Artefact,
    payload: Vec<u8>,
    at: u64,
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    use access_authority_signer::adapters::call;
    use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
    use access_kernel::verify::key_scope::KeyUsage;
    if !led.signer_open {
        led.signer_open = open_keyring(path, domain).await;
    }
    let (usage, content_type) = match artefact {
        Artefact::Receipt => (KeyUsage::Receipt, access_kernel::receipt::CONTENT_TYPE),
        Artefact::Pap => (KeyUsage::Pap, access_kernel::pap::CONTENT_TYPE),
        Artefact::KeyLookup => (KeyUsage::KeyLookup, keys::CONTENT_TYPE),
    };
    let sign = SignRequest::Sign {
        domain,
        usage,
        content_type: String::from(content_type),
        payload,
        at,
    };
    match call(path, &sign).await {
        Ok(SignResponse::Signed { sign1, excerpt }) => Ok((sign1, excerpt)),
        Ok(SignResponse::Error(code)) => Err(signer_reason(&code)),
        Ok(_) => Err("signer-error"),
        Err(_) => Err("signer-unreachable"),
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
        let mut changes: Vec<KeyChange> = Vec::new();
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
                // OP-149 m.5
                if let Some(change) = keys::change(kind, g, value.as_ref(), r.pos, r.recorded_at) {
                    changes.push(change);
                    continue;
                }
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
        advance_with(deriver, &id, at, to, &rows, &changes).await?;
        at = to;
    }
    Ok(at)
}
