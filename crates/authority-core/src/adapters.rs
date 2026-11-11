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
use access_kernel::combinator::{Mode, Outcome};
use access_kernel::digest::Digest;
use access_kernel::fold;
use access_kernel::meta::{self, ActorKind, GrantState, Payload};
use access_kernel::model::{Id, ResourceSelector, SubjectSelector, TrustedTime};
use access_kernel::pap::Pap;
use access_kernel::record::{Opened, RecordEnvelope};
use access_kernel::status::StatusRef;
use access_kernel::verify::cose::PublicKey;
use access_store::authority::position_at;
use access_store::authority::read_log;
use access_store::authority::{
    NonceRow, ReceiptRow, Renewal, StateRow, counter, domain_tenant, find_nonce, keep_receipt,
    receipt, request_lease_handoff, state_of, state_prefix,
};
use access_store::derived::{GrantRow, KeyChange, advance_with, cursor, keys_of};
use access_store::offline::{ContractRow, insert_contract};
use access_store::projections::{Family, family as read_family};
use access_store::scope::DomainId;
use access_store::{Pool, StoreError};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::pkcs11::KeyStore;

use crate::CoreError;
use crate::app::projection::{class_word, namespaces, variant_word};
use crate::app::{Authority, Compromise, Incoming, Response};
use crate::ports::{Binding, Keys, Reader, Row, Salts};
use crate::query::{Hit, Query, page_after, page_body};
use crate::status::adapters::open_family;
use crate::{keys, parties};

mod audit;
mod binding;
mod consent;
mod linux;
mod one;
mod projection;
mod proxy;
mod reconcile;
mod ssh;
mod vault;
mod workload;
pub use audit::{
    AUDIT_EVENT_EXPORT, AUDIT_EVENT_READ, AUDIT_EVENT_REJECTED, audit_text, is_rejection, txn,
};
pub use consent::IssuedGrant;
pub use projection::{
    BOUNDS_HORIZON_MS, CONTRACT_LABEL, FAMILY_CLAIM, INTENT_HORIZON_MS, Projected, STATUS_CLAIM,
    Token, TokenAuthority, TokenOrder,
};
pub use reconcile::Reconciled;
pub use vault::ReleaseBasis;

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

    async fn proof(&self, digest: &[u8; 32]) -> Result<Option<Vec<u8>>, CoreError> {
        Ok(access_store::claims::proof(&self.pool, &self.domain, digest).await?)
    }

    async fn live_families(&self, holder: &Id) -> Result<Vec<Digest>, CoreError> {
        Ok(
            access_store::status::live_families(&self.pool, &self.domain, &holder.0)
                .await?
                .into_iter()
                .map(|f| Digest(f.root_exercise))
                .collect(),
        )
    }

    async fn verifier_profile(
        &self,
        audience: &str,
        now: u64,
    ) -> Result<Option<([u8; 32], Vec<u8>)>, CoreError> {
        Ok(access_store::offline::profile_for(&self.pool, &self.domain, audience, now).await?)
    }

    async fn highest_incarnation(
        &self,
        namespace: &str,
        path: &[String],
    ) -> Result<Option<u64>, CoreError> {
        Ok(
            access_store::resources::highest_incarnation(&self.pool, &self.domain, namespace, path)
                .await?,
        )
    }

    async fn incarnations(
        &self,
        namespace: &str,
        path: &[String],
    ) -> Result<Vec<crate::app::resources::Fact>, CoreError> {
        Ok(
            access_store::resources::incarnations(&self.pool, &self.domain, namespace, path)
                .await?
                .into_iter()
                .map(|r| crate::app::resources::Fact {
                    incarnation: r.incarnation,
                    event: r.event,
                    claim: Id(r.claim),
                    issuer: Id(r.issuer),
                    pos: r.pos,
                })
                .collect(),
        )
    }

    async fn discovered(&self, limit: u32) -> Result<Vec<crate::app::discovery::Row>, CoreError> {
        Ok(
            access_store::discovered_apps::list(&self.pool, &self.domain, limit)
                .await?
                .into_iter()
                .map(|r| crate::app::discovery::Row {
                    app: crate::app::discovery::Discovered {
                        connector: r.connector,
                        app: r.app,
                        name: r.name,
                        principal: None,
                        scopes: r.scopes.into_iter().collect(),
                    },
                    claim: Id(r.claim),
                    issuer: Id(r.issuer),
                    subject: Id(r.subject),
                    pos: r.pos,
                })
                .collect(),
        )
    }

    async fn open_offline(&self, holder: &Id, now: u64) -> Result<u64, CoreError> {
        Ok(access_store::offline::open_offline(&self.pool, &self.domain, &holder.0, now).await?)
    }

    async fn issued_since(
        &self,
        holder: &Id,
        since_ms: u64,
        namespaces: &[String],
    ) -> Result<u64, CoreError> {
        Ok(access_store::offline::issued_since(
            &self.pool,
            &self.domain,
            &holder.0,
            since_ms,
            namespaces,
        )
        .await?)
    }

    async fn unreported_overdue(&self, audience: &str, now: u64) -> Result<bool, CoreError> {
        Ok(access_store::offline::unreported_overdue(
            &self.pool,
            &self.domain,
            audience,
            now,
            access_kernel::validity::ceiling::REPORT_GRACE_MS,
        )
        .await?)
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

    async fn position_at(&self, at: u64) -> Result<Option<u64>, CoreError> {
        Ok(position_at(&self.pool, &self.domain, at).await?)
    }

    async fn open_contracts(&self, at: u64) -> Result<Vec<crate::ports::OpenContract>, CoreError> {
        Ok(access_store::offline::open_at(&self.pool, &self.domain, at)
            .await?
            .into_iter()
            .map(|c| crate::ports::OpenContract {
                exercise: Digest(c.exercise),
                holder: Id(c.holder),
                class: c.class,
                horizon_ms: c.horizon_ms,
                pep: c.pep,
            })
            .collect())
    }

    async fn indexed_live(
        &self,
        after: Option<Id>,
        limit: u32,
    ) -> Result<(Vec<Id>, u64), CoreError> {
        let live =
            access_store::derived::live_grants(&self.pool, &self.domain, after.map(|a| a.0), limit)
                .await?;
        let at = cursor(&self.pool, &self.domain).await?;
        Ok((live.into_iter().map(Id).collect(), at))
    }

    async fn publications(&self, namespace: &str) -> Result<Vec<Vec<u8>>, CoreError> {
        Ok(
            access_store::publications::of_namespace(&self.pool, &self.domain, namespace)
                .await?
                .into_iter()
                .map(|r| r.package)
                .collect(),
        )
    }

    async fn key_cutoff(&self, iss: &str, kid: &[u8; 32]) -> Result<Option<u64>, CoreError> {
        Ok(access_store::authority::realm_key_cutoff(&self.pool, iss, kid).await?)
    }

    async fn opening(&self, intent: &Digest) -> Result<Option<crate::ports::Opening>, CoreError> {
        let Some(row) =
            access_store::authority::find_opening(&self.pool, &self.domain, &intent.0).await?
        else {
            return Ok(None);
        };
        let tier = crate::app::approval::tier_of(row.tier)
            .ok_or(CoreError::Store(access_store::StoreError::Corrupt))?;
        Ok(Some(crate::ports::Opening {
            render: Digest(row.render_digest),
            tier,
        }))
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
    /// The deployment's API base: the address a domain's Token Status Lists are served under,
    /// and the `uri` a token's `status` claim names (OP-150 m.10 (b)).
    pub api_base: String,
    /// The control-plane analysis of restriction policy changes (OP-105); a process without the
    /// pinned, sandboxed solver passes [`crate::ports::NoAnalysis`] and every policy preview
    /// answers `unknown`.
    pub analysis: Arc<dyn crate::ports::PolicyAnalysis>,
}

struct Led<B: Binding, S: Salts, C> {
    core: Authority<PgLog, PgReader, B, S>,
    clock: C,
    tokens: TokenKey,
    signer_open: bool,
}

/// How a `projection.issue` commit opens its family (OP-150 m.10 (a)): for the OAuth client of a
/// token, else the PEP; in the refreshed family, else a new one.
#[derive(Clone, Copy, Debug, Default)]
struct Opening<'a> {
    client: Option<&'a str>,
    family: Option<[u8; 16]>,
}

/// The family a `projection.issue` commit was given before its decision.
#[derive(Clone, Debug)]
struct PapFamily {
    family: [u8; 16],
    status: StatusRef,
    opened: bool,
}

type Slot<B, S, C> = Arc<tokio::sync::Mutex<Option<Led<B, S, C>>>>;
type Guard<B, S, C> = tokio::sync::OwnedMutexGuard<Option<Led<B, S, C>>>;

/// Hard deadline of one search page (§9.7.1, EA).
pub const SEARCH_DEADLINE: Duration = Duration::from_secs(1);

/// How long a metadata request waits for the signer (PD).
pub const SIGNER_DEADLINE: Duration = Duration::from_secs(2);

/// How many lease lengths a one-shot job waits for a leader to hand a domain over (OP-149
/// m.28 (a), PD); a leader renews every third of a lease.
pub const HANDOFF_WAIT: u32 = 2;

/// How often a waiting one-shot job tries the lease again (PD).
const HANDOFF_POLL: Duration = Duration::from_millis(250);

/// Kind of the page token (OP-141 m.22 (b)).
const PAGE_TOKEN: &str = "page";

/// The domains this process leads, each taken on its first request (OP-141 m.18 (a)).
pub struct Domains<K, B: Binding, S: Salts, C> {
    setup: Setup<K, B, S, C>,
    led: Mutex<HashMap<Digest, Slot<B, S, C>>>,
    bell: Option<Arc<dyn suiss_ledger::doorbell::Bell>>,
    /// The general ingest lane of each domain (OP-157 m.3 (p)).
    lanes: crate::app::Lanes,
    standing_down: std::sync::atomic::AtomicBool,
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
            bell: None,
            lanes: crate::app::Lanes::default(),
            standing_down: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Every domain this leads rings `bell` after a durable commit (OP-156 m.3 (j)).
    #[must_use]
    pub fn with_bell(mut self, bell: Arc<dyn suiss_ledger::doorbell::Bell>) -> Self {
        self.bell = Some(bell);
        self
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
        // OP-46, OP-157 m.3 (j)
        if self.standing_down() {
            return Err(CoreError::Unavailable("leader-unhealthy"));
        }
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
            Ok(leader) => {
                // §17.8.2, TI-2
                epoch_changed("acquired");
                match &self.bell {
                    Some(bell) => leader.with_bell(bell.clone()),
                    None => leader,
                }
            }
            Err(SequencerError::Store(StoreError::LeaseHeld)) => {
                return Err(CoreError::Unavailable("lease-held"));
            }
            Err(e) => return Err(e.into()),
        };
        let reader = PgReader::new(s.app.clone(), id);
        // SAI-46
        if let Some(path) = s.signer.clone() {
            tokio::spawn(async move {
                open_keyring(&path, domain).await;
            });
        }
        let signer_open = false;
        Ok(Led {
            core: Authority::new(leader, reader, s.binding.clone(), s.salts.clone(), domain)
                .with_pseudonyms(pseudonyms)
                .with_analysis(s.analysis.clone()),
            clock: s.clock.clone(),
            tokens,
            signer_open,
        })
    }

    /// The leader of `domain` and its trusted time now.
    async fn led_now(&self, domain: Digest) -> Result<(Guard<B, S, C>, u64), CoreError> {
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        Ok((guard, now))
    }

    /// Decision lab Check on the request's domain (§8.17.10.4, §9.7): advisory, recorded
    /// nowhere. A sandbox domain is addressed the same way.
    ///
    /// # Errors
    /// As [`Authority::lab_check`].
    pub async fn lab_check(&self, inc: &Incoming) -> Result<crate::app::lab::LabCheck, CoreError> {
        let (mut guard, now) = self.led_now(inc.request.domain).await?;
        let led = guard.as_mut().ok_or(CoreError::Unavailable("leader"))?;
        led.core.lab_check(inc, now).await
    }

    /// The accepted action `namespace`/`name` of `major` in `domain` now, with its pinned
    /// schema digest (OP-151 m.20 (a)): what the console's decision lab drafts a tenant action
    /// with.
    ///
    /// # Errors
    /// As [`Authority::accepted_action`].
    pub async fn accepted_action(
        &self,
        domain: Digest,
        namespace: &str,
        name: &str,
        major: u64,
    ) -> Result<Option<access_kernel::model::ActionRef>, CoreError> {
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core.accepted_action(namespace, name, major, now).await
    }

    /// Decision lab Explain on the request's domain (§8.17.10.4).
    ///
    /// # Errors
    /// As [`Authority::lab_explain`].
    pub async fn lab_explain(
        &self,
        inc: &Incoming,
    ) -> Result<crate::app::lab::Explanation, CoreError> {
        let (mut guard, now) = self.led_now(inc.request.domain).await?;
        let led = guard.as_mut().ok_or(CoreError::Unavailable("leader"))?;
        led.core.lab_explain(inc, now).await
    }

    /// Decision lab Replay of the decision at `record` on the request's domain (§8.17.10.4,
    /// INV-27).
    ///
    /// # Errors
    /// As [`Authority::lab_replay`].
    pub async fn lab_replay(
        &self,
        inc: &Incoming,
        record: u64,
    ) -> Result<crate::app::lab::Replay, CoreError> {
        let (mut guard, now) = self.led_now(inc.request.domain).await?;
        let led = guard.as_mut().ok_or(CoreError::Unavailable("leader"))?;
        let result = led.core.lab_replay(inc, record, now).await;
        if matches!(result, Err(CoreError::Sequencer(_) | CoreError::Store(_))) {
            *guard = None;
        }
        result
    }

    /// A policy simulation over `samples` on `domain` for the auditor `caller` (§18.3).
    ///
    /// # Errors
    /// As [`Authority::lab_simulate`].
    pub async fn lab_simulate(
        &self,
        domain: Digest,
        caller: Id,
        policy: Option<Id>,
        candidate: &Value,
        samples: &[crate::app::lab::Sample],
    ) -> Result<crate::app::lab::Simulation, CoreError> {
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core
            .lab_simulate(caller, policy, candidate, samples, now)
            .await
    }

    /// A `policy.set` preview on `domain` with the control-plane analysis of the setup (§5.8,
    /// OP-105); the caller must be one of the domain's auditors.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `lab-scope` for another caller; as
    /// [`Authority::change_policy`].
    pub async fn change_policy(
        &self,
        domain: Digest,
        caller: Id,
        policy: Option<Id>,
        candidate: &Value,
    ) -> Result<crate::app::impact::PolicyChange, CoreError> {
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        if !led.core.audits(&caller, now).await? {
            return Err(CoreError::Protocol("lab-scope"));
        }
        led.core
            .change_policy(policy, candidate, self.setup.analysis.as_ref())
            .await
    }

    /// Offers `published` to each of `domains` (§8.17.10.2, E10): kept in each domain's scope,
    /// it changes none of them; each accepts only by its own `acceptance.amend`.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `publication-version` when the publisher already offered
    /// another package as this version to one of them; the store's errors.
    pub async fn keep_publication(
        &self,
        published: &crate::app::publishing::Published,
        domains: &[Digest],
    ) -> Result<bool, CoreError> {
        let p = &published.publication;
        let row = access_store::publications::PublicationRow {
            fingerprint: published.fingerprint.0,
            publisher: p.spp.publisher.0,
            namespace: p.spp.namespace.clone(),
            catalog_version: p.spp.catalog_version,
            package: p
                .to_bytes()
                .map_err(|_| CoreError::Protocol("publication"))?,
            published_ms: p.published_ms,
        };
        let mut new = false;
        for d in domains {
            let domain = DomainId::from_bytes(d.0);
            match access_store::publications::keep(&self.setup.app, &domain, &row).await? {
                access_store::publications::Kept::New => new = true,
                access_store::publications::Kept::Same => {}
                access_store::publications::Kept::VersionTaken => {
                    return Err(CoreError::Protocol("publication-version"));
                }
            }
        }
        Ok(new)
    }

    /// Publishes `draft` as the actor of `inc` and offers it to `domains` (L1-ADP-18,
    /// §8.17.10.2, E10–E12): the publisher is the Party of the request's `check` AIS on its own
    /// domain, the previous version is its latest one offered to any of `domains`, and the kept
    /// package changes none of them (X21). `Ok(Err(_))` is a package refused before it was kept.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `anonymous` for a request without an AIS; as
    /// [`Authority::publisher`] and [`Domains::keep_publication`].
    pub async fn publish(
        &self,
        inc: &Incoming,
        draft: crate::app::publishing::Draft,
        package: &Digest,
        domains: &[Digest],
    ) -> Result<
        Result<(crate::app::publishing::Published, bool), crate::app::publishing::PublishError>,
        CoreError,
    > {
        let publisher = {
            let (guard, now) = self.led_now(inc.request.domain).await?;
            let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
            let p = led
                .core
                .publisher(inc, &draft.namespace, Some(package), now)
                .await?;
            p.map(|p| (p, now))
        };
        let Some((publisher, now)) = publisher else {
            return Err(CoreError::Protocol("anonymous"));
        };
        let mut previous: Option<crate::app::publishing::Publication> = None;
        for d in domains {
            if let Some(p) = self
                .latest_publication(*d, publisher, &draft.namespace)
                .await?
                && previous
                    .as_ref()
                    .is_none_or(|q| q.spp.catalog_version < p.spp.catalog_version)
            {
                previous = Some(p);
            }
        }
        let package_kept =
            match crate::app::publishing::publish(publisher, draft, previous.as_ref(), now) {
                Ok(p) => p,
                Err(e) => return Ok(Err(e)),
            };
        let new = self.keep_publication(&package_kept, domains).await?;
        Ok(Ok((package_kept, new)))
    }

    /// Where the publication `fingerprint` of `namespace` stands in `domains`, for its
    /// publisher only (L1-ADP-18, X21); `None` when the actor of `inc` published no such package
    /// to any of them.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `anonymous` for a request without an AIS; as
    /// [`Authority::publisher`] and [`Domains::publication_status`].
    pub async fn own_publication_status(
        &self,
        inc: &Incoming,
        namespace: &str,
        fingerprint: &Digest,
        domains: &[Digest],
    ) -> Result<Option<crate::app::publishing::Status>, CoreError> {
        let publisher = {
            let (guard, now) = self.led_now(inc.request.domain).await?;
            let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
            led.core.publisher(inc, namespace, None, now).await?
        };
        let Some(publisher) = publisher else {
            return Err(CoreError::Protocol("anonymous"));
        };
        let mut found = None;
        for d in domains {
            found = access_store::publications::of_namespace(
                &self.setup.app,
                &DomainId::from_bytes(d.0),
                namespace,
            )
            .await?
            .into_iter()
            .find(|r| r.fingerprint == fingerprint.0 && r.publisher == publisher.0)
            .and_then(|r| crate::app::publishing::Publication::from_bytes(&r.package).ok());
            if found.is_some() {
                break;
            }
        }
        match found {
            Some(p) => Ok(Some(self.publication_status(&p, domains).await?)),
            None => Ok(None),
        }
    }

    /// The latest package `publisher` offered to `domain` for `namespace`.
    ///
    /// # Errors
    /// The store's errors.
    pub async fn latest_publication(
        &self,
        domain: Digest,
        publisher: Id,
        namespace: &str,
    ) -> Result<Option<crate::app::publishing::Publication>, CoreError> {
        Ok(access_store::publications::of_namespace(
            &self.setup.app,
            &DomainId::from_bytes(domain.0),
            namespace,
        )
        .await?
        .into_iter()
        .filter(|r| r.publisher == publisher.0)
        .find_map(|r| crate::app::publishing::Publication::from_bytes(&r.package).ok()))
    }

    /// Where `publication` stands in each of `domains` (§8.17.10.2, X21): the publisher's
    /// "Pending acceptance in: …". Read without leading any domain; a domain that never
    /// accepted this publisher for the namespace is left out. There is no accept here.
    ///
    /// # Errors
    /// The store's errors; [`CoreError::Unavailable`] without trusted time.
    pub async fn publication_status(
        &self,
        publication: &crate::app::publishing::Publication,
        domains: &[Digest],
    ) -> Result<crate::app::publishing::Status, CoreError> {
        let now = self
            .setup
            .clock
            .clone()
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let mut rows = Vec::new();
        for d in domains {
            rows.extend(
                access_store::publications::of_namespace(
                    &self.setup.app,
                    &DomainId::from_bytes(d.0),
                    &publication.spp.namespace,
                )
                .await?,
            );
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.catalog_version));
        let previous = rows
            .into_iter()
            .filter(|r| {
                r.publisher == publication.spp.publisher.0
                    && r.catalog_version < publication.spp.catalog_version
            })
            .find_map(|r| crate::app::publishing::Publication::from_bytes(&r.package).ok());
        let readers = domains
            .iter()
            .map(|d| {
                (
                    *d,
                    PgReader::new(self.setup.app.clone(), DomainId::from_bytes(d.0)),
                )
            })
            .collect();
        crate::app::publishing::status(publication, previous.as_ref(), readers, now).await
    }

    /// Explains the recorded decision at `record` on its domain's leader (OP-141 m.36).
    async fn explain_led(
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
        let result = self.decide(inc, None).await;
        self.audited(inc, "evaluation", result).await
    }

    /// The single-subject eligibility check of `inc` for `subject` on its domain's leader: a
    /// `check` that records nothing (OP-149 m.10).
    ///
    /// # Errors
    /// As [`Authority::eligible`].
    pub async fn eligible(&self, inc: &Incoming, subject: Id) -> Result<Response, CoreError> {
        let result = self.decide(inc, Some(subject)).await;
        self.audited(inc, "eligibility", result).await
    }

    async fn decide(&self, inc: &Incoming, subject: Option<Id>) -> Result<Response, CoreError> {
        let mut guard = self.leading(inc.request.domain).await?;
        self.decide_led(&mut guard, inc, subject, Opening::default())
            .await
    }

    /// The projection family a `projection.issue` commit belongs to, opened before the decision
    /// (OP-150 m.10 (a), §11.20): the refreshed family, or a new one named by the first 16 bytes
    /// of the `ExerciseID`, held by the Instance whose key signed the AIS, for the OAuth client of
    /// a token or else the PEP, with the next entry of the domain's newest Token Status List.
    /// The PAP's contract names the entry, so it is committed with the PAP digest. `None` for any
    /// other request, or when no Instance holds the key (the decision denies that itself).
    async fn pap_family(
        &self,
        led: &mut Led<B, S, C>,
        inc: &Incoming,
        opening: Opening<'_>,
    ) -> Result<Option<PapFamily>, CoreError> {
        let req = &inc.request;
        if req.mode != Mode::Commit || !matches!(req.payload, Some(Payload::ProjectionIssue { .. }))
        {
            return Ok(None);
        }
        let Some(holder) = led.core.holder_of(inc).await? else {
            return Ok(None);
        };
        let domain = req.domain;
        let id = DomainId::from_bytes(domain.0);
        let exercise =
            meta::exercise_id(&domain, &req.nonce).map_err(|_| CoreError::Protocol("nonce"))?;
        let mut f = [0; 16];
        f.copy_from_slice(exercise.0.get(..16).ok_or(CoreError::Protocol("family"))?);
        let family = opening.family.unwrap_or(f);
        let fresh = Family {
            family,
            client_id: opening.client.unwrap_or(&inc.pep).to_owned(),
            holder: holder.0,
            root_exercise: exercise.0,
            status: None,
            revoked_pos: None,
        };
        let (status, opened) = if opening.family.is_some() {
            (
                read_family(&self.setup.app, &id, &family)
                    .await?
                    .and_then(|row| row.status),
                false,
            )
        } else {
            match open_family(&self.setup.sequencer, &self.setup.api_base, domain, &fresh).await? {
                Some(entry) => {
                    // INV-5
                    let basis = suiss_crypto::dcbor::encode(
                        &access_kernel::meta::basis_value(&req.basis),
                        suiss_crypto::dcbor::Limits::CEILING,
                    )
                    .map_err(|_| CoreError::Protocol("basis"))?;
                    access_store::projections::keep_basis(
                        &self.setup.sequencer,
                        &id,
                        &family,
                        &basis,
                    )
                    .await?;
                    (Some(entry), true)
                }
                None => (
                    read_family(&self.setup.app, &id, &family)
                        .await?
                        .filter(|row| row.holder == holder.0)
                        .and_then(|row| row.status),
                    false,
                ),
            }
        };
        Ok(status.map(|(uri, idx)| PapFamily {
            family,
            status: StatusRef { idx, uri },
            opened,
        }))
    }

    /// Keeps the contract of an allowed projection beside its record (§9.12, §9.12.2,
    /// §13.7.4): what the issuance limits, the report deadline and the reconciliation read.
    async fn keep_contract(&self, inc: &Incoming, r: &Response) -> Result<(), CoreError> {
        let (Some(pos), Some(payload), false) = (r.record, &r.pap, r.replayed) else {
            return Ok(());
        };
        if r.decision.outcome != Outcome::Allow {
            return Ok(());
        }
        let pap = Pap::from_bytes(payload).map_err(|_| CoreError::Protocol("pap"))?;
        let contract = pap
            .validity
            .to_bytes()
            .map_err(|_| CoreError::Protocol("validity"))?;
        let row = ContractRow {
            exercise: pap.projection_exercise.0,
            pos,
            holder: pap.holder.instance.0,
            pep: inc.pep.clone(),
            class: String::from(class_word(pap.validity.class)),
            variant: String::from(variant_word(pap.validity.variant)),
            iat_ms: pap.iat,
            horizon_ms: pap.validity.horizon,
            audiences: pap.validity.audience.iter().cloned().collect(),
            namespaces: namespaces(&pap.bounds),
            slice: !pap.validity.offline_slice.is_empty(),
            contract_digest: suiss_crypto::digest::context_digest(CONTRACT_LABEL, &contract).0,
            contract,
        };
        let id = DomainId::from_bytes(inc.request.domain.0);
        Ok(insert_contract(&self.setup.sequencer, &id, &row).await?)
    }

    /// [`Domains::decide`] on the leader in `guard`, which the caller holds across whatever
    /// must not interleave with another commit of the domain.
    async fn decide_led(
        &self,
        guard: &mut Guard<B, S, C>,
        inc: &Incoming,
        subject: Option<Id>,
        opening: Opening<'_>,
    ) -> Result<Response, CoreError> {
        let domain = inc.request.domain;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        // OP-150 m.10 (a)
        let family = self.pap_family(led, inc, opening).await?;
        let with_status: Option<Box<Incoming>> = family.as_ref().map(|f| {
            Box::new(Incoming {
                status: Some(f.status.clone()),
                ..inc.clone()
            })
        });
        let inc = with_status.as_deref().unwrap_or(inc);
        // OP-141 m.22 (f)
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
        if let Ok(r) = &mut result {
            self.sign_artefacts(led, domain, r, now).await;
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
        // §9.9.3 k.6, P50
        if let Ok(r) = &result
            && let Some(pos) = r.record
            && !r.replayed
        {
            for holder in &r.ended {
                if let Err(e) = crate::status::adapters::revoke_holder(
                    &self.setup.sequencer,
                    domain,
                    &holder.0,
                    pos,
                )
                .await
                {
                    result = Err(e);
                    break;
                }
            }
        }
        self.settle_projection(led, inc, family.as_ref(), &mut result)
            .await;
        if matches!(result, Err(CoreError::Sequencer(_) | CoreError::Store(_))) {
            **guard = None;
        }
        result
    }

    /// The receipt and the PAP of a decision, signed after the commit (§9.8, L2-RCP-2, L2-PAP-2);
    /// without a signer they wait unsigned. The receipt is kept for `GET
    /// /access/v1/exercises/{id}` (OP-149 m.9); without it the answer comes from state.
    async fn sign_artefacts(
        &self,
        led: &mut Led<B, S, C>,
        domain: Digest,
        r: &mut Response,
        now: u64,
    ) {
        if let Some(path) = &self.setup.signer
            && let Some(payload) = r.receipt.clone()
        {
            r.signed_receipt = sign_artefact(path, led, domain, Artefact::Receipt, payload, now)
                .await
                .ok();
        }
        if let (Some(payload), Some(exercise), Some(pos)) = (&r.receipt, r.exercise, r.record) {
            let row = ReceiptRow {
                exercise: exercise.0,
                pos,
                payload: payload.clone(),
                signed: r.signed_receipt.clone(),
            };
            let _ =
                keep_receipt(&self.setup.sequencer, &DomainId::from_bytes(domain.0), &row).await;
        }
        if let Some(path) = &self.setup.signer
            && let Some(payload) = r.pap.clone()
        {
            r.signed_pap = sign_artefact(path, led, domain, Artefact::Pap, payload, now)
                .await
                .ok();
        }
    }

    /// After a `projection.issue` decision: the contract of an allowed one is kept with its
    /// record (§9.12, §13.7.4); a family opened for a decision that did not allow holds no
    /// projection, so its entry is set at once and nothing can ever be presented against it
    /// (OP-73: the row stays). A store failure replaces the result.
    async fn settle_projection(
        &self,
        led: &Led<B, S, C>,
        inc: &Incoming,
        family: Option<&PapFamily>,
        result: &mut Result<Response, CoreError>,
    ) {
        if let Ok(r) = &*result
            && let Err(e) = self.keep_contract(inc, r).await
        {
            *result = Err(e);
        }
        let Some(f) = family.filter(|f| f.opened) else {
            return;
        };
        if matches!(&*result, Ok(r) if r.decision.outcome == Outcome::Allow && !r.replayed) {
            return;
        }
        let head = led.core.head().max(1);
        let pos = match &*result {
            Ok(r) => r.record.unwrap_or(head),
            Err(_) => head,
        };
        if let Err(e) = access_store::projections::revoke_family(
            &self.setup.sequencer,
            &DomainId::from_bytes(inc.request.domain.0),
            &f.family,
            pos,
        )
        .await
        {
            *result = Err(e.into());
        }
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

    /// Leads `domain` here for a one-shot job (OP-149 m.28 (a)): when another process holds
    /// its lease, that leader is asked to hand it over and this waits for the release, up to
    /// [`HANDOFF_WAIT`] lease lengths. The lease itself is never taken from a live leader;
    /// the leader releases it at its next renewal and leads again on its next request.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] with `lease-held` when the leader did not hand over in time;
    /// [`CoreError`] for anything else that stops the domain being led here.
    pub async fn take_over(&self, domain: Digest) -> Result<(), CoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.setup.ttl.saturating_mul(HANDOFF_WAIT))
            .ok_or(CoreError::Unavailable("time"))?;
        let mut asked = false;
        loop {
            match self.leading(domain).await {
                Ok(_) => return Ok(()),
                Err(CoreError::Unavailable("lease-held")) => {}
                Err(e) => return Err(e),
            }
            if !asked {
                let id = DomainId::from_bytes(domain.0);
                asked =
                    request_lease_handoff(&self.setup.sequencer, &id, &self.setup.holder).await?;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(CoreError::Unavailable("lease-held"));
            }
            tokio::time::sleep(HANDOFF_POLL).await;
        }
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
        let result = self.search_led(inc, query, page).await;
        let (hits, next, audited) = self.audited(inc, "search", result).await?;
        // U53, OP-44
        if let Some(instance) = audited {
            self.operational(
                inc,
                (
                    audit::AUDIT_EVENT_READ,
                    &audit::who(inc, Some(&instance)),
                    &format!("report:{}", query.kind()),
                    "report",
                ),
            )
            .await?;
        }
        Ok((hits, next))
    }

    async fn search_led(
        &self,
        inc: &Incoming,
        query: &Query,
        page: Option<&str>,
    ) -> Result<(Vec<Hit>, Option<String>, Option<Id>), CoreError> {
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
        // §9.7.1
        let found = tokio::time::timeout(SEARCH_DEADLINE, led.core.search(inc, query, after, now))
            .await
            .map_err(|_| CoreError::Unavailable("deadline"))??;
        let next = found
            .next
            .map(|n| led.tokens.seal(&domain.0, PAGE_TOKEN, &page_body(&n)))
            .transpose()
            .map_err(|_| CoreError::Unavailable("token-key"))?;
        Ok((found.hits, next, found.audited))
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
        let pos = self.position(&id, head, as_of).await?;
        if cursor(&self.setup.app, &id).await? < pos {
            return Err(CoreError::Unavailable("index"));
        }
        let rows = keys_of(&self.setup.app, &id, kids).await?;
        let mut parties: BTreeMap<[u8; 16], (ActorKind, Vec<Compromise>)> = BTreeMap::new();
        for r in &rows {
            if let std::collections::btree_map::Entry::Vacant(slot) = parties.entry(r.party) {
                let party = Id(r.party);
                // OP-149 m.8
                let kind = led
                    .core
                    .actor_kind(&party)
                    .await?
                    .ok_or(CoreError::Store(StoreError::Corrupt))?;
                slot.insert((kind, led.core.compromises(&party, now).await?));
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
                let (kind, c) = parties.get(&r.party)?;
                keys::entry(r, pos, *kind, c)
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

    /// The ledger position a lookup at `as_of` reads, given the leader's `head`.
    async fn position(
        &self,
        id: &DomainId,
        head: u64,
        as_of: keys::AsOf,
    ) -> Result<u64, CoreError> {
        Ok(match as_of {
            keys::AsOf::Head => head,
            keys::AsOf::Position(p) if p <= head => p,
            keys::AsOf::Position(_) => return Err(CoreError::Unavailable("consistency")),
            keys::AsOf::Time(t) => position_at(&self.setup.app, id, t)
                .await?
                .ok_or(CoreError::Protocol("as_of"))?
                .min(head),
        })
    }

    /// The Parties `parties` of `domain` at `as_of` (OP-149 m.28 (c)): each Party's state as
    /// the leader holds it, read back to the position asked, with the trusted times of the
    /// records that admitted and ended it; with `sign` the payload is signed under usage
    /// `party-lookup`. Nothing is recorded.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] for more than [`parties::MAX_PARTIES`] Parties or a time before
    /// the domain's Genesis; [`CoreError::Unavailable`] for a position past the head.
    pub async fn lookup_parties(
        &self,
        domain: Digest,
        parties: &[Id],
        as_of: keys::AsOf,
        sign: bool,
    ) -> Result<PartyAnswer, CoreError> {
        if parties.is_empty() || parties.len() > parties::MAX_PARTIES {
            return Err(CoreError::Protocol("parties"));
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
        let head = led.core.head();
        let pos = self.position(&id, head, as_of).await?;
        let mut lookup = parties::Lookup {
            domain,
            pos,
            iat: now,
            parties: Vec::with_capacity(parties.len()),
            unknown: Vec::new(),
        };
        for party in parties {
            let found = match led.core.party_state(party).await? {
                Some(state) if state.since <= pos => {
                    let since_at = recorded_at(&self.setup.app, &id, state.since).await?;
                    let ended_at = match state.ended.as_ref().filter(|e| e.at <= pos) {
                        Some(e) => Some(recorded_at(&self.setup.app, &id, e.at).await?),
                        None => None,
                    };
                    parties::entry(*party, &state, pos, since_at, ended_at)
                }
                _ => None,
            };
            match found {
                Some(e) => lookup.parties.push(e),
                None => lookup.unknown.push(*party),
            }
        }
        let consistency = led
            .tokens
            .seal(&domain.0, CONSISTENCY, &head.to_be_bytes())
            .map_err(|_| CoreError::Unavailable("token-key"))?;
        let signed = match (sign, &self.setup.signer) {
            (true, Some(path)) => {
                let payload = parties::payload(&lookup);
                Some(
                    sign_artefact(path, led, domain, Artefact::PartyLookup, payload, now)
                        .await
                        .map_err(CoreError::Unavailable)?,
                )
            }
            (true, None) => return Err(CoreError::Unavailable("signer")),
            (false, _) => None,
        };
        Ok(PartyAnswer {
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

    /// The domains led here.
    #[must_use]
    pub fn led(&self) -> Vec<Digest> {
        self.led
            .lock()
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Brings the derived index of every domain led here up to its head (OP-141 m.22 (g)); the
    /// failures are returned and left for the next round.
    pub async fn derive(&self) -> Vec<CoreError> {
        let mut failed = Vec::new();
        for d in self.led() {
            if let Err(error) = derive(&self.setup.deriver, d).await {
                failed.push(error);
            }
        }
        failed
    }

    /// Extends every held lease; a domain whose lease is lost is dropped (OP-130 m.6), and one
    /// another process asked for is released to it (OP-149 m.28 (a)) and led again on the next
    /// request here.
    pub async fn renew(&self) {
        for slot in self.slots() {
            let mut guard = slot.lock().await;
            let Some(led) = guard.as_ref() else {
                continue;
            };
            match led.core.renew().await {
                Ok(Renewal::Extended) => {}
                Ok(Renewal::HandoffRequested) => {
                    if let Some(led) = guard.take() {
                        epoch_changed("handoff");
                        let _ = led.core.release().await;
                    }
                }
                Err(_) => {
                    // §17.8.2, TI-2, OP-130 m.6
                    access_authority_sequencer::app::fenced("renew_failed");
                    *guard = None;
                }
            }
        }
    }

    /// An operator directive marked this process's leader unhealthy (OP-46, OP-157 m.3 (j)), or
    /// cleared the mark: while marked it gives every lease up and takes none, so another process
    /// leads under a new, fencing epoch. No record is written and nothing is decided.
    pub async fn stand_down(&self, unhealthy: bool) {
        let was = self
            .standing_down
            .swap(unhealthy, std::sync::atomic::Ordering::SeqCst);
        if unhealthy {
            if !was {
                epoch_changed("stand_down");
            }
            self.release().await;
        }
    }

    /// Whether an operator directive holds this process off leading.
    #[must_use]
    pub fn standing_down(&self) -> bool {
        self.standing_down.load(std::sync::atomic::Ordering::SeqCst)
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

/// A Party status lookup answer (OP-149 m.28 (c)).
#[derive(Clone, Debug)]
pub struct PartyAnswer {
    /// The Parties at the answer's position.
    pub lookup: parties::Lookup,
    /// The head it was answered at, as an opaque token (OP-141 m.22 (f)).
    pub consistency: String,
    /// The signed `party-lookup` payload and its key excerpt, when asked for.
    pub signed: Option<(Vec<u8>, Vec<u8>)>,
}

/// The trusted time the record at `pos` of `domain` was committed at.
async fn recorded_at(app: &Pool, domain: &DomainId, pos: u64) -> Result<u64, CoreError> {
    read_log(app, domain, pos, pos)
        .await?
        .into_iter()
        .next()
        .map(|r| r.recorded_at)
        .ok_or(CoreError::Store(StoreError::Corrupt))
}

/// What a decision point asks the signer to sign.
#[derive(Clone, Copy)]
enum Artefact {
    Receipt,
    Pap,
    KeyLookup,
    PartyLookup,
}

/// The signer's stable error codes; a code not listed reads as `signer-error`.
const SIGNER_CODES: [&str; 9] = [
    "signer-binding",
    "signer-unknown-domain",
    "signer-time",
    "signer-no-key",
    "signer-usage",
    "signer-encode",
    "signer-note",
    "signer-token",
    "signer-token-horizon",
];

/// The stable reason of a signer's refusal (OP-149 m.5): an operational key signs only
/// `T_publish_lead` after it is published (SAI-46; the founding key at once, CR-59), and
/// without one the signer answers `signer-no-key`.
pub(crate) fn signer_reason(code: &str) -> &'static str {
    SIGNER_CODES
        .into_iter()
        .find(|c| *c == code)
        .unwrap_or("signer-error")
}

/// Opens the keyring of `domain` in the signer at `path`, so that its key schedule runs; the
/// signer keeps an open keyring as it is (OP-143 m.4).
pub(crate) async fn open_keyring(path: &std::path::Path, domain: Digest) -> bool {
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
        Artefact::PartyLookup => (KeyUsage::PartyLookup, parties::CONTENT_TYPE),
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

mod ingest;

/// What a decision point left for the approval of an intent (§9.14.1 step 1, OP-150 L6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    /// The render digest.
    pub render: Digest,
    /// The render, dCBOR, when kept.
    pub render_bytes: Option<Vec<u8>>,
    /// The tier.
    pub tier: access_kernel::tier::Tier,
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// The latest `REQUIRE_ACTION` on `intent` in `domain` with its render, read from the
    /// store without the leader.
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn asked(&self, domain: Digest, intent: &Digest) -> Result<Option<Asked>, CoreError> {
        let scope = DomainId::from_bytes(domain.0);
        let Some(row) =
            access_store::authority::find_opening(&self.setup.app, &scope, &intent.0).await?
        else {
            return Ok(None);
        };
        let tier =
            crate::app::approval::tier_of(row.tier).ok_or(CoreError::Store(StoreError::Corrupt))?;
        let render_bytes =
            access_store::claims::proof(&self.setup.app, &scope, &row.render_digest).await?;
        Ok(Some(Asked {
            render: Digest(row.render_digest),
            render_bytes,
            tier,
        }))
    }
}

/// Counts a leader epoch change by `reason` (§17.8.2, TI-2, FA-13).
fn epoch_changed(reason: &'static str) {
    access_telemetry::signals::LEADER_EPOCH_CHANGES.incr([reason]);
    tracing::info!(
        event = "sequencer.epoch.changed",
        outcome = "ok",
        reason,
        "sequencer leader epoch changed"
    );
}
