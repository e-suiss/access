//! What the management API needs from the outside world (OP-63): time, randomness, the read
//! token and Instance key verifiers, the surface's domain, the write path, the idempotency store
//! and the rate limiter. Every port fails closed: [`Unavailable`] refuses the request (MD-8).

use std::future::Future;
use std::pin::Pin;

use access_kernel::digest::Digest;
use access_kernel::verify::cose::PublicKey;

use super::domain::SurfaceScope;
use super::domain::caller::WriteCaller;
use super::domain::rate::{BucketKey, Quota, Take};

/// A port could not answer; the request is refused with `503` (MD-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unavailable")]
pub struct Unavailable;

/// Trusted time (OP-63: the clock is a port).
pub trait Clock: Send + Sync {
    /// Unix time in milliseconds.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn now_ms(&self) -> Result<u64, Unavailable>;
}

/// Randomness (OP-63: the RNG is a port).
pub trait Entropy: Send + Sync {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable>;
}

/// What the request presents as its read token: `Authorization: DPoP <token>` and its `DPoP`
/// proofs, with the method and URI the proof must name (RFC 9449).
#[derive(Clone, Copy, Debug)]
pub struct Presented<'a> {
    /// The access token.
    pub token: &'a str,
    /// The `DPoP` header values.
    pub proofs: &'a [&'a str],
    /// The request method.
    pub method: &'a str,
    /// The request URI the proof's `htu` names: the configured management origin and the path.
    pub uri: &'a str,
}

/// A read token the verifier accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadToken {
    /// Its one audience.
    pub audience: String,
    /// Its scopes.
    pub scopes: Vec<String>,
    /// The holder's subject, pseudonymous.
    pub subject: String,
    /// Issued at, Unix milliseconds.
    pub issued_at_ms: u64,
    /// Expires at, Unix milliseconds.
    pub expires_at_ms: u64,
    /// A stable digest of the token, the per-token rate limit key.
    pub id: [u8; 32],
}

/// Verifies management read tokens (TN-27, TN-130, OP-151 m.3 (c)).
pub trait ReadTokens: Send + Sync {
    /// The token if its signature verifies with the issuing realm's keys, its DPoP proof binds
    /// it to the presenting holder for this method and URI, and it is not revoked (session and
    /// key epochs, OP-21); `None` otherwise. Audience, scope and lifetime are the caller
    /// model's checks, not the verifier's.
    fn verify(
        &self,
        presented: Presented<'_>,
    ) -> impl Future<Output = Result<Option<ReadToken>, Unavailable>> + Send;
}

/// The governing domains and live Instance keys behind the management surfaces (PI-7, TN-119).
pub trait Surfaces: Send + Sync {
    /// The surface's governing domain; `None` when there is no such realm.
    fn domain(
        &self,
        scope: &SurfaceScope,
    ) -> impl Future<Output = Result<Option<Digest>, Unavailable>> + Send;

    /// The live key of the Instance `kid` (RFC 7638 thumbprint) in `domain` at `at_ms`; `None`
    /// when no live Instance of the domain has it.
    fn instance_key(
        &self,
        domain: Digest,
        kid: [u8; 32],
        at_ms: u64,
    ) -> impl Future<Output = Result<Option<PublicKey>, Unavailable>> + Send;
}

/// What a request under an `Idempotency-Key` does (TN-126).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Begun {
    /// Run it.
    Run,
    /// Answer with the kept answer.
    Replay(Vec<u8>),
    /// Another request ran under the key: `422`.
    Reused,
    /// The same request is still running: `409`.
    Running,
}

/// Keeps the first answer under each key for [`super::domain::idempotency::RETENTION_MS`]
/// (TN-126, OP-151 m.3 (c)).
pub trait IdempotencyStore: Send + Sync {
    /// Claims `scope` for `request`, or tells what it holds.
    fn begin(
        &self,
        scope: [u8; 32],
        request: [u8; 32],
        now_ms: u64,
    ) -> impl Future<Output = Result<Begun, Unavailable>> + Send;

    /// Keeps `answer`, or releases the key when `None`.
    fn finish(
        &self,
        scope: [u8; 32],
        request: [u8; 32],
        answer: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
}

/// The three rate limit layers behind one interface (TN-127, OP-151 m.3 (d)): token buckets
/// and concurrency slots. In process; exact across nodes is not promised.
pub trait RateLimiter: Send + Sync {
    /// Takes one token from `key`'s bucket under `quota` at `now_ms`.
    fn take(&self, key: &BucketKey, quota: Quota, now_ms: u64) -> Take;

    /// Enters one of `max` concurrency slots of `key`; `false` when all are taken.
    fn enter(&self, key: &str, max: u32) -> bool;

    /// Leaves a slot [`RateLimiter::enter`] gave.
    fn leave(&self, key: &str);
}

/// Seals list cursors (OP-65): the next position, opaque to the client and bound to the list
/// that issued it.
pub trait CursorSeal: Send + Sync {
    /// The cursor text for `position` under `context`.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn seal(&self, context: &[u8], position: &[u8]) -> Result<String, Unavailable>;

    /// The position of a cursor sealed under `context`; `None` for any other text.
    fn open(&self, context: &[u8], cursor: &str) -> Option<Vec<u8>>;
}

/// A port answer that may be pending, boxed so [`RealmResources`] stays object safe.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Unavailable>> + Send + 'a>>;

/// A readable kind of realm resource (OP-151 m.2 M1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    /// Clients, by `client_id`.
    Clients,
    /// Groups, by name.
    Groups,
    /// Accounts, by `account_id`.
    Accounts,
    /// Upstream identity providers, by name.
    UpstreamIdps,
    /// The settings singleton.
    Settings,
    /// Inline hooks, by `hook_id` (TN-135).
    Hooks,
    /// Webhooks, by `webhook_id` (TN-136).
    Webhooks,
    /// The realm's signal sources singleton (§8.13).
    Signals,
    /// The realm's sign-in analytics singleton (IDP-36).
    Analytics,
    /// One webhook's delivery log, by `webhook_id` (TN-136).
    Deliveries,
    /// Social presets, by preset id (IDP-31).
    SocialProviders,
    /// Organizations, by their Party's base64url (§8.5 S7, OP-153 m.10 (c)).
    Organizations,
}

impl ResourceKind {
    /// Its name in `ETag`s and cursors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Clients => "clients",
            Self::Groups => "groups",
            Self::Accounts => "accounts",
            Self::UpstreamIdps => "upstream-idps",
            Self::Settings => "settings",
            Self::Hooks => "hooks",
            Self::Webhooks => "webhooks",
            Self::Signals => "signals",
            Self::Analytics => "analytics",
            Self::Deliveries => "deliveries",
            Self::SocialProviders => "social-providers",
            Self::Organizations => "organizations",
        }
    }
}

/// A read of one realm resource, or of one page of a collection (TN-113: the answer holds only
/// what the realm may see; the handler filters nothing).
#[derive(Clone, Debug)]
pub struct ResourceQuery {
    /// The realm's slug.
    pub slug: String,
    /// What to read.
    pub kind: ResourceKind,
    /// One resource's natural key; `None` for a page.
    pub key: Option<String>,
    /// The natural key the page starts after.
    pub after: Option<String>,
    /// Page size.
    pub limit: u32,
}

/// One resource as read: its JSON view and the position of the decision that last changed it.
#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    /// The view, with no credential field (TN-61).
    pub body: serde_json::Value,
    /// Its version, the `ETag`'s source.
    pub version: u64,
}

/// What a read found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Listing {
    /// The items.
    pub items: Vec<Item>,
    /// The natural key the next page starts after, when there may be one.
    pub last: Option<String>,
}

/// A write to a realm resource, as one manifest operation with its natural key and its JSON body
/// (a merge patch already applied).
#[derive(Clone, Debug)]
pub struct ResourceWrite {
    /// The realm's slug.
    pub slug: String,
    /// Its governing domain.
    pub domain: Digest,
    /// The manifest operation.
    pub operation: &'static str,
    /// The path's natural key.
    pub key: Option<String>,
    /// The body, without the AIS.
    pub body: serde_json::Value,
    /// Trusted time of the request, Unix milliseconds.
    pub now_ms: u64,
}

/// The intent a write compiles to, for the caller to sign (TN-110, PI-7).
#[derive(Clone, Debug, PartialEq)]
pub struct Draft {
    /// The body to send with the AIS: the request's, with its validity and any server-assigned
    /// key filled in.
    pub body: serde_json::Value,
    /// The governing domain the AIS names.
    pub domain: Digest,
    /// Deterministic CBOR of the intent.
    pub intent: Vec<u8>,
    /// Its digest, which the AIS signs.
    pub intent_digest: Digest,
    /// The PEP the AIS addresses.
    pub pep: String,
}

/// What a write did.
#[derive(Clone, Debug, PartialEq)]
pub enum Written {
    /// Committed: the Exercise record and the resource as it now is.
    Committed {
        /// The `ExerciseID`.
        exercise_id: Digest,
        /// Its position in the domain's log.
        position: u64,
        /// The resource after the write, when it has a view.
        resource: Option<Item>,
        /// A server-generated secret, shown this once and never kept (CR-38): a client secret,
        /// or a hook's or webhook's verification key (TN-135, TN-136).
        secret: Option<String>,
    },
    /// Recorded by the identity plane and not yet decided: an ownership handover's proposal
    /// waits for its recipient and its delay (TN-91).
    Accepted {
        /// The identity-plane record, base64url.
        record: String,
    },
    /// Decided and not allowed; nothing changed.
    NotAllowed,
    /// Refused before a decision with this problem; nothing changed.
    Rejected(&'static crate::problem::Code),
}

/// One core meta-action write of a bulk job (E17, TN-125): a Grant revoke or amend, decoded
/// as ADP decodes a `commit`, with its own AIS.
#[derive(Clone, Debug)]
pub struct MetaWrite {
    /// The realm's slug.
    pub slug: String,
    /// What the write is for beyond its meta-action, when the identity plane keeps a record of
    /// it.
    pub target: Option<MetaTarget>,
    /// The request: domain, nonce, intent, payload, basis and capacity.
    pub request: access_authority_core::domain::Request,
}

/// The identity-plane record a meta-action item of a job belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetaTarget {
    /// An accepted invitation's role Grant: the organization's id and the member's
    /// `account_id` (TN-89 (3)).
    Role([u8; 16], String),
    /// An ownership handover's proposal: the organization's Party and the proposing owner's
    /// and the recipient's `account_id` (TN-91).
    ProposeHandover([u8; 16], String, String),
    /// A contributed handover's completion: the organization's Party and the handover (TN-91).
    CompleteHandover([u8; 16], [u8; 16]),
    /// An organization's autojoin role Grant, held by its `org_member` Claims: the
    /// organization's Party (TN-90, OP-153 m.25 (i) (3)).
    Autojoin([u8; 16]),
}

/// What a draft found.
#[derive(Clone, Debug, PartialEq)]
pub enum Drafted {
    /// The intent to sign.
    Draft(Draft),
    /// The write cannot be made, with this problem.
    Rejected(&'static crate::problem::Code),
}

/// The realm resources behind the realm-admin surface (OP-151 m.2 M1): reads scoped to the realm
/// in the store (TN-113), drafts of the intent a write compiles to, and commits of exactly one
/// `idp.*` Exercise per write through the identity plane (TN-110, PI-4, INV-2).
pub trait RealmResources: Send + Sync {
    /// Reads; `None` when there is no such realm.
    fn read(&self, query: ResourceQuery) -> Pending<'_, Option<Listing>>;

    /// The intent `write` compiles to; nothing is decided or changed.
    fn draft(&self, write: ResourceWrite) -> Pending<'_, Drafted>;

    /// Commits `write` with the caller's verified AIS.
    fn commit(&self, write: ResourceWrite, caller: WriteCaller) -> Pending<'_, Written>;

    /// A page of the realm's full-taxonomy audit stream (channel B) in `query.format`, after
    /// the read itself was audited (OP-41, OP-44); `None` when there is no such realm. None by
    /// default.
    fn audit(&self, query: AuditQuery) -> Pending<'_, Option<Listing>> {
        let _ = query;
        Box::pin(async { Err(Unavailable) })
    }

    /// The inclusion proof of one audit event in the realm's own audit tree, after the read
    /// itself was audited (OP-152 m.7 (d), OP-44); `None` when there is no such realm or the
    /// event is not in a signed realm checkpoint yet. None by default.
    fn audit_proof(&self, query: AuditProofQuery) -> Pending<'_, Option<serde_json::Value>> {
        let _ = query;
        Box::pin(async { Err(Unavailable) })
    }

    /// Commits one meta-action write of a bulk job with the caller's verified AIS, as its own
    /// Exercise (E17, TN-125). None by default.
    fn exercise(&self, write: MetaWrite, caller: WriteCaller) -> Pending<'_, Written> {
        let _ = (write, caller);
        Box::pin(async { Err(Unavailable) })
    }
}

/// A read of one audit event's realm inclusion proof (OP-152 m.7 (d)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditProofQuery {
    /// The realm's slug.
    pub slug: String,
    /// The event, as the audit stream names it.
    pub event: String,
    /// The reader, the read token's pseudonymous subject.
    pub reader: String,
}

/// A rendering of the full-taxonomy audit stream, channel B (OP-41, §17.6.8): a copy, not the
/// record (X22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditFormat {
    /// An OCSF event object.
    Ocsf,
    /// A CEF line.
    Cef,
    /// The claims of a Security Event Token (RFC 8417).
    Set,
}

impl AuditFormat {
    /// The format a `format` query value names.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ocsf" => Some(Self::Ocsf),
            "cef" => Some(Self::Cef),
            "set" => Some(Self::Set),
            _ => None,
        }
    }
}

/// A read of one page of the realm's audit stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditQuery {
    /// The realm's slug.
    pub slug: String,
    /// The rendering.
    pub format: AuditFormat,
    /// The event the page starts after, as a previous page's `last`.
    pub after: Option<String>,
    /// Page size.
    pub limit: u32,
    /// The reader, the read token's pseudonymous subject, as the `audit.read` event names it.
    pub reader: String,
}

/// Realm resources that do not exist: every read finds no realm and every write is refused
/// (MD-8). The default until a process wires its own.
pub struct NoRealmResources;

impl RealmResources for NoRealmResources {
    fn read(&self, _: ResourceQuery) -> Pending<'_, Option<Listing>> {
        Box::pin(async { Ok(None) })
    }

    fn draft(&self, _: ResourceWrite) -> Pending<'_, Drafted> {
        Box::pin(async { Err(Unavailable) })
    }

    fn commit(&self, _: ResourceWrite, _: WriteCaller) -> Pending<'_, Written> {
        Box::pin(async { Err(Unavailable) })
    }
}

/// A readable kind of platform resource (OP-151 m.2 M2): metadata only (INV-29, X31).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformKind {
    /// Tenants, by opaque `tenant_id`.
    Tenants,
    /// Realms, by slug: their metadata, never their settings or content.
    Realms,
    /// Sandbox domains, by their realm's slug.
    SandboxDomains,
    /// The operator's health summary, without secrets.
    Health,
}

impl PlatformKind {
    /// Its name in cursors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tenants => "tenants",
            Self::Realms => "realms",
            Self::SandboxDomains => "sandbox-domains",
            Self::Health => "health",
        }
    }
}

/// A read of platform metadata: one resource, or one page of a collection, optionally within a
/// tenant.
#[derive(Clone, Debug)]
pub struct PlatformQuery {
    /// What to read.
    pub kind: PlatformKind,
    /// The tenant the collection is in, for realms and sandbox domains.
    pub tenant: Option<String>,
    /// One resource's natural key; `None` for a page.
    pub key: Option<String>,
    /// The natural key the page starts after.
    pub after: Option<String>,
    /// Page size.
    pub limit: u32,
}

/// A provisioning write (OP-151 m.2 M2): one manifest operation, the tenant its path names and
/// its JSON body.
#[derive(Clone, Debug)]
pub struct PlatformWrite {
    /// The platform's governing domain.
    pub domain: Digest,
    /// The manifest operation.
    pub operation: &'static str,
    /// The tenant the path names.
    pub tenant: Option<String>,
    /// The body, without the AIS.
    pub body: serde_json::Value,
    /// Trusted time of the request, Unix milliseconds.
    pub now_ms: u64,
}

/// The platform resources behind the platform-admin surface (OP-151 m.2 M2): metadata reads
/// across tenants that never include realm content (INV-29, X31), drafts of the intent a write
/// compiles to, and commits of exactly one `idp.platform.*` Exercise per write in the platform
/// realm's governing domain (TN-110, PI-4, INV-2).
pub trait PlatformResources: Send + Sync {
    /// Reads; `None` when the tenant or resource does not exist.
    fn read(&self, query: PlatformQuery) -> Pending<'_, Option<Listing>>;

    /// The intent `write` compiles to; nothing is decided or changed.
    fn draft(&self, write: PlatformWrite) -> Pending<'_, Drafted>;

    /// Commits `write` with the caller's verified AIS.
    fn commit(&self, write: PlatformWrite, caller: WriteCaller) -> Pending<'_, Written>;
}

/// Platform resources that are not wired: every request is unavailable (MD-8).
pub struct NoPlatformResources;

impl PlatformResources for NoPlatformResources {
    fn read(&self, _: PlatformQuery) -> Pending<'_, Option<Listing>> {
        Box::pin(async { Err(Unavailable) })
    }

    fn draft(&self, _: PlatformWrite) -> Pending<'_, Drafted> {
        Box::pin(async { Err(Unavailable) })
    }

    fn commit(&self, _: PlatformWrite, _: WriteCaller) -> Pending<'_, Written> {
        Box::pin(async { Err(Unavailable) })
    }
}

/// A bulk job to record (TN-125): its mode, the Instance whose AIS submitted it, and each
/// item's operation and natural key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewJob {
    /// `sequential` or `parallel`.
    pub mode: &'static str,
    /// The submitting Instance's `kid`.
    pub actor: [u8; 32],
    /// Each item's operation and natural key, in order.
    pub items: Vec<(String, Option<String>)>,
    /// Accepted at, Unix milliseconds.
    pub created_ms: u64,
    /// Shown until.
    pub expires_ms: u64,
}

/// A job as read: its counts, so a throttled item is visible on the envelope (TN-125).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobView {
    /// Its id, a UUID.
    pub id: String,
    /// `sequential` or `parallel`.
    pub mode: String,
    /// `running`, `succeeded`, `partial` or `failed`.
    pub status: String,
    /// Items in it.
    pub items: u32,
    /// Items committed.
    pub committed: u32,
    /// Items refused, not allowed, unavailable or not run for a failed dependency.
    pub failed: u32,
    /// Items refused by a rate limit.
    pub throttled: u32,
    /// Accepted at, Unix milliseconds.
    pub created_ms: u64,
    /// Finished at.
    pub finished_ms: Option<u64>,
    /// Shown until.
    pub expires_ms: u64,
}

/// One item's outcome: the Exercise it committed or why not (TN-125's per-item error file).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobItem {
    /// Its place in the job.
    pub index: u32,
    /// The write operation.
    pub operation: String,
    /// The natural key it names.
    pub key: Option<String>,
    /// `pending`, `committed`, `accepted`, `not_allowed`, `rejected`, `throttled`, `failed_dependency` or
    /// `unavailable`.
    pub status: String,
    /// The status the write answered with.
    pub http_status: Option<u16>,
    /// The problem code of a refusal.
    pub problem: Option<String>,
    /// The committed Exercise, base64url.
    pub exercise_id: Option<String>,
    /// Its log position.
    pub position: Option<u64>,
}

/// Where bulk jobs are kept (TN-125): in the realm's scope, 7 days, never deleted (OP-73).
pub trait Jobs: Send + Sync {
    /// Records a job; `None` when there is no such realm.
    fn create(&self, slug: String, job: NewJob) -> Pending<'_, Option<String>>;

    /// Records one item's outcome.
    fn record(&self, slug: String, job: String, item: JobItem) -> Pending<'_, ()>;

    /// Finishes the job with `status` at `now_ms`.
    fn finish(
        &self,
        slug: String,
        job: String,
        status: &'static str,
        now_ms: u64,
    ) -> Pending<'_, ()>;

    /// The job, unless it is unknown or expired by `now_ms`.
    fn read(&self, slug: String, job: String, now_ms: u64) -> Pending<'_, Option<JobView>>;

    /// Up to `limit` of its items after `after`.
    fn items(
        &self,
        slug: String,
        job: String,
        after: Option<u32>,
        limit: u32,
    ) -> Pending<'_, Vec<JobItem>>;
}

/// No job store: every job request is unavailable (MD-8).
pub struct NoJobs;

impl Jobs for NoJobs {
    fn create(&self, _: String, _: NewJob) -> Pending<'_, Option<String>> {
        Box::pin(async { Err(Unavailable) })
    }

    fn record(&self, _: String, _: String, _: JobItem) -> Pending<'_, ()> {
        Box::pin(async { Err(Unavailable) })
    }

    fn finish(&self, _: String, _: String, _: &'static str, _: u64) -> Pending<'_, ()> {
        Box::pin(async { Err(Unavailable) })
    }

    fn read(&self, _: String, _: String, _: u64) -> Pending<'_, Option<JobView>> {
        Box::pin(async { Err(Unavailable) })
    }

    fn items(&self, _: String, _: String, _: Option<u32>, _: u32) -> Pending<'_, Vec<JobItem>> {
        Box::pin(async { Err(Unavailable) })
    }
}

/// Every port of the management API.
pub trait Env: Send + Sync + 'static {
    /// Read token verifier.
    type Tokens: ReadTokens + 'static;
    /// Surface domains and Instance keys.
    type Surfaces: Surfaces + 'static;
    /// Idempotency answers.
    type Idempotency: IdempotencyStore + 'static;

    /// Trusted time.
    fn clock(&self) -> &dyn Clock;
    /// Randomness.
    fn entropy(&self) -> &dyn Entropy;
    /// The rate limiter.
    fn limiter(&self) -> &dyn RateLimiter;
    /// List cursors.
    fn cursors(&self) -> &dyn CursorSeal;
    /// Read tokens.
    fn tokens(&self) -> &Self::Tokens;
    /// Surfaces.
    fn surfaces(&self) -> &Self::Surfaces;
    /// Idempotency answers.
    fn idempotency(&self) -> &Self::Idempotency;
    /// The management origin, `https://<host>[:port]`, from configuration only (§17.9.6).
    fn origin(&self) -> &str;
    /// The realm resources; none by default.
    fn realm(&self) -> &dyn RealmResources {
        &NoRealmResources
    }
    /// The platform resources; none by default.
    fn platform(&self) -> &dyn PlatformResources {
        &NoPlatformResources
    }
    /// The bulk job store; none by default.
    fn jobs(&self) -> &dyn Jobs {
        &NoJobs
    }
}
