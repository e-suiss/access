//! What the management API needs from the outside world (OP-63): time, randomness, the read
//! token and Instance key verifiers, the surface's domain, the write path, the idempotency store
//! and the rate limiter. Every port fails closed: [`Unavailable`] refuses the request (MD-8).

use std::future::Future;

use access_kernel::digest::Digest;
use access_kernel::verify::cose::PublicKey;
use axum::body::Bytes;

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

/// A write the management API compiles into an Exercise (TN-110): the surface, the operation,
/// the caller's verified AIS and the request body.
#[derive(Clone, Debug)]
pub struct Proposal {
    /// The surface.
    pub scope: SurfaceScope,
    /// The surface's governing domain.
    pub domain: Digest,
    /// The manifest operation.
    pub operation: &'static str,
    /// The caller and its statement.
    pub caller: WriteCaller,
    /// The body.
    pub body: Bytes,
}

/// What the write path answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proposed {
    /// Committed: the Exercise record (TN-110, X14).
    Committed {
        /// The `ExerciseID`.
        exercise_id: Digest,
        /// Its position in the domain's log.
        position: u64,
    },
    /// Decided and not allowed; nothing changed.
    NotAllowed {
        /// Position of the decision record, when recorded.
        position: Option<u64>,
    },
    /// Refused before a decision; nothing changed.
    Refused,
}

/// Compiles management writes into `idp.*` domain action or meta-action Exercises and submits
/// them through ADP `commit` (TN-110, PI-4, INV-2): the only way a management write changes
/// authority state or realm configuration.
pub trait Proposals: Send + Sync {
    /// Submits `proposal`.
    fn propose(
        &self,
        proposal: Proposal,
    ) -> impl Future<Output = Result<Proposed, Unavailable>> + Send;
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

/// Every port of the management API.
pub trait Env: Send + Sync + 'static {
    /// Read token verifier.
    type Tokens: ReadTokens + 'static;
    /// Surface domains and Instance keys.
    type Surfaces: Surfaces + 'static;
    /// The write path.
    type Proposals: Proposals + 'static;
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
    /// The write path.
    fn proposals(&self) -> &Self::Proposals;
    /// Idempotency answers.
    fn idempotency(&self) -> &Self::Idempotency;
    /// The management origin, `https://<host>[:port]`, from configuration only (§17.9.6).
    fn origin(&self) -> &str;
}
