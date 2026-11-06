//! Verification of authority tokens at a resource server (§9.9, §9.9.3, §9.9.4, §10.4.3,
//! §12.2.1, §13.4 U55, §13.7.9, L2-JOS-1 to L2-JOS-4, OP-150 m.3 (d), m.9): an RFC 9068 token
//! whose authority is in RAR `authorization_details`, signed by the domain's operational key
//! published in the realm JWKS, for this one resource server, bound to the key the request
//! was made with, within its `ValidityContract`, its status list entry clear, and, under the
//! strict profile, confirmed by introspection on every request.
//!
//! The resource server never re-emits a token: a [`Verified`] carries what the token proved,
//! not the token (§9.9.3 rule 9, L24). Nothing is accepted on a fault (MD-8, X21, TI-9).

pub mod claims;
pub mod introspection;
pub mod keys;
pub mod status;

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::digest::Digest;
use access_kernel::json::Json;
use access_kernel::model::TrustedTime;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::Algorithm;
use access_kernel::verify::dpop::{self, DpopError, ProofRules};
use access_kernel::verify::key_scope::DomainMetadata;
use access_kernel::verify::projection::{
    AccessTokenRules, Confirmation, Kind, ProjectionError, verify_access_token,
};
use suiss_crypto::digest::context_digest;

pub use self::claims::{ActionType, ActorRef, Contract, Detail, TokenCapacity};
pub use self::introspection::Introspector;
pub use self::keys::{DEFAULT_KEY_EPOCH_MS, KeySource, Keys, MAX_KEY_EPOCH_MS};
pub use self::status::StatusSource;
use crate::authorize::{Authorized, Intent};
use crate::transport::{Clock, Fault};

/// Largest token accepted, checked before anything else (OP-150 m.3 (s), §9.9.6).
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Longest horizon of a token under the fast profile (§13.7.9, §9.9.3 rule 4: 5 minutes).
pub const FAST_HORIZON_MS: u64 = 5 * 60 * 1000;

/// Default DPoP proof lifetime after `iat` (MD-18 example: 5 s).
pub const DEFAULT_PROOF_LIFETIME_MS: u64 = 5_000;

/// Default clock skew for DPoP proofs (MD-18 example: 5 s).
pub const DEFAULT_PROOF_SKEW_MS: u64 = 5_000;

/// Default clock skew for token claims (CR-55 m.9).
pub const DEFAULT_CLAIMS_SKEW_MS: u64 = 60_000;

/// Digest context of a DPoP replay key (TN-30): a fixed-length key over `htm`, `htu` and `jti`.
pub const REPLAY_CONTEXT: &str = "access/dpop-replay/v1";

/// Digest context of an exact-intent token's single use (§9.9.1: `count = 1`).
pub const SINGLE_USE_CONTEXT: &str = "access/exact-intent-use/v1";

/// The revocation profile of a resource server (§13.7.9, MD-7, OP-150 m.3 (g)). Neither skips
/// the signature, audience, confirmation, contract or status checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Introspection on every request; for administrative and financial resource servers.
    Strict,
    /// A JWT within [`FAST_HORIZON_MS`] and its status list; revocation reaches the server
    /// within the token's horizon.
    Fast,
}

/// Why a configuration is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// `key_epoch_ms` is above [`MAX_KEY_EPOCH_MS`] or zero.
    #[error("key epoch")]
    KeyEpoch,
    /// The issuer or audience is empty.
    #[error("identity")]
    Identity,
    /// No algorithm is allowed, or one that is not enabled.
    #[error("algorithms")]
    Algorithms,
}

/// A resource server.
#[derive(Clone, Debug)]
pub struct ResourceServer {
    issuer: String,
    audience: String,
    domain: Digest,
    metadata: Option<DomainMetadata>,
    profile: Profile,
    algorithms: BTreeSet<Algorithm>,
    key_epoch_ms: u64,
    claims_skew_ms: u64,
    proof_lifetime_ms: u64,
    proof_skew_ms: u64,
}

/// How a resource server is set up.
#[derive(Clone, Debug)]
pub struct Config {
    /// The expected `iss`: the realm's authorization server.
    pub issuer: String,
    /// This resource server, the token's only audience (RFC 8707).
    pub audience: String,
    /// The domain whose authority the tokens project.
    pub domain: Digest,
    /// Verified Domain Metadata of that domain, for CWT status lists.
    pub metadata: Option<DomainMetadata>,
    /// The revocation profile.
    pub profile: Profile,
    /// Signature algorithms allowed for tokens and proofs (MD-3).
    pub algorithms: BTreeSet<Algorithm>,
    /// How long a fetched JWKS stays usable, at most [`MAX_KEY_EPOCH_MS`].
    pub key_epoch_ms: u64,
}

impl ResourceServer {
    /// A resource server with the default skews and proof lifetime.
    ///
    /// # Errors
    /// [`ConfigError`].
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        if config.issuer.is_empty() || config.audience.is_empty() {
            return Err(ConfigError::Identity);
        }
        if config.key_epoch_ms == 0 || config.key_epoch_ms > MAX_KEY_EPOCH_MS {
            return Err(ConfigError::KeyEpoch);
        }
        if config.algorithms.is_empty() || config.algorithms.iter().any(|a| !a.enabled()) {
            return Err(ConfigError::Algorithms);
        }
        Ok(Self {
            issuer: config.issuer,
            audience: config.audience,
            domain: config.domain,
            metadata: config.metadata,
            profile: config.profile,
            algorithms: config.algorithms,
            key_epoch_ms: config.key_epoch_ms,
            claims_skew_ms: DEFAULT_CLAIMS_SKEW_MS,
            proof_lifetime_ms: DEFAULT_PROOF_LIFETIME_MS,
            proof_skew_ms: DEFAULT_PROOF_SKEW_MS,
        })
    }

    /// The profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// This server's audience.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

/// Whether a replay key was recorded for the first time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replay {
    /// First time; recorded until the given time.
    Fresh,
    /// Seen before within its window.
    Seen,
    /// The store did not answer; the proof is refused (TN-30, MD-8).
    Unavailable,
}

/// The replay port (§10.4.3 m.5, IDP-11, TN-30): records a fixed-length key until `until` and
/// says whether it was already there.
pub trait ReplayStore {
    /// Records `key`.
    fn record(&self, key: &[u8; 32], until: TrustedTime) -> Replay;
}

/// The DPoP nonce port (TN-29, MD-18): whether the proof's `nonce` is one this server
/// currently accepts. Once a client was given a nonce, a proof without one is refused.
pub trait NonceSource {
    /// Whether `nonce` is acceptable now.
    fn accept(&self, nonce: Option<&str>) -> bool;
}

/// Revocation the resource server learned of itself (§9.16, OP-150 m.10 (g)): families ended
/// by `projection-invalidated` events it received. An information channel (PI-9): `false`
/// means nothing is known, never that the family is live.
pub trait Revocations {
    /// Whether this family was ended.
    fn family_ended(&self, family: &[u8; 16]) -> bool;
}

/// The ports one verification uses.
#[derive(Clone, Copy, Debug)]
pub struct Ports<'a, K, P, N, S, I, V> {
    /// The realm JWKS.
    pub keys: &'a K,
    /// DPoP and single-use replay state.
    pub replay: &'a P,
    /// DPoP nonces.
    pub nonces: &'a N,
    /// Status lists.
    pub status: &'a S,
    /// Introspection.
    pub introspection: &'a I,
    /// Locally known revocations.
    pub revocations: &'a V,
}

/// One request presenting a token.
#[derive(Clone, Copy, Debug)]
pub struct Presented<'a> {
    /// The access token as presented.
    pub token: &'a str,
    /// The request method.
    pub method: &'a str,
    /// The request URI as this server sees it.
    pub uri: &'a str,
    /// The `DPoP` header, when the request carries one.
    pub proof: Option<&'a str>,
    /// The SHA-256 thumbprint of the client certificate, for an mTLS request.
    pub certificate: Option<[u8; 32]>,
    /// The position the protected content was written at, when known (§13.4 U60).
    pub content_position: Option<u64>,
}

/// Why a token is not accepted. A value applied as DENY, never an error that could pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Denied {
    /// No trusted time.
    #[error("clock")]
    Clock,
    /// The token is over [`MAX_TOKEN_BYTES`].
    #[error("token-too-large")]
    TooLarge,
    /// An opaque token under the fast profile: nothing verifies it locally.
    #[error("token-opaque")]
    Opaque,
    /// No proof of possession, or two.
    #[error("confirmation-{0}")]
    Confirmation(&'static str),
    /// The DPoP proof fails a stateless step.
    #[error("{0}")]
    Dpop(DpopError),
    /// The DPoP nonce is not one this server accepts.
    #[error("dpop-nonce")]
    DpopNonce,
    /// The DPoP proof was seen before.
    #[error("dpop-replay")]
    DpopReplay,
    /// The replay store did not answer.
    #[error("replay-store")]
    ReplayStore,
    /// The JWKS could not be fetched.
    #[error("jwks-unavailable: {0}")]
    KeysUnavailable(Fault),
    /// The JWKS endpoint answered other than 200.
    #[error("jwks-status {0}")]
    KeysStatus(u16),
    /// The JWKS is not a key set.
    #[error("jwks-malformed")]
    KeysMalformed,
    /// The cached JWKS is older than `key_epoch`.
    #[error("jwks-stale")]
    KeysStale,
    /// The token fails the Kernel's profile (L2-JOS-1 to L2-JOS-4).
    #[error("{0}")]
    Projection(ProjectionError),
    /// A claim is missing or of another shape.
    #[error("token-claim {0}")]
    Claim(&'static str),
    /// The basis reference carries no position.
    #[error("token-basis")]
    Basis,
    /// The exact-intent token is not for this intent.
    #[error("token-intent")]
    Intent,
    /// The bounds token does not name this action.
    #[error("token-bounds")]
    Bounds,
    /// This server is not in the contract's audience.
    #[error("contract-audience")]
    ContractAudience,
    /// The contract's horizon has passed.
    #[error("contract-horizon")]
    ContractHorizon,
    /// The token's status reference and the contract's differ.
    #[error("contract-status")]
    ContractStatus,
    /// The token's horizon is longer than the profile allows.
    #[error("profile-horizon")]
    ProfileHorizon,
    /// No status list reference.
    #[error("status-missing")]
    StatusMissing,
    /// The status list could not be fetched.
    #[error("status-unavailable: {0}")]
    StatusUnavailable(Fault),
    /// The status list endpoint answered other than 200.
    #[error("status-status {0}")]
    StatusStatus(u16),
    /// The list is not a list token.
    #[error("status-malformed")]
    StatusMalformed,
    /// The list's key cannot be resolved.
    #[error("status-key")]
    StatusKey,
    /// The list's signature does not verify.
    #[error("status-signature")]
    StatusSignature,
    /// The list is older than Δ.
    #[error("status-stale")]
    StatusStale,
    /// The list is not the referenced one.
    #[error("status-uri")]
    StatusUri,
    /// The index is past the end of the list.
    #[error("status-index")]
    StatusIndex,
    /// The entry is set.
    #[error("status-revoked")]
    Revoked,
    /// The family was ended.
    #[error("family-ended")]
    FamilyEnded,
    /// Introspection could not be reached.
    #[error("introspection-unavailable: {0}")]
    IntrospectionUnavailable(Fault),
    /// Introspection answered other than 200.
    #[error("introspection-status {0}")]
    IntrospectionStatus(u16),
    /// The introspection body is not an answer.
    #[error("introspection-malformed")]
    IntrospectionMalformed,
    /// `active: false`.
    #[error("token-inactive")]
    Inactive,
    /// Introspection names another audience.
    #[error("introspection-audience")]
    IntrospectionAudience,
    /// Introspection says the token expired.
    #[error("introspection-expired")]
    IntrospectionExpired,
    /// Introspection's confirmation is not the presented key.
    #[error("introspection-confirmation")]
    IntrospectionConfirmation,
    /// Introspection reflects a position older than the token's basis or the content.
    #[error("introspection-stale")]
    IntrospectionStale,
    /// The exact-intent token was used before.
    #[error("intent-reused")]
    Reused,
    /// The projection is older than the protected content (§13.4 U60).
    #[error("content-position")]
    Stale,
}

impl Denied {
    /// Whether Access, not a fault, stopped the effect: an explicit refusal a PEP reports as
    /// `deny` rather than as an unknown state.
    #[must_use]
    pub const fn is_decision(&self) -> bool {
        matches!(
            self,
            Self::Inactive
                | Self::Revoked
                | Self::FamilyEnded
                | Self::Reused
                | Self::Projection(_)
                | Self::Dpop(_)
                | Self::DpopNonce
                | Self::DpopReplay
                | Self::Claim(_)
                | Self::Intent
                | Self::Bounds
                | Self::ContractAudience
                | Self::ContractHorizon
                | Self::IntrospectionAudience
                | Self::IntrospectionExpired
                | Self::IntrospectionConfirmation
        )
    }
}

/// What a verified token proved. It holds no token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    /// Exact-intent or bounds.
    pub kind: Kind,
    /// The `projection.issue` Exercise.
    pub exercise: Digest,
    /// The actions the token names.
    pub actions: Vec<ActionType>,
    /// The capacity the claims project (a hint, §9.9.4).
    pub capacity: TokenCapacity,
    /// Whether `may_act` is present (a hint, never authority).
    pub may_act: bool,
    /// The contract view.
    pub contract: Contract,
    /// The refresh family.
    pub family: Option<[u8; 16]>,
    /// `rev`, when present.
    pub rev: Option<u64>,
    /// The OAuth client; not the actor (PI-7).
    pub client_id: String,
    /// The position the projection reflects.
    pub as_of: u64,
    /// The head position introspection reflected, under the strict profile.
    pub introspected_as_of: Option<u64>,
}

/// A verified presentation: the proof the effect runs under and what the token proved.
pub struct Verified<R, A> {
    /// The proof, consumed by the effect.
    pub authorized: Authorized<R, A>,
    /// What the token proved.
    pub authority: Authority,
}

impl<R, A> core::fmt::Debug for Verified<R, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verified")
            .field("authorized", &self.authorized)
            .field("authority", &self.authority)
            .finish()
    }
}

fn replay_key(proof: &dpop::Proof) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        proof
            .htm
            .len()
            .saturating_add(proof.htu.len())
            .saturating_add(proof.jti.len())
            .saturating_add(2),
    );
    input.extend_from_slice(proof.htm.as_bytes());
    input.push(0);
    input.extend_from_slice(proof.htu.as_bytes());
    input.push(0);
    input.extend_from_slice(proof.jti.as_bytes());
    context_digest(REPLAY_CONTEXT, &input).0
}

fn single_use_key(exercise: &Digest) -> [u8; 32] {
    context_digest(SINGLE_USE_CONTEXT, &exercise.0).0
}

struct Verdict {
    claims: Json,
    details: Vec<Detail>,
    contract: Contract,
    introspected_as_of: Option<u64>,
}

impl ResourceServer {
    fn confirmation(
        &self,
        presented: &Presented<'_>,
        now: TrustedTime,
        replay: &impl ReplayStore,
        nonces: &impl NonceSource,
    ) -> Result<Confirmation, Denied> {
        match (presented.proof, presented.certificate) {
            (Some(_), Some(_)) => Err(Denied::Confirmation("ambiguous")),
            (None, None) => Err(Denied::Confirmation("missing")),
            (None, Some(cert)) => Ok(Confirmation::X5tS256(cert)),
            (Some(proof), None) => {
                // IDP-11 steps 1 to 8, 11
                let rules = ProofRules {
                    method: presented.method,
                    uri: presented.uri,
                    allowed: &self.algorithms,
                    now,
                    lifetime_ms: self.proof_lifetime_ms,
                    skew_ms: self.proof_skew_ms,
                    access_token: Some(presented.token),
                    bound_jkt: None,
                };
                let proof =
                    dpop::verify_proof(&PureBackend, proof, &rules).map_err(Denied::Dpop)?;
                // IDP-11 step 10, TN-29
                if !nonces.accept(proof.nonce.as_deref()) {
                    return Err(Denied::DpopNonce);
                }
                // IDP-11 step 9, TN-30: TTL = lifetime + 2 × skew
                let until = proof
                    .iat
                    .saturating_add(self.proof_lifetime_ms)
                    .saturating_add(self.proof_skew_ms.saturating_mul(2));
                match replay.record(&replay_key(&proof), until) {
                    Replay::Fresh => Ok(Confirmation::Jkt(proof.jkt)),
                    Replay::Seen => Err(Denied::DpopReplay),
                    Replay::Unavailable => Err(Denied::ReplayStore),
                }
            }
        }
    }

    fn jwt<K: KeySource, S: StatusSource>(
        &self,
        presented: &Presented<'_>,
        confirmation: &Confirmation,
        now: TrustedTime,
        keys: &K,
        status: &S,
    ) -> Result<Verdict, Denied> {
        let key_set = keys::resolve(keys.jwks(), &self.algorithms, now, self.key_epoch_ms)?;
        // L2-JOS-1 to L2-JOS-4
        let rules = AccessTokenRules {
            issuer: &self.issuer,
            audience: &self.audience,
            domain: &self.domain,
            confirmation,
            now,
            skew_ms: self.claims_skew_ms,
        };
        let token = verify_access_token(&PureBackend, presented.token, &key_set, &rules)
            .map_err(Denied::Projection)?;
        let claims = token.claims;
        // §9.9.4 k.1, P55
        claims::reserved_shapes(&claims)?;
        let details = claims::details(&claims, &self.domain)?;
        let contract = claims::contract(&claims, claims::validity(&claims)?)?;
        // §9.9.3 rule 4, §13.7.9: the fast profile lives within 5 minutes
        if self.profile == Profile::Fast {
            let iat = claims::time_ms(&claims, "iat")?;
            let exp = claims::time_ms(&claims, "exp")?;
            if exp.checked_sub(iat).is_none_or(|h| h > FAST_HORIZON_MS) {
                return Err(Denied::ProfileHorizon);
            }
        }
        // L2-STL-1
        let reference = claims::status_claim(&claims)?.ok_or(Denied::StatusMissing)?;
        if contract.status.as_ref().is_some_and(|s| *s != reference) {
            return Err(Denied::ContractStatus);
        }
        let list_keys = status::ListKeys {
            realm: &key_set,
            metadata: self.metadata.as_ref(),
        };
        status::check(
            status.list(&reference.uri),
            &reference,
            &list_keys,
            now,
            contract.max_staleness_ms,
        )?;
        Ok(Verdict {
            claims,
            details,
            contract,
            introspected_as_of: None,
        })
    }

    fn introspected(
        &self,
        presented: &Presented<'_>,
        confirmation: &Confirmation,
        now: TrustedTime,
        introspection: &impl Introspector,
    ) -> Result<introspection::Active, Denied> {
        let active = introspection::active(
            introspection.introspect(presented.token),
            &self.audience,
            now,
            self.claims_skew_ms,
        )?;
        // PI-11: the answer names the key the request was made with
        let (member, thumbprint) = claims::confirmation_thumbprint(&active.claims)
            .map_err(|_| Denied::IntrospectionConfirmation)?;
        if member != confirmation.member() || thumbprint != *confirmation.thumbprint() {
            return Err(Denied::IntrospectionConfirmation);
        }
        Ok(active)
    }

    fn opaque(
        &self,
        presented: &Presented<'_>,
        confirmation: &Confirmation,
        now: TrustedTime,
        introspection: &impl Introspector,
    ) -> Result<Verdict, Denied> {
        if self.profile != Profile::Strict {
            return Err(Denied::Opaque);
        }
        let active = self.introspected(presented, confirmation, now, introspection)?;
        let claims = active.claims;
        claims::reserved_shapes(&claims)?;
        let details = claims::details(&claims, &self.domain)?;
        let contract = claims::contract(&claims, claims::validity(&claims)?)?;
        Ok(Verdict {
            claims,
            details,
            contract,
            introspected_as_of: Some(active.as_of),
        })
    }

    /// Verifies one presentation of an authority token for `intent` and, when everything
    /// holds, authorizes the effect: size, proof of possession (DPoP with this server's nonce
    /// and replay state, or mTLS), the realm key within `key_epoch`, the Kernel's token profile
    /// for this issuer, audience, domain and confirmation, the reserved claim shapes, the RAR
    /// details for this intent or action, the contract's audience and horizon, the status list
    /// entry within Δ, locally known revocations, introspection under the strict profile,
    /// single use of an exact-intent token, and the content position.
    ///
    /// # Errors
    /// [`Denied`]: no effect.
    #[allow(
        clippy::too_many_lines,
        reason = "one pass over the checks, in spec order"
    )]
    pub fn verify<R, A, K, P, N, S, I, V>(
        &self,
        presented: &Presented<'_>,
        intent: &Intent<R, A>,
        clock: &impl Clock,
        ports: &Ports<'_, K, P, N, S, I, V>,
    ) -> Result<Verified<R, A>, Denied>
    where
        K: KeySource,
        P: ReplayStore,
        N: NonceSource,
        S: StatusSource,
        I: Introspector,
        V: Revocations,
    {
        let now = clock.now().ok_or(Denied::Clock)?;
        // OP-150 m.3 (s)
        if presented.token.len() > MAX_TOKEN_BYTES {
            return Err(Denied::TooLarge);
        }
        // §9.9.3 rule 2, PI-11
        let confirmation = self.confirmation(presented, now, ports.replay, ports.nonces)?;
        let is_jws = presented.token.split('.').count() == 3;
        let mut verdict = if is_jws {
            self.jwt(presented, &confirmation, now, ports.keys, ports.status)?
        } else {
            self.opaque(presented, &confirmation, now, ports.introspection)?
        };
        // §9.9.3 rule 5, §13.7.9: strict confirms every request
        if self.profile == Profile::Strict && verdict.introspected_as_of.is_none() {
            let active = self.introspected(presented, &confirmation, now, ports.introspection)?;
            verdict.introspected_as_of = Some(active.as_of);
        }
        let claims = &verdict.claims;
        let first = verdict
            .details
            .first()
            .ok_or(Denied::Claim("authorization_details"))?;
        let kind = first.kind;
        let exercise = claims::exercise(claims)?;
        if exercise != first.exercise {
            return Err(Denied::Claim("exercise"));
        }
        let as_of = first.basis_position;
        // §9.9.1: an exact-intent token is this intent; a bounds token names this action
        match kind {
            Kind::Intent => {
                if first.intent.as_ref() != Some(intent.digest()) {
                    return Err(Denied::Intent);
                }
            }
            Kind::Bounds => {
                let action = intent.action().ok_or(Denied::Bounds)?;
                if !verdict.details.iter().any(|d| d.action.is(action)) {
                    return Err(Denied::Bounds);
                }
            }
        }
        // §9.12: the contract names this verifier and has not ended
        if !verdict.contract.audience.contains(&self.audience) {
            return Err(Denied::ContractAudience);
        }
        if verdict.contract.horizon < now {
            return Err(Denied::ContractHorizon);
        }
        let capacity = claims::capacity(claims, &first.capacity)?;
        let family = if is_jws || claims.get("family").is_some() {
            Some(claims::family(claims)?)
        } else {
            None
        };
        if family.is_some_and(|f| ports.revocations.family_ended(&f)) {
            return Err(Denied::FamilyEnded);
        }
        // §13.4 U60, OP-150 m.3 (l)
        if presented.content_position.is_some_and(|q| as_of < q) {
            return Err(Denied::Stale);
        }
        if let Some(head) = verdict.introspected_as_of
            && (head < as_of || presented.content_position.is_some_and(|q| head < q))
        {
            return Err(Denied::IntrospectionStale);
        }
        // §9.9.1: count = 1
        if kind == Kind::Intent {
            let until = claims::time_ms(claims, "exp")?.saturating_add(self.claims_skew_ms);
            match ports.replay.record(&single_use_key(&exercise), until) {
                Replay::Fresh => {}
                Replay::Seen => return Err(Denied::Reused),
                Replay::Unavailable => return Err(Denied::ReplayStore),
            }
        }
        let authority = Authority {
            kind,
            exercise,
            actions: verdict.details.iter().map(|d| d.action.clone()).collect(),
            capacity,
            may_act: claims.get("may_act").is_some(),
            contract: verdict.contract.clone(),
            family,
            rev: claims::rev(claims)?,
            client_id: claims::client_id(claims)?,
            as_of,
            introspected_as_of: verdict.introspected_as_of,
        };
        Ok(Verified {
            authorized: Authorized::new(exercise, *intent.digest(), as_of, None),
            authority,
        })
    }
}
