//! What the core needs from the outside (OP-63): state reads, actor-binding, salts, keys.

use std::future::Future;

use access_crypto::event_id::EventKey;
use access_crypto::token::TokenKey;
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use access_kernel::verify::cose::PublicKey;
use access_store::authority::NonceRow;
use suiss_crypto::dcbor::Value;

use crate::CoreError;

/// One fetched state key: its value, `None` when absent, and its version.
pub type Row = (Vec<u8>, Option<Value>, u64);

/// A recorded Verifier Profile: its body digest and its body (§9.12.1).
pub type Profile = ([u8; 32], Vec<u8>);

/// Reads the state and the nonce table (the `StateView` read side).
pub trait Reader {
    /// Current values and versions of `keys`; an absent key comes back as `(key, None, 0)`.
    fn fetch(&self, keys: &[Vec<u8>]) -> impl Future<Output = Result<Vec<Row>, CoreError>> + Send;
    /// The live rows whose key starts with `prefix` (OP-141 m.20 (b)).
    fn scan(&self, prefix: &[u8]) -> impl Future<Output = Result<Vec<Row>, CoreError>> + Send;
    /// Live Grants on resources in `namespace` from the derived index, in id order after
    /// `after` (OP-141 m.22 (g)); candidates only, never a decision input.
    fn grants_in(
        &self,
        namespace: &str,
        after: Option<Id>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Id>, CoreError>> + Send;
    /// Live Grants `party` may hold, from the derived index, in id order after `after`.
    fn grants_for(
        &self,
        party: &Id,
        after: Option<Id>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Id>, CoreError>> + Send;
    /// The envelopes of the records `from..=to`, in order (OP-141 m.36 (d)).
    fn log(
        &self,
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, CoreError>> + Send;
    /// The trusted time of the record at `pos`, if there is one.
    fn recorded_at(&self, pos: u64) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send;
    /// A SYNC-DERIVED counter's used amount; 0 when never drawn.
    fn counter(&self, key: &[u8]) -> impl Future<Output = Result<u64, CoreError>> + Send;
    /// The bytes a record kept as a proof under `digest` (a Claim, or a Claim body by its
    /// digest); none by default.
    fn proof(
        &self,
        digest: &[u8; 32],
    ) -> impl Future<Output = Result<Option<Vec<u8>>, CoreError>> + Send {
        let _ = digest;
        std::future::ready(Ok(None))
    }
    /// The position of the first decision of a nonce (OP-141 m.34 (c)).
    fn nonce_opened(
        &self,
        nonce: &[u8],
    ) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send;
    /// The latest outcome of a nonce.
    fn nonce(
        &self,
        nonce: &[u8],
    ) -> impl Future<Output = Result<Option<NonceRow>, CoreError>> + Send;
    /// The first `projection.issue` of each live projection family `holder` holds (§9.9.3
    /// k.6, P50): the families that end with the holder Instance.
    fn live_families(
        &self,
        holder: &Id,
    ) -> impl Future<Output = Result<Vec<Digest>, CoreError>> + Send;
    /// The accepted Verifier Profile of the verifier `audience` names, current at `now`: the
    /// body digest a contract names in `verifier_profile_ref` and the body (§9.12.1, PI-12);
    /// none by default.
    fn verifier_profile(
        &self,
        audience: &str,
        now: u64,
    ) -> impl Future<Output = Result<Option<Profile>, CoreError>> + Send {
        let _ = (audience, now);
        std::future::ready(Ok(None))
    }
    /// The highest incarnation an admitted `resource_lifecycle` Claim named for the resource
    /// (OP-156 m.3 (k)). A reader without the registry is unavailable, so the ingest of such a
    /// Claim fails closed.
    fn highest_incarnation(
        &self,
        namespace: &str,
        path: &[String],
    ) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send {
        let _ = (namespace, path);
        std::future::ready(Err(CoreError::Unavailable("incarnations")))
    }
    /// Every recorded lifecycle fact of the resource, in record order (OP-156 m.3 (k));
    /// unavailable by default.
    fn incarnations(
        &self,
        namespace: &str,
        path: &[String],
    ) -> impl Future<Output = Result<Vec<crate::app::resources::Fact>, CoreError>> + Send {
        let _ = (namespace, path);
        std::future::ready(Err(CoreError::Unavailable("incarnations")))
    }
    /// The newest `limit` accesses discovery connectors reported (OP-156 m.4 Q20), in record
    /// order; unavailable by default.
    fn discovered(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<crate::app::discovery::Row>, CoreError>> + Send {
        let _ = limit;
        std::future::ready(Err(CoreError::Unavailable("discovered")))
    }
    /// How many offline-class projections of `holder` are open at `now` (§13.7.4); 0 by
    /// default.
    fn open_offline(
        &self,
        holder: &Id,
        now: u64,
    ) -> impl Future<Output = Result<u64, CoreError>> + Send {
        let _ = (holder, now);
        std::future::ready(Ok(0))
    }
    /// How many projections `holder` was issued since `since_ms` on one of `namespaces`
    /// (§13.7.4); 0 by default.
    fn issued_since(
        &self,
        holder: &Id,
        since_ms: u64,
        namespaces: &[String],
    ) -> impl Future<Output = Result<u64, CoreError>> + Send {
        let _ = (holder, since_ms, namespaces);
        std::future::ready(Ok(0))
    }
    /// Whether `audience` left a `checkpointed-offline` projection unreported past its deadline
    /// at `now` (§13.7.2, SEC14); `false` by default.
    fn unreported_overdue(
        &self,
        audience: &str,
        now: u64,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send {
        let _ = (audience, now);
        std::future::ready(Ok(false))
    }
    /// What the latest `require_action` on `intent` left for its approval (§9.14.1 step 1,
    /// OP-150 L6): the render digest the decision point computed and the tier.
    fn opening(
        &self,
        intent: &Digest,
    ) -> impl Future<Output = Result<Option<Opening>, CoreError>> + Send;
    /// The last position recorded at or before trusted time `at` (§16.5.1); unavailable by
    /// default.
    fn position_at(&self, at: u64) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send {
        let _ = at;
        std::future::ready(Err(CoreError::Unavailable("position")))
    }
    /// The projection contracts open after `at`, family not revoked (§5.4); unavailable by
    /// default.
    fn open_contracts(
        &self,
        at: u64,
    ) -> impl Future<Output = Result<Vec<OpenContract>, CoreError>> + Send {
        let _ = at;
        std::future::ready(Err(CoreError::Unavailable("contracts")))
    }
    /// The Grants the derived index holds as live, in id order after `after`, and the last
    /// position it applied (§5.4 orphan tuple counter); unavailable by default.
    fn indexed_live(
        &self,
        after: Option<Id>,
        limit: u32,
    ) -> impl Future<Output = Result<(Vec<Id>, u64), CoreError>> + Send {
        let _ = (after, limit);
        std::future::ready(Err(CoreError::Unavailable("index")))
    }
    /// The canonical bytes of the packages published for `namespace`, newest first
    /// (§8.17.10.2); unavailable by default.
    fn publications(
        &self,
        namespace: &str,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, CoreError>> + Send {
        let _ = namespace;
        std::future::ready(Err(CoreError::Unavailable("publications")))
    }
    /// Whether this domain's realm has opened delegated administration (TN-114, OP-157 m.3 (t)).
    fn delegated_admin_open(&self) -> impl Future<Output = Result<bool, CoreError>> + Send;
    /// The issuer cutoff a decided drop of the realm key `kid` recorded for the realm whose
    /// issuer is `iss` (§13.7.7, SEC9); `None` when no such key was dropped. Unavailable by
    /// default.
    fn key_cutoff(
        &self,
        iss: &str,
        kid: &[u8; 32],
    ) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send {
        let _ = (iss, kid);
        std::future::ready(Err(CoreError::Unavailable("key-cutoff")))
    }
    /// Draws one widening commit of this domain at `now` from its own and its tenant's quota
    /// (layer B, OP-158 m.3 (v)); the refusing counter when over. A reader without counters
    /// refuses as unavailable, never admits (MD-8).
    fn take_quota(
        &self,
        now: u64,
    ) -> impl Future<Output = Result<Option<crate::app::quota::Refusal>, CoreError>> + Send {
        let _ = now;
        std::future::ready(Err(CoreError::Unavailable("quota")))
    }
}

/// A projection contract still open at some time (§5.4).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenContract {
    /// The projection's `ExerciseID`.
    pub exercise: Digest,
    /// The holder Instance.
    pub holder: Id,
    /// Profile class word.
    pub class: String,
    /// The contract's horizon, milliseconds.
    pub horizon_ms: u64,
    /// The PEP that asked for the projection.
    pub pep: String,
}

/// Whether a restriction policy change moved authority (§5.8, OP-105), as the control-plane
/// analysis answers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyRelation {
    /// Same outcome for every request.
    Equivalent,
    /// Restricts at least as much everywhere and more somewhere.
    Narrowing,
    /// Restricts less somewhere.
    Widening,
    /// Restricts less somewhere and more elsewhere.
    Incomparable,
    /// A policy can raise an evaluation error.
    MayError,
    /// No relation was proved (time limit, solver `unknown`, any failure); never equivalent.
    Unknown,
}

impl PolicyRelation {
    /// Its word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::Narrowing => "narrowing",
            Self::Widening => "widening",
            Self::Incomparable => "incomparable",
            Self::MayError => "may_error",
            Self::Unknown => "unknown",
        }
    }
}

/// The relation a [`PolicyAnalysis`] answers, boxed so the port can be shared.
pub type Comparing<'a> = std::pin::Pin<Box<dyn Future<Output = PolicyRelation> + Send + 'a>>;

/// The control-plane SMT analysis of restriction policy changes (OP-105): never on the request
/// path, wired by the binary that holds the pinned solver ([`crate::adapters::Setup`]).
pub trait PolicyAnalysis: Send + Sync {
    /// The relation of `new` to `old`, both written against `schema`.
    fn compare<'a>(&'a self, schema: &'a str, old: &'a str, new: &'a str) -> Comparing<'a>;

    /// Whether a solver is wired; without one the Kernel's structural rule decides alone
    /// (OP-157 m.3 (n)).
    fn wired(&self) -> bool {
        true
    }
}

impl PolicyRelation {
    /// Whether this answer raises a structurally narrowing `policy.set` to expansion: widening,
    /// incomparable, may-error, and, from a wired solver, no answer (OP-157 m.3 (n)).
    #[must_use]
    pub const fn raises(self, wired: bool) -> bool {
        match self {
            Self::Widening | Self::Incomparable | Self::MayError => true,
            Self::Unknown => wired,
            Self::Equivalent | Self::Narrowing => false,
        }
    }
}

/// No analysis is wired: every change is [`PolicyRelation::Unknown`].
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAnalysis;

impl PolicyAnalysis for NoAnalysis {
    fn compare<'a>(&'a self, schema: &'a str, old: &'a str, new: &'a str) -> Comparing<'a> {
        let _ = (schema, old, new);
        Box::pin(std::future::ready(PolicyRelation::Unknown))
    }

    fn wired(&self) -> bool {
        false
    }
}

/// What a decision point recorded when it asked for an approval (§9.14.1, §13.7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The render digest of the intent (§9.13.3, XI-8).
    pub render: Digest,
    /// The intent's consequence tier.
    pub tier: access_kernel::tier::Tier,
}

/// Confirms who a new key belongs to before it is an Instance: the actor-binding of
/// `party_register` and `instance_create` (§7.9.2.3). The identity plane provides it; without
/// a binding the request is anonymous.
pub trait Binding {
    /// The Party and key bound to `kid`, if any.
    fn bound(&self, kid: &[u8; 32]) -> Option<(Id, PublicKey)>;
}

/// Fresh field salts (OP-106 m.15).
pub trait Salts {
    /// A fresh salt.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when no randomness is available.
    fn salt(&mut self) -> Result<[u8; 32], CoreError>;
}

/// The domains' event-id keys `K_D` (OP-141 m.18 (d)).
pub trait Keys: Send + Sync {
    /// The key of `domain`.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the key is missing or the token fails.
    fn event_key(&self, domain: &Digest) -> Result<EventKey, CoreError>;
    /// The token key of `domain` (OP-141 m.22 (d)).
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the key is missing or the token fails.
    fn token_key(&self, domain: &Digest) -> Result<TokenKey, CoreError>;
    /// The pseudonym key of `domain` (P52, OP-143 m.15 (d)).
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the token fails.
    fn pseudonym_key(
        &self,
        domain: &Digest,
    ) -> Result<access_crypto::pseudonym::PseudonymKey, CoreError>;
    /// Makes the event-id and token keys of the new domain `domain` that are missing
    /// (OP-141 m.18 (d), m.22 (d)); a key that exists is kept.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the token fails.
    fn open_domain(&self, domain: &Digest) -> Result<(), CoreError>;
}
