//! Domain Metadata and operational key scope (CR-58, CR-18, T20, TI-RT6, §9.10 step 1).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};
use suiss_crypto::dcbor::Value;

use super::Backend;
use super::cose::{Algorithm, CoseError, KeySet, PublicKey, verify_sign1};
use crate::codec::{
    Canonical, Fields, ModelError, int, map, map_value, opt_param_map, set_items, set_of,
    set_value, single, tagged, uint, word, word_of,
};
use crate::digest::Digest;
use crate::json::b64url_encode;
use crate::model::TrustedTime;

/// Content type of the binding-signed excerpt.
pub const EXCERPT_CONTENT_TYPE: &str = "application/access-key-excerpt+cbor";
/// Content type of the binding-signed Domain Metadata.
pub const METADATA_CONTENT_TYPE: &str = "application/access-domain-metadata+cbor";
/// Upper bound of the operational key window (T20).
pub const MAX_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// What an operational key may sign (CR-58 m.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyUsage {
    /// Decision receipts.
    Receipt,
    /// Portable Authority Proofs.
    Pap,
    /// Authority-carrying tokens.
    Token,
    /// Checkpoints.
    Checkpoint,
    /// Security event tokens.
    Set,
    /// Status lists.
    StatusList,
    /// Instance key lookup answers (OP-149 m.5).
    KeyLookup,
    /// Party status lookup answers (OP-149 m.28 (c)).
    PartyLookup,
}

pub(crate) const USAGES: [(&str, KeyUsage); 8] = [
    ("receipt", KeyUsage::Receipt),
    ("pap", KeyUsage::Pap),
    ("token", KeyUsage::Token),
    ("checkpoint", KeyUsage::Checkpoint),
    ("set", KeyUsage::Set),
    ("status-list", KeyUsage::StatusList),
    ("key-lookup", KeyUsage::KeyLookup),
    ("party-lookup", KeyUsage::PartyLookup),
];

/// Operational key declaration (T20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalKey {
    /// RFC 7638 SHA-256 thumbprint of `key` (CR-55 m.4).
    pub kid: [u8; 32],
    /// Algorithm.
    pub alg: Algorithm,
    /// Public key.
    pub key: PublicKey,
    /// First instant a signature may carry.
    pub valid_from: TrustedTime,
    /// Last instant a signature may carry.
    pub valid_until: TrustedTime,
    /// What the key may sign; never empty.
    pub usage: BTreeSet<KeyUsage>,
}

/// Excerpt payload embedded in an artefact (CR-58 m.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyExcerpt {
    /// Domain the key belongs to.
    pub domain: Digest,
    /// The key.
    pub key: OperationalKey,
}

/// Which domains a binding key speaks for (CR-58 m.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingScope {
    /// Only the metadata's own domain.
    Domain,
    /// A provider-wide key declared for these domains.
    Provider(BTreeSet<Digest>),
}

/// Why a binding key was superseded (OP-159 m.3 (i)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupersededCause {
    /// A binding re-anchor (OP-60, CR-45).
    ReAnchor,
    /// A handover to another provider.
    Handover,
    /// A forced recovery.
    Recovery,
}

const CAUSES: [(&str, SupersededCause); 3] = [
    ("re-anchor", SupersededCause::ReAnchor),
    ("handover", SupersededCause::Handover),
    ("recovery", SupersededCause::Recovery),
];

/// The old binding after a handover or recovery (§9.10 recovery predicate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superseded {
    /// Checkpoint `C_{h+1}` or `N`.
    pub at: Digest,
    /// `N_cited` from the `domain.handover` / `domain.recover` record.
    pub cited: Digest,
    /// Why it was superseded; absent in 0.6.0 metadata, which asks for evidence under every
    /// cause (OP-159 m.3 (i)).
    pub cause: Option<SupersededCause>,
}

/// A provider binding key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingKey {
    /// RFC 7638 thumbprint.
    pub kid: [u8; 32],
    /// Algorithm.
    pub alg: Algorithm,
    /// Public key.
    pub key: PublicKey,
    /// Scope.
    pub scope: BindingScope,
    /// Set after a handover or recovery.
    pub superseded: Option<Superseded>,
}

/// Minimum spec versions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpecVersions {
    /// Core semantic spec.
    pub core: u64,
    /// Core meta-schema.
    pub meta_schema: u64,
    /// Interop profiles.
    pub profiles: BTreeMap<String, u64>,
    /// Pinned schema digests.
    pub schemas: BTreeSet<Digest>,
}

/// Highest consequence tier (§13.7.2).
pub const MAX_CT: u8 = 3;

/// Local acceptance ceilings a verifier reads from metadata, never from the artefact (T20).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifierCaps {
    /// Horizon ceilings in milliseconds by consequence tier, 0 to [`MAX_CT`], written as
    /// `"ct0"` to `"ct3"` (OP-118 m.4, OP-122 m.1).
    pub horizon: BTreeMap<u8, u64>,
    /// Offline slice ceilings by budget unit.
    pub slice_max: BTreeMap<String, i64>,
}

/// Hybrid signature policy; absent is [`Hybrid::Classic`] (CR-55 m.11, OP-118 m.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hybrid {
    /// Classic signature required; a PQ signature is ignored.
    Classic,
    /// Classic and ML-DSA signatures both required and valid.
    Both,
    /// ML-DSA signature required; a classic signature is ignored.
    Pq,
}

const HYBRIDS: [(&str, Hybrid); 3] = [
    ("classic", Hybrid::Classic),
    ("both", Hybrid::Both),
    ("pq", Hybrid::Pq),
];

/// The authority fields of Domain Metadata (CR-58 m.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainMetadata {
    /// Domain identifier.
    pub domain: Digest,
    /// Genesis record digest.
    pub genesis: Digest,
    /// Publication time.
    pub issued_at: TrustedTime,
    /// Binding keys by `kid`.
    pub binding: BTreeMap<[u8; 32], BindingKey>,
    /// The only algorithm allowlist (SAI-40).
    pub algorithms: BTreeSet<Algorithm>,
    /// Operational key window ceiling; at most [`MAX_WINDOW_MS`].
    pub operational_window_max_ms: u64,
    /// Operational keys.
    pub operational_keys: Vec<OperationalKey>,
    /// Domain minimum versions.
    pub min_versions: SpecVersions,
    /// Versions the domain has adopted (OP-120 m.7).
    pub adopted: SpecVersions,
    /// Verifier ceilings.
    pub caps: Option<VerifierCaps>,
    /// Hybrid policy.
    pub hybrid: Option<Hybrid>,
    /// Discovery fields, opaque to the Kernel.
    pub discovery: Option<Vec<u8>>,
    /// What the domain declares about its witnesses, replicas, durability, residency, MMD,
    /// recovery and binding ceremony (OP-158 m.3 (b)); absent in 0.5.0 metadata.
    pub declared: Declarations,
}

/// A witness the domain declares (§16.6, SI-12, OP-158 m.3 (d)).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Witness {
    /// The note key name its cosignatures carry.
    pub name: String,
    /// Its public key.
    pub key: PublicKey,
    /// Its signature algorithm.
    pub algorithm: Algorithm,
    /// Who runs it.
    pub operator: String,
    /// Whether its operator is independent of the provider and the provider's operator.
    pub independent: bool,
}

impl Witness {
    /// A witness named `name` run by `operator`.
    #[must_use]
    pub const fn new(
        name: String,
        key: PublicKey,
        algorithm: Algorithm,
        operator: String,
        independent: bool,
    ) -> Self {
        Self {
            name,
            key,
            algorithm,
            operator,
            independent,
        }
    }
}

/// A replica the domain declares (§16.6.1, TI-13, OP-158 m.3 (f)): whose signed `replica_ack`
/// counts.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Replica {
    /// Its name.
    pub name: String,
    /// The key its acks are signed with.
    pub key: PublicKey,
    /// Who runs it.
    pub operator: String,
    /// Whether its operator is outside the provider.
    pub independent: bool,
}

impl Replica {
    /// A replica named `name` run by `operator`.
    #[must_use]
    pub const fn new(name: String, key: PublicKey, operator: String, independent: bool) -> Self {
        Self {
            name,
            key,
            operator,
            independent,
        }
    }
}

/// The durability profile the domain publishes (HL-40, OP-158 m.3 (p)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Synchronous standbys: no acknowledged write is lost (FA-1).
    Replicated,
    /// The small-provider profile: an acknowledged write can be lost with the node.
    SingleNode,
}

const DURABILITIES: [(&str, Durability); 2] = [
    ("replicated", Durability::Replicated),
    ("single-node", Durability::SingleNode),
];

/// Residency and DR class (CMP-26, OP-30, OP-158 m.3 (o)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrClass {
    /// One region.
    Regional,
    /// Synchronous across regions.
    MultiRegionSync,
}

const DR_CLASSES: [(&str, DrClass); 2] = [
    ("regional", DrClass::Regional),
    ("multi-region-sync", DrClass::MultiRegionSync),
];

/// Where the domain's cell is (OP-158 m.3 (o)).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Residency {
    /// The region identifier.
    pub region: String,
    /// Its DR class.
    pub class: DrClass,
}

impl Residency {
    /// Residency in `region` with `class`.
    #[must_use]
    pub const fn new(region: String, class: DrClass) -> Self {
        Self { region, class }
    }
}

/// The maximum merge delay of each log, in milliseconds (T16, OP-158 m.3 (c)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Mmd {
    /// The authority log.
    pub authority_ms: u64,
    /// The identity audit log.
    pub identity_ms: u64,
}

impl Mmd {
    /// The two delays.
    #[must_use]
    pub const fn new(authority_ms: u64, identity_ms: u64) -> Self {
        Self {
            authority_ms,
            identity_ms,
        }
    }
}

/// Whether a hosting resource is shared with other tenants (HL-8, HL-17, DL-10, OP-159 m.3 (s)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sharing {
    /// Shared with other tenants; the co-tenant risk applies.
    Shared,
    /// Dedicated to this domain's provider install.
    Dedicated,
}

const SHARINGS: [(&str, Sharing); 2] = [
    ("shared", Sharing::Shared),
    ("dedicated", Sharing::Dedicated),
];

/// The hosting the provider declares (HL-8, HL-17, DL-10, OP-159 m.3 (s)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Hosting {
    /// The HSM partition.
    pub hsm_partition: Sharing,
    /// The compute.
    pub compute: Sharing,
}

impl Hosting {
    /// Hosting with `hsm_partition` and `compute`.
    #[must_use]
    pub const fn new(hsm_partition: Sharing, compute: Sharing) -> Self {
        Self {
            hsm_partition,
            compute,
        }
    }
}

/// The crypto profile the domain declares (CR-15, CR-44, OP-159 m.3 (r)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoProfile {
    /// The standard algorithm set.
    Standard,
    /// FIPS-approved algorithms only; ML-DSA cannot join the allowlist.
    Fips,
}

const CRYPTO_PROFILES: [(&str, CryptoProfile); 2] = [
    ("standard", CryptoProfile::Standard),
    ("fips", CryptoProfile::Fips),
];

/// The last post-quantum re-anchor checkpoint the domain published (CR-45, RR-35, OP-159
/// m.3 (g)).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PqReanchor {
    /// Its tree size.
    pub size: u64,
    /// When it was cosigned.
    pub time: TrustedTime,
    /// The note key names of the witnesses whose post-quantum cosign it carries.
    pub witnesses: Vec<String>,
}

impl PqReanchor {
    /// The re-anchor checkpoint of `size` cosigned at `time` by `witnesses`.
    #[must_use]
    pub const fn new(size: u64, time: TrustedTime, witnesses: Vec<String>) -> Self {
        Self {
            size,
            time,
            witnesses,
        }
    }
}

/// Whether the domain has a recovery entry (§13.6, OP-158 m.3 (m)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// A rootTerms recovery entry exists.
    Available,
    /// None could be set up; S7 says "Recovery not available".
    NotAvailable,
}

const RECOVERIES: [(&str, Recovery); 2] = [
    ("available", Recovery::Available),
    ("not-available", Recovery::NotAvailable),
];

/// The Stage 13 declarations of Domain Metadata (OP-158 m.3 (b)). Every member is optional on
/// the wire; an absent one reads as nothing declared, which never grants an acknowledgement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Declarations {
    /// The witnesses.
    pub witnesses: Vec<Witness>,
    /// The replicas.
    pub replicas: Vec<Replica>,
    /// The durability profile.
    pub durability: Option<Durability>,
    /// The residency.
    pub residency: Option<Residency>,
    /// The maximum merge delays.
    pub mmd: Option<Mmd>,
    /// Whether recovery is available; absent reads as not available.
    pub recovery: Option<Recovery>,
    /// Digest of the binding ceremony transcript (CR-29, OP-157 m.7 (i)).
    pub ceremony_transcript: Option<Digest>,
    /// The last post-quantum re-anchor checkpoint; absent before the first (OP-159 m.3 (g)).
    pub pq_reanchor: Option<PqReanchor>,
    /// The hosting; absent reads as shared (OP-159 m.3 (s)).
    pub hosting: Option<Hosting>,
    /// The crypto profile (OP-159 m.3 (r)).
    pub crypto_profile: Option<CryptoProfile>,
    /// Whether signatures come from a FIPS 140-3 validated module; absent reads as no (OP-159
    /// m.3 (r)).
    pub fips_module: Option<bool>,
}

impl Declarations {
    /// Whether a SEC23 acknowledgement can ever be given: at least one declared replica and one
    /// independent witness. Anything less gives none (SEC23, TI-13).
    #[must_use]
    pub fn acknowledges(&self) -> bool {
        !self.replicas.is_empty() && self.witnesses.iter().any(|w| w.independent)
    }
}

/// Why a key is not accepted for an artefact. Each is a local DENY (§9.10 step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyScopeError {
    /// The excerpt or metadata signature does not verify, or its `kid` is not a binding key.
    #[error("signature: {0}")]
    Signature(#[from] CoseError),
    /// The payload is not a value of the model.
    #[error("payload: {0}")]
    Payload(#[from] ModelError),
    /// The binding key was superseded; only the inclusion-proof path may accept (CR-58 m.6).
    #[error("binding key superseded")]
    Superseded,
    /// The binding key does not speak for the artefact's domain (HL-8).
    #[error("binding key does not cover the domain")]
    OutOfScope,
    /// The excerpt names another domain (TI-RT6, G35).
    #[error("excerpt domain mismatch")]
    DomainMismatch,
    /// `kid` is not the key's thumbprint.
    #[error("kid is not the key thumbprint")]
    Thumbprint,
    /// Algorithm not in the metadata allowlist, or not the key's type.
    #[error("algorithm not allowed")]
    Algorithm,
    /// The key may not sign this kind of artefact.
    #[error("usage not allowed")]
    Usage,
    /// The window is inverted, too long, or does not contain `iat`.
    #[error("outside the key window")]
    Window,
    /// The domain retired its classical algorithm and the verifier pinned no post-quantum
    /// anchor (CR-45 RA-7, OP-159 m.3 (h)).
    #[error("post-quantum anchor missing")]
    PqAnchorMissing,
}

/// RFC 7638 SHA-256 JWK thumbprint (CR-24). `AKP` members follow the ML-DSA JOSE draft.
#[must_use]
pub fn thumbprint(key: &PublicKey) -> [u8; 32] {
    let json = match key {
        PublicKey::Ed25519(x) => alloc::format!(
            r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
            b64url_encode(x)
        ),
        PublicKey::P256(sec1) => {
            let (x, y) = sec1
                .get(1..)
                .and_then(|xy| xy.split_at_checked(32))
                .unwrap_or_default();
            alloc::format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                b64url_encode(x),
                b64url_encode(y)
            )
        }
        PublicKey::MlDsa(alg, public) => alloc::format!(
            r#"{{"alg":"{}","kty":"AKP","pub":"{}"}}"#,
            ml_dsa_name(*alg),
            b64url_encode(public)
        ),
    };
    Sha256::digest(json.as_bytes()).into()
}

const fn ml_dsa_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::MlDsa44 => "ML-DSA-44",
        Algorithm::MlDsa65 => "ML-DSA-65",
        _ => "ML-DSA-87",
    }
}

fn key_set(
    keys: impl IntoIterator<Item = ([u8; 32], PublicKey)>,
    allowed: &BTreeSet<Algorithm>,
) -> KeySet {
    let mut set = KeySet::default();
    set.keys.extend(keys);
    set.allowed.extend(allowed.iter().copied());
    set
}

/// Verifies and decodes binding-signed Domain Metadata. `trusted` are the binding keys the
/// verifier already holds (Genesis or the previous metadata). Freshness (TI-RT5) is checked by
/// the caller and passed in prepared form (CR-58 m.7).
///
/// # Errors
/// [`KeyScopeError`].
pub fn verify_metadata(
    backend: &impl Backend,
    bytes: &[u8],
    trusted: &KeySet,
) -> Result<DomainMetadata, KeyScopeError> {
    let verified = verify_sign1(backend, bytes, trusted, METADATA_CONTENT_TYPE)?;
    let metadata = DomainMetadata::from_bytes(&verified.payload)?;
    let signer = metadata
        .binding
        .get(&verified.kid)
        .ok_or(KeyScopeError::Signature(CoseError::UnknownKid))?;
    if signer.superseded.is_some() {
        return Err(KeyScopeError::Superseded);
    }
    if signer.alg != verified.algorithm || !metadata.algorithms.contains(&signer.alg) {
        return Err(KeyScopeError::Algorithm);
    }
    Ok(metadata)
}

/// What a verifier passes to [`operational_key`] for an artefact signed under a superseded
/// binding key: the artefact's exact-content digest, its [`Inclusion`] and the log and
/// independent witness keys that verify the cited checkpoint (P18, SEC25, U12, U27, OP-159
/// m.3 (i)).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct InclusionEvidence<'a> {
    /// The artefact's exact-content digest.
    pub artefact: Digest,
    /// The record, its path and the cited checkpoint.
    pub inclusion: Inclusion<'a>,
    /// The log origin line.
    pub origin: &'a str,
    /// The log key.
    pub log: &'a suiss_crypto::note::Verifier,
    /// The independent witness keys.
    pub witnesses: &'a [suiss_crypto::note::Verifier],
}

impl<'a> InclusionEvidence<'a> {
    /// The evidence for `artefact` at `inclusion` under `log` from `origin`.
    #[must_use]
    pub const fn new(
        artefact: Digest,
        inclusion: Inclusion<'a>,
        origin: &'a str,
        log: &'a suiss_crypto::note::Verifier,
        witnesses: &'a [suiss_crypto::note::Verifier],
    ) -> Self {
        Self {
            artefact,
            inclusion,
            origin,
            log,
            witnesses,
        }
    }
}

/// Resolves the operational key that signed an artefact of `artefact_domain` at `iat`
/// (CR-58 m.5). The artefact signature is then verified with [`OperationalKey::key_set`].
/// `evidence` is the inclusion evidence for a superseded binding (OP-159 m.3 (i)); a binding
/// that is superseded is refused whatever it carries until that path is decided.
///
/// # Errors
/// The first step that fails, as [`KeyScopeError`].
pub fn operational_key(
    backend: &impl Backend,
    metadata: &DomainMetadata,
    artefact_domain: &Digest,
    excerpt: &[u8],
    usage: KeyUsage,
    iat: TrustedTime,
    evidence: Option<&InclusionEvidence<'_>>,
) -> Result<OperationalKey, KeyScopeError> {
    resolve(
        backend,
        metadata,
        (artefact_domain, excerpt, usage, iat),
        evidence,
        |alg| hybrid_admits(metadata.hybrid, alg),
    )
}

/// [`operational_key`] with the hybrid check replaced by `admits`: one component of a hybrid
/// artefact is resolved on its own and the pair is checked by [`super::hybrid`].
pub(crate) fn resolve(
    backend: &impl Backend,
    metadata: &DomainMetadata,
    (artefact_domain, excerpt, usage, iat): (&Digest, &[u8], KeyUsage, TrustedTime),
    evidence: Option<&InclusionEvidence<'_>>,
    admits: impl Fn(Algorithm) -> bool,
) -> Result<OperationalKey, KeyScopeError> {
    let _ = evidence;
    let bindings = key_set(
        metadata.binding.values().map(|b| (b.kid, b.key.clone())),
        &metadata.algorithms,
    );
    let verified = verify_sign1(backend, excerpt, &bindings, EXCERPT_CONTENT_TYPE)?;
    let binding = metadata
        .binding
        .get(&verified.kid)
        .ok_or(KeyScopeError::Signature(CoseError::UnknownKid))?;
    if binding.alg != verified.algorithm {
        return Err(KeyScopeError::Algorithm);
    }
    if binding.superseded.is_some() {
        return Err(KeyScopeError::Superseded);
    }
    let in_scope = match &binding.scope {
        BindingScope::Domain => metadata.domain == *artefact_domain,
        BindingScope::Provider(domains) => domains.contains(artefact_domain),
    };
    if !in_scope {
        return Err(KeyScopeError::OutOfScope);
    }
    let KeyExcerpt { domain, key } = KeyExcerpt::from_bytes(&verified.payload)?;
    if domain != *artefact_domain {
        return Err(KeyScopeError::DomainMismatch);
    }
    if key.kid != thumbprint(&key.key) {
        return Err(KeyScopeError::Thumbprint);
    }
    if !metadata.algorithms.contains(&key.alg)
        || !backend.supports(key.alg)
        || !key.fits()
        || !admits(key.alg)
    {
        return Err(KeyScopeError::Algorithm);
    }
    if !key.usage.contains(&usage) {
        return Err(KeyScopeError::Usage);
    }
    let width = key
        .valid_until
        .checked_sub(key.valid_from)
        .ok_or(KeyScopeError::Window)?;
    if width > metadata.operational_window_max_ms.min(MAX_WINDOW_MS)
        || iat < key.valid_from
        || iat > key.valid_until
    {
        return Err(KeyScopeError::Window);
    }
    Ok(key)
}

/// The record field that commits the digest of the artefact a decision produced (§13.3 rule 1).
pub const ARTEFACT_FIELD: &str = "artefact";

/// A consistency path to the checkpoint of `size` records with `root` (RFC 9162).
pub type Consistency<'a> = (u64, [u8; 32], &'a [[u8; 32]]);

/// What a verifier holds to accept an artefact signed under a superseded binding key: the
/// committed record that names the artefact, its RFC 9162 path into the cited checkpoint, that
/// checkpoint's signed note, and after a handover the consistency path to `C_{h+1}`
/// (`to_size`, `to_root`, path) (§9.10, §13.3, P18, SEC25, U12, U27).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Inclusion<'a> {
    /// The committed record, disclosed.
    pub record: &'a crate::record::Disclosure,
    /// Inclusion path of the record in the cited checkpoint.
    pub path: &'a [[u8; 32]],
    /// The cited checkpoint's signed note with its cosignatures.
    pub note: &'a str,
    /// The consistency path to the checkpoint the old key is superseded at.
    pub consistency: Option<Consistency<'a>>,
}

impl<'a> Inclusion<'a> {
    /// The evidence of `record` at `path` in the checkpoint `note`.
    #[must_use]
    pub const fn new(
        record: &'a crate::record::Disclosure,
        path: &'a [[u8; 32]],
        note: &'a str,
        consistency: Option<Consistency<'a>>,
    ) -> Self {
        Self {
            record,
            path,
            note,
            consistency,
        }
    }
}

/// The superseded-at predicate (§9.10 step 1, §13.3, P18, SEC25, U12, U27): an artefact with
/// exact-content digest `artefact`, signed under `binding` whose key is superseded, is accepted
/// only when its record commits `artefact` under [`ARTEFACT_FIELD`], sits in the cited checkpoint
/// `N_cited` (its root is `Superseded::cited`), that checkpoint verifies under `log` from
/// `origin` with at least one cosignature of the independent `witnesses`, and, when the key is
/// superseded at another checkpoint (a handover's `C_{h+1}`), a consistency path reaches it. The
/// artefact's own Exercise id or time is never evidence.
///
/// # Errors
/// [`KeyScopeError::Superseded`] for every failed condition.
pub fn superseded_inclusion(
    backend: &impl Backend,
    binding: &BindingKey,
    artefact: &Digest,
    evidence: &Inclusion<'_>,
    (origin, log, witnesses): (
        &str,
        &suiss_crypto::note::Verifier,
        &[suiss_crypto::note::Verifier],
    ),
) -> Result<(), KeyScopeError> {
    let Some(superseded) = binding.superseded else {
        return Err(KeyScopeError::Superseded);
    };
    let independent: Vec<suiss_crypto::note::Verifier> = witnesses
        .iter()
        .filter(|w| w.is_cosigner() && (w.name() != log.name() || w.id() != log.id()))
        .cloned()
        .collect();
    let (cp, accepted) =
        suiss_crypto::note::verify_checkpoint(backend, evidence.note, origin, log, &independent)
            .map_err(|_| KeyScopeError::Superseded)?;
    let cosigned = accepted.iter().any(|a| {
        a.timestamp.is_some()
            && independent
                .iter()
                .any(|w| w.name() == a.name && w.id() == a.id)
    });
    let committed = evidence
        .record
        .opened
        .get(ARTEFACT_FIELD)
        .is_some_and(|f| Digest::from_value(&f.value) == Some(*artefact));
    if !cosigned
        || !committed
        || cp.root != superseded.cited.0
        || evidence
            .record
            .verify_inclusion(cp.size, evidence.path, &cp.root)
            .is_err()
    {
        return Err(KeyScopeError::Superseded);
    }
    match evidence.consistency {
        None if superseded.at == superseded.cited => Ok(()),
        Some((to_size, to_root, path))
            if to_root == superseded.at.0
                && crate::digest::verify_consistency(
                    cp.size, to_size, &cp.root, &to_root, path,
                )
                .is_ok() =>
        {
            Ok(())
        }
        _ => Err(KeyScopeError::Superseded),
    }
}

/// Whether one signature with `alg` can satisfy `policy` alone (L0-SIG-75a, OP-159 m.3 (e)):
/// `classic` (or none) a classical algorithm, `pq` an ML-DSA one, and `both` never: under `both`
/// a single signature is not enough, whichever it is (CR-42 m.2, SAI-44).
#[must_use]
pub const fn hybrid_admits(policy: Option<Hybrid>, alg: Algorithm) -> bool {
    match policy {
        None | Some(Hybrid::Classic) => !super::ml_dsa::is_ml_dsa(alg),
        Some(Hybrid::Pq) => super::ml_dsa::is_ml_dsa(alg),
        Some(Hybrid::Both) => false,
    }
}

impl OperationalKey {
    /// The key set that verifies the artefact signed with this key.
    #[must_use]
    pub fn key_set(&self) -> KeySet {
        key_set([(self.kid, self.key.clone())], &BTreeSet::from([self.alg]))
    }

    fn fits(&self) -> bool {
        self.key.check().is_ok()
            && matches!(
                (&self.key, self.alg),
                (PublicKey::Ed25519(_), Algorithm::Ed25519)
                    | (PublicKey::P256(_), Algorithm::Esp256 | Algorithm::Es256)
            )
            || matches!(&self.key, PublicKey::MlDsa(a, _) if *a == self.alg)
    }
}

fn alg_value(a: Algorithm) -> Value {
    Value::int(a.cose())
}

fn alg_of(v: &Value) -> Result<Algorithm, ModelError> {
    Algorithm::from_cose(int(v)?).ok_or(ModelError::Unknown)
}

fn bytes32(v: &Value) -> Result<[u8; 32], ModelError> {
    match v {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| ModelError::Range),
        _ => Err(ModelError::Shape),
    }
}

fn bytes(v: &Value) -> Result<Vec<u8>, ModelError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(ModelError::Shape),
    }
}

impl Canonical for PublicKey {
    fn to_value(&self) -> Value {
        match self {
            Self::Ed25519(k) => tagged("ed25519", Value::Bytes(k.to_vec())),
            Self::P256(k) => tagged("p256", Value::Bytes(k.clone())),
            Self::MlDsa(a, k) => tagged(
                "ml_dsa",
                Value::Array(alloc::vec![alg_value(*a), Value::Bytes(k.clone())]),
            ),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let key = match single(v)? {
            ("ed25519", k) => Self::Ed25519(bytes32(k)?),
            ("p256", k) => Self::P256(bytes(k)?),
            ("ml_dsa", Value::Array(parts)) => match parts.as_slice() {
                [a, k] => Self::MlDsa(alg_of(a)?, bytes(k)?),
                _ => return Err(ModelError::Shape),
            },
            ("ml_dsa", _) => return Err(ModelError::Shape),
            _ => return Err(ModelError::Unknown),
        };
        key.check().map_err(|_| ModelError::Range)?;
        Ok(key)
    }
}

// OP-116 m.2
impl Canonical for KeySet {
    fn to_value(&self) -> Value {
        map([
            (
                "keys",
                Some(Value::Map(
                    self.keys
                        .iter()
                        .map(|(kid, key)| (Value::Bytes(kid.to_vec()), key.to_value()))
                        .collect(),
                )),
            ),
            (
                "allowed",
                Some(set_value(self.allowed.iter().map(|a| alg_value(*a)))),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let Value::Map(entries) = f.req("keys")? else {
            return Err(ModelError::Shape);
        };
        if entries.is_empty() {
            return Err(ModelError::Range);
        }
        let mut set = KeySet::default();
        for (kid, key) in entries {
            if set
                .keys
                .insert(bytes32(kid)?, PublicKey::from_value(key)?)
                .is_some()
            {
                return Err(ModelError::SetOrder);
            }
        }
        set.allowed = set_of(f.req("allowed")?, true, alg_of)?;
        f.done()?;
        Ok(set)
    }
}

impl Canonical for OperationalKey {
    fn to_value(&self) -> Value {
        map([
            ("kid", Some(Value::Bytes(self.kid.to_vec()))),
            ("alg", Some(alg_value(self.alg))),
            ("key", Some(self.key.to_value())),
            ("valid_from", Some(Value::Unsigned(self.valid_from))),
            ("valid_until", Some(Value::Unsigned(self.valid_until))),
            (
                "usage",
                Some(set_value(self.usage.iter().map(|u| word_of(*u, &USAGES)))),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let key = Self {
            kid: bytes32(f.req("kid")?)?,
            alg: alg_of(f.req("alg")?)?,
            key: PublicKey::from_value(f.req("key")?)?,
            valid_from: uint(f.req("valid_from")?)?,
            valid_until: uint(f.req("valid_until")?)?,
            usage: set_of(f.req("usage")?, true, |u| word(u, &USAGES))?,
        };
        f.done()?;
        Ok(key)
    }
}

impl Canonical for KeyExcerpt {
    fn to_value(&self) -> Value {
        map([
            ("domain", Some(self.domain.to_value())),
            ("key", Some(self.key.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let e = Self {
            domain: Digest::from_value(f.req("domain")?).ok_or(ModelError::Shape)?,
            key: OperationalKey::from_value(f.req("key")?)?,
        };
        f.done()?;
        Ok(e)
    }
}

impl Canonical for BindingScope {
    fn to_value(&self) -> Value {
        match self {
            Self::Domain => Value::text("domain"),
            Self::Provider(d) => tagged("provider", set_value(d.iter().map(Canonical::to_value))),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        match v {
            Value::Text(t) if t == "domain" => Ok(Self::Domain),
            Value::Text(_) => Err(ModelError::Unknown),
            _ => match single(v)? {
                ("provider", d) => Ok(Self::Provider(set_of(d, true, digest_model)?)),
                _ => Err(ModelError::Unknown),
            },
        }
    }
}

fn digest_model(v: &Value) -> Result<Digest, ModelError> {
    Digest::from_value(v).ok_or(ModelError::Shape)
}

impl Canonical for BindingKey {
    fn to_value(&self) -> Value {
        map([
            ("kid", Some(Value::Bytes(self.kid.to_vec()))),
            ("alg", Some(alg_value(self.alg))),
            ("key", Some(self.key.to_value())),
            ("scope", Some(self.scope.to_value())),
            (
                "superseded",
                self.superseded.map(|s| {
                    map([
                        ("at", Some(s.at.to_value())),
                        ("cited", Some(s.cited.to_value())),
                        ("cause", s.cause.map(|c| word_of(c, &CAUSES))),
                    ])
                }),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let superseded = f
            .opt("superseded")
            .map(|s| {
                let mut g = Fields::of(s)?;
                let out = Superseded {
                    at: digest_model(g.req("at")?)?,
                    cited: digest_model(g.req("cited")?)?,
                    cause: g.opt("cause").map(|c| word(c, &CAUSES)).transpose()?,
                };
                g.done()?;
                Ok::<_, ModelError>(out)
            })
            .transpose()?;
        let key = Self {
            kid: bytes32(f.req("kid")?)?,
            alg: alg_of(f.req("alg")?)?,
            key: PublicKey::from_value(f.req("key")?)?,
            scope: BindingScope::from_value(f.req("scope")?)?,
            superseded,
        };
        f.done()?;
        if key.kid != thumbprint(&key.key) {
            return Err(ModelError::Range);
        }
        Ok(key)
    }
}

impl Canonical for SpecVersions {
    fn to_value(&self) -> Value {
        map([
            ("core", Some(Value::Unsigned(self.core))),
            ("meta_schema", Some(Value::Unsigned(self.meta_schema))),
            (
                "profiles",
                map_value(&self.profiles, |n| Value::Unsigned(*n)),
            ),
            (
                "schemas",
                (!self.schemas.is_empty())
                    .then(|| set_value(self.schemas.iter().map(Canonical::to_value))),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let out = Self {
            core: uint(f.req("core")?)?,
            meta_schema: uint(f.req("meta_schema")?)?,
            profiles: opt_param_map(f.opt("profiles"), uint)?,
            schemas: f
                .opt("schemas")
                .map(|s| set_of(s, true, digest_model))
                .transpose()?
                .unwrap_or_default(),
        };
        f.done()?;
        Ok(out)
    }
}

impl Canonical for VerifierCaps {
    fn to_value(&self) -> Value {
        map([
            (
                "horizon",
                (!self.horizon.is_empty()).then(|| {
                    Value::Map(
                        self.horizon
                            .iter()
                            .map(|(ct, ms)| (ct_key(*ct), Value::Unsigned(*ms)))
                            .collect(),
                    )
                }),
            ),
            ("slice_max", map_value(&self.slice_max, |n| Value::int(*n))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let out = Self {
            horizon: f
                .opt("horizon")
                .map(horizon_caps)
                .transpose()?
                .unwrap_or_default(),
            slice_max: opt_param_map(f.opt("slice_max"), int)?,
        };
        f.done()?;
        Ok(out)
    }
}

impl Canonical for DomainMetadata {
    fn to_value(&self) -> Value {
        map([
            ("domain", Some(self.domain.to_value())),
            ("genesis", Some(self.genesis.to_value())),
            ("issued_at", Some(Value::Unsigned(self.issued_at))),
            (
                "binding",
                Some(set_value(self.binding.values().map(Canonical::to_value))),
            ),
            (
                "algorithms",
                Some(set_value(self.algorithms.iter().map(|a| alg_value(*a)))),
            ),
            (
                "operational_window_max_ms",
                Some(Value::Unsigned(self.operational_window_max_ms)),
            ),
            (
                "operational_keys",
                Some(set_value(
                    self.operational_keys.iter().map(Canonical::to_value),
                )),
            ),
            ("min_versions", Some(self.min_versions.to_value())),
            ("adopted", Some(self.adopted.to_value())),
            ("caps", self.caps.as_ref().map(Canonical::to_value)),
            ("hybrid", self.hybrid.map(|h| word_of(h, &HYBRIDS))),
            ("discovery", self.discovery.clone().map(Value::Bytes)),
            (
                "witnesses",
                (!self.declared.witnesses.is_empty())
                    .then(|| set_value(self.declared.witnesses.iter().map(witness_value))),
            ),
            (
                "replicas",
                (!self.declared.replicas.is_empty())
                    .then(|| set_value(self.declared.replicas.iter().map(replica_value))),
            ),
            (
                "durability",
                self.declared.durability.map(|d| word_of(d, &DURABILITIES)),
            ),
            (
                "residency",
                self.declared.residency.as_ref().map(|r| {
                    map([
                        ("region", Some(Value::text(&r.region))),
                        ("class", Some(word_of(r.class, &DR_CLASSES))),
                    ])
                }),
            ),
            (
                "mmd",
                self.declared.mmd.map(|m| {
                    map([
                        ("authority_ms", Some(Value::Unsigned(m.authority_ms))),
                        ("identity_ms", Some(Value::Unsigned(m.identity_ms))),
                    ])
                }),
            ),
            (
                "recovery",
                self.declared.recovery.map(|r| word_of(r, &RECOVERIES)),
            ),
            (
                "ceremony_transcript",
                self.declared
                    .ceremony_transcript
                    .as_ref()
                    .map(Canonical::to_value),
            ),
            (
                "pq_reanchor",
                self.declared.pq_reanchor.as_ref().map(pq_reanchor_value),
            ),
            (
                "hosting",
                self.declared.hosting.map(|h| {
                    map([
                        ("hsm_partition", Some(word_of(h.hsm_partition, &SHARINGS))),
                        ("compute", Some(word_of(h.compute, &SHARINGS))),
                    ])
                }),
            ),
            (
                "crypto_profile",
                self.declared
                    .crypto_profile
                    .map(|c| word_of(c, &CRYPTO_PROFILES)),
            ),
            ("fips_module", self.declared.fips_module.map(Value::Bool)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let mut binding = BTreeMap::new();
        for b in set_of_vec(f.req("binding")?, true, BindingKey::from_value)? {
            if binding.insert(b.kid, b).is_some() {
                return Err(ModelError::SetOrder);
            }
        }
        let out = Self {
            domain: digest_model(f.req("domain")?)?,
            genesis: digest_model(f.req("genesis")?)?,
            issued_at: uint(f.req("issued_at")?)?,
            binding,
            algorithms: set_of(f.req("algorithms")?, true, alg_of)?,
            operational_window_max_ms: uint(f.req("operational_window_max_ms")?)?,
            operational_keys: set_of_vec(
                f.req("operational_keys")?,
                false,
                OperationalKey::from_value,
            )?,
            min_versions: SpecVersions::from_value(f.req("min_versions")?)?,
            adopted: SpecVersions::from_value(f.req("adopted")?)?,
            caps: f.opt("caps").map(VerifierCaps::from_value).transpose()?,
            hybrid: f.opt("hybrid").map(|h| word(h, &HYBRIDS)).transpose()?,
            discovery: f.opt("discovery").map(bytes).transpose()?,
            declared: declarations(&mut f)?,
        };
        f.done()?;
        if out.operational_window_max_ms > MAX_WINDOW_MS {
            return Err(ModelError::Range);
        }
        Ok(out)
    }
}

fn name(v: &Value) -> Result<String, ModelError> {
    let t = crate::codec::text(v)?;
    if t.is_empty() || t.len() > 255 {
        return Err(ModelError::Range);
    }
    Ok(String::from(t))
}

pub(crate) fn witness_value(w: &Witness) -> Value {
    map([
        ("name", Some(Value::text(&w.name))),
        ("key", Some(w.key.to_value())),
        ("alg", Some(alg_value(w.algorithm))),
        ("operator", Some(Value::text(&w.operator))),
        ("independent", Some(Value::Bool(w.independent))),
    ])
}

pub(crate) fn witness(v: &Value) -> Result<Witness, ModelError> {
    let mut f = Fields::of(v)?;
    let out = Witness {
        name: name(f.req("name")?)?,
        key: PublicKey::from_value(f.req("key")?)?,
        algorithm: alg_of(f.req("alg")?)?,
        operator: name(f.req("operator")?)?,
        independent: crate::codec::boolean(f.req("independent")?)?,
    };
    f.done()?;
    Ok(out)
}

pub(crate) fn replica_value(r: &Replica) -> Value {
    map([
        ("name", Some(Value::text(&r.name))),
        ("key", Some(r.key.to_value())),
        ("operator", Some(Value::text(&r.operator))),
        ("independent", Some(Value::Bool(r.independent))),
    ])
}

pub(crate) fn replica(v: &Value) -> Result<Replica, ModelError> {
    let mut f = Fields::of(v)?;
    let out = Replica {
        name: name(f.req("name")?)?,
        key: PublicKey::from_value(f.req("key")?)?,
        operator: name(f.req("operator")?)?,
        independent: crate::codec::boolean(f.req("independent")?)?,
    };
    f.done()?;
    Ok(out)
}

fn pq_reanchor_value(r: &PqReanchor) -> Value {
    map([
        ("size", Some(Value::Unsigned(r.size))),
        ("time", Some(Value::Unsigned(r.time))),
        (
            "witnesses",
            Some(set_value(r.witnesses.iter().map(|w| Value::text(w)))),
        ),
    ])
}

// OP-159 m.3 (g)
fn pq_reanchor(v: &Value) -> Result<PqReanchor, ModelError> {
    let mut g = Fields::of(v)?;
    let out = PqReanchor {
        size: uint(g.req("size")?)?,
        time: uint(g.req("time")?)?,
        witnesses: set_of_vec(g.req("witnesses")?, true, name)?,
    };
    g.done()?;
    Ok(out)
}

// OP-159 m.3 (s)
fn hosting(v: &Value) -> Result<Hosting, ModelError> {
    let mut g = Fields::of(v)?;
    let out = Hosting {
        hsm_partition: word(g.req("hsm_partition")?, &SHARINGS)?,
        compute: word(g.req("compute")?, &SHARINGS)?,
    };
    g.done()?;
    Ok(out)
}

// OP-158 m.3 (b), OP-159 m.3 (b)
fn declarations(f: &mut Fields<'_>) -> Result<Declarations, ModelError> {
    let residency = f
        .opt("residency")
        .map(|r| {
            let mut g = Fields::of(r)?;
            let out = Residency {
                region: name(g.req("region")?)?,
                class: word(g.req("class")?, &DR_CLASSES)?,
            };
            g.done()?;
            Ok::<_, ModelError>(out)
        })
        .transpose()?;
    let mmd = f
        .opt("mmd")
        .map(|m| {
            let mut g = Fields::of(m)?;
            let out = Mmd {
                authority_ms: uint(g.req("authority_ms")?)?,
                identity_ms: uint(g.req("identity_ms")?)?,
            };
            g.done()?;
            Ok::<_, ModelError>(out)
        })
        .transpose()?;
    Ok(Declarations {
        witnesses: f
            .opt("witnesses")
            .map(|w| set_of_vec(w, true, witness))
            .transpose()?
            .unwrap_or_default(),
        replicas: f
            .opt("replicas")
            .map(|r| set_of_vec(r, true, replica))
            .transpose()?
            .unwrap_or_default(),
        durability: f
            .opt("durability")
            .map(|d| word(d, &DURABILITIES))
            .transpose()?,
        residency,
        mmd,
        recovery: f
            .opt("recovery")
            .map(|r| word(r, &RECOVERIES))
            .transpose()?,
        ceremony_transcript: f.opt("ceremony_transcript").map(digest_model).transpose()?,
        pq_reanchor: f.opt("pq_reanchor").map(pq_reanchor).transpose()?,
        hosting: f.opt("hosting").map(hosting).transpose()?,
        crypto_profile: f
            .opt("crypto_profile")
            .map(|c| word(c, &CRYPTO_PROFILES))
            .transpose()?,
        fips_module: f
            .opt("fips_module")
            .map(crate::codec::boolean)
            .transpose()?,
    })
}

// OP-118 m.4
pub(crate) fn horizon_caps(v: &Value) -> Result<BTreeMap<u8, u64>, ModelError> {
    let mut f = Fields::of(v)?;
    if f.is_empty() {
        return Err(ModelError::Range);
    }
    let out = f
        .drain(|k, ms| Ok((ct_of(k)?, uint(ms)?)))?
        .into_iter()
        .collect();
    f.done()?;
    Ok(out)
}

// OP-122 m.1
fn ct_of(key: &str) -> Result<u8, ModelError> {
    CT_KEYS
        .iter()
        .position(|k| *k == key)
        .and_then(|i| u8::try_from(i).ok())
        .ok_or(ModelError::Unknown)
}

pub(crate) fn ct_key(ct: u8) -> Value {
    Value::text(CT_KEYS.get(usize::from(ct)).copied().unwrap_or(""))
}

const CT_KEYS: [&str; 4] = ["ct0", "ct1", "ct2", "ct3"];

pub(crate) fn set_of_vec<T>(
    v: &Value,
    non_empty: bool,
    read: impl Fn(&Value) -> Result<T, ModelError>,
) -> Result<Vec<T>, ModelError> {
    set_items(v, non_empty)?.iter().map(read).collect()
}

#[cfg(test)]
mod tests;
