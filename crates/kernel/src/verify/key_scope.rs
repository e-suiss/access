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
}

pub(crate) const USAGES: [(&str, KeyUsage); 6] = [
    ("receipt", KeyUsage::Receipt),
    ("pap", KeyUsage::Pap),
    ("token", KeyUsage::Token),
    ("checkpoint", KeyUsage::Checkpoint),
    ("set", KeyUsage::Set),
    ("status-list", KeyUsage::StatusList),
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

/// The old binding after a handover or recovery (§9.10 recovery predicate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superseded {
    /// Checkpoint `C_{h+1}` or `N`.
    pub at: Digest,
    /// `N_cited` from the `domain.handover` / `domain.recover` record.
    pub cited: Digest,
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

/// Resolves the operational key that signed an artefact of `artefact_domain` at `iat`
/// (CR-58 m.5). The artefact signature is then verified with [`OperationalKey::key_set`].
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
) -> Result<OperationalKey, KeyScopeError> {
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
        || !key.alg.enabled()
        || !key.fits()
        || !hybrid_satisfiable(metadata.hybrid)
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

// OP-118 m.5, CR-55 m.1
const fn hybrid_satisfiable(policy: Option<Hybrid>) -> bool {
    matches!(policy, None | Some(Hybrid::Classic))
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
        };
        f.done()?;
        if out.operational_window_max_ms > MAX_WINDOW_MS {
            return Err(ModelError::Range);
        }
        Ok(out)
    }
}

// OP-118 m.4
fn horizon_caps(v: &Value) -> Result<BTreeMap<u8, u64>, ModelError> {
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

fn ct_key(ct: u8) -> Value {
    Value::text(CT_KEYS.get(usize::from(ct)).copied().unwrap_or(""))
}

const CT_KEYS: [&str; 4] = ["ct0", "ct1", "ct2", "ct3"];

fn set_of_vec<T>(
    v: &Value,
    non_empty: bool,
    read: impl Fn(&Value) -> Result<T, ModelError>,
) -> Result<Vec<T>, ModelError> {
    set_items(v, non_empty)?.iter().map(read).collect()
}

#[cfg(test)]
mod tests;
