//! The keys that verify authority tokens at the resource server (§10.4.5, §9.10 step 1, §9.11.2,
//! §13.11 EP-4, MD-6, MD-7, TI-RT6): the domain's operational keys declared for usage `token`
//! in its binding-signed Domain Metadata, verified against the binding keys the resource server
//! pins, read within the `key_epoch` window when it was fetched earlier. A realm JWKS key, or
//! any key the metadata does not declare for `token` at the token's `iat`, verifies nothing.
//! The algorithm allowlist is the intersection of the metadata's and the resource server's
//! configuration, never the token header's (MD-3).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::model::TrustedTime;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, KeySet, PublicKey};
use access_kernel::verify::key_scope::{
    DomainMetadata, KeyUsage, MAX_WINDOW_MS, OperationalKey, thumbprint, verify_metadata,
};

use super::Denied;
use crate::transport::Answer;

/// Largest JWKS document read (§14.6).
pub const MAX_JWKS: usize = 64 * 1024;

/// Largest Domain Metadata document read (§14.6).
pub const MAX_METADATA: usize = 64 * 1024;

/// Default `key_epoch`: how long fetched Domain Metadata stays usable (MD-6, PD: 1 hour).
pub const DEFAULT_KEY_EPOCH_MS: u64 = 60 * 60 * 1000;

/// Longest `key_epoch` a resource server may configure (MD-6: 24 hours).
pub const MAX_KEY_EPOCH_MS: u64 = 24 * 60 * 60 * 1000;

/// What the key port hands back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keys {
    /// A fresh fetch of the binding-signed Domain Metadata.
    Fetched(Answer),
    /// The last binding-signed Domain Metadata the caller fetched, and when.
    Cached {
        /// The `COSE_Sign1` bytes.
        body: Vec<u8>,
        /// Trusted time of the fetch, Unix milliseconds.
        fetched_at: TrustedTime,
    },
}

/// The key port: the domain's binding-signed Domain Metadata
/// (`application/access-domain-metadata+cbor`, served at
/// `/.well-known/access-domain-metadata/{DomainID}`).
pub trait KeySource {
    /// The signed metadata, fetched now or as cached.
    fn metadata(&self) -> Keys;
}

fn binding_keys(pinned: &DomainMetadata) -> KeySet {
    let mut set = KeySet::default();
    set.keys.extend(
        pinned
            .binding
            .values()
            .filter(|b| b.superseded.is_none())
            .map(|b| (b.kid, b.key.clone())),
    );
    set.allowed.extend(pinned.algorithms.iter().copied());
    set
}

/// Verifies signed Domain Metadata against the binding keys of the `pinned` metadata (CR-58):
/// the same domain, issued no earlier than the pinned one.
///
/// # Errors
/// [`Denied::KeysMalformed`].
pub fn verified(body: &[u8], pinned: &DomainMetadata) -> Result<DomainMetadata, Denied> {
    if body.len() > MAX_METADATA {
        return Err(Denied::KeysMalformed);
    }
    let metadata = verify_metadata(&PureBackend, body, &binding_keys(pinned))
        .map_err(|_| Denied::KeysMalformed)?;
    // TI-RT6, TI-RT5
    if metadata.domain != pinned.domain || metadata.issued_at < pinned.issued_at {
        return Err(Denied::KeysMalformed);
    }
    Ok(metadata)
}

/// The metadata from what the port handed back: a 200 with metadata the pinned binding keys
/// signed, or such a document fetched no more than `key_epoch_ms` ago (§9.11.2: keys that
/// cannot be refreshed serve within the `key_epoch` window, not beyond it).
///
/// # Errors
/// [`Denied`].
pub fn resolve(
    keys: Keys,
    pinned: &DomainMetadata,
    now: TrustedTime,
    key_epoch_ms: u64,
) -> Result<DomainMetadata, Denied> {
    match keys {
        Keys::Fetched(Answer::Unanswered(fault)) => Err(Denied::KeysUnavailable(fault)),
        Keys::Fetched(Answer::Response(r)) if r.status != 200 => Err(Denied::KeysStatus(r.status)),
        Keys::Fetched(Answer::Response(r)) => verified(&r.body, pinned),
        Keys::Cached { body, fetched_at } => {
            let age = now.checked_sub(fetched_at).ok_or(Denied::KeysStale)?;
            if age > key_epoch_ms {
                return Err(Denied::KeysStale);
            }
            verified(&body, pinned)
        }
    }
}

fn usable(metadata: &DomainMetadata, key: &OperationalKey, allowed: &BTreeSet<Algorithm>) -> bool {
    let fits = matches!(
        (&key.key, key.alg),
        (PublicKey::Ed25519(_), Algorithm::Ed25519)
            | (PublicKey::P256(_), Algorithm::Esp256 | Algorithm::Es256)
    );
    let width = key.valid_until.checked_sub(key.valid_from);
    fits && key.key.check().is_ok()
        && key.kid == thumbprint(&key.key)
        && key.alg.enabled()
        && metadata.algorithms.contains(&key.alg)
        && allowed.contains(&key.alg)
        && width.is_some_and(|w| w <= metadata.operational_window_max_ms.min(MAX_WINDOW_MS))
}

/// The key set of the operational keys `metadata` declares for `usage` that the allowlist
/// admits (CR-58 m.5, TI-RT6). Whether the key that verified was live at the artefact's `iat`
/// is [`live_at`].
#[must_use]
pub fn usage_keys(
    metadata: &DomainMetadata,
    usage: KeyUsage,
    allowed: &BTreeSet<Algorithm>,
) -> KeySet {
    let mut set = KeySet::default();
    for key in metadata
        .operational_keys
        .iter()
        .filter(|k| k.usage.contains(&usage) && usable(metadata, k, allowed))
    {
        if set.insert(key.kid, key.key.clone()).is_ok() {
            set.allowed.insert(key.alg);
        }
    }
    set
}

/// Whether the key `kid` of `metadata`, declared for `usage`, was live in the second `iat_s`
/// (§9.10 step 1: the signature time is inside the operational key's window). A JOSE `iat` is
/// whole seconds, rounded down from the signing time, so the key's window must overlap that
/// second.
#[must_use]
pub fn live_at(metadata: &DomainMetadata, kid: &[u8; 32], usage: KeyUsage, iat_s: u64) -> bool {
    let Some(from) = iat_s.checked_mul(1000) else {
        return false;
    };
    let until = from.saturating_add(999);
    metadata.operational_keys.iter().any(|k| {
        k.kid == *kid && k.usage.contains(&usage) && k.valid_from <= until && from <= k.valid_until
    })
}

fn coordinate(jwk: &Json, name: &str) -> Option<[u8; 32]> {
    let raw = b64url_decode(jwk.get(name)?.as_str()?).ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

fn public_key(jwk: &Json) -> Option<PublicKey> {
    let text = |name: &str| jwk.get(name).and_then(Json::as_str);
    match (text("kty"), text("crv")) {
        (Some("OKP"), Some("Ed25519")) => Some(PublicKey::Ed25519(coordinate(jwk, "x")?)),
        (Some("EC"), Some("P-256")) => {
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(4);
            sec1.extend_from_slice(&coordinate(jwk, "x")?);
            sec1.extend_from_slice(&coordinate(jwk, "y")?);
            Some(PublicKey::P256(sec1))
        }
        _ => None,
    }
}

/// Reads a realm JWKS into the key set identity assertions (ID tokens) verify under: every
/// Ed25519 or P-256 key whose `kid` is its RFC 7638 thumbprint (CR-24). A realm key never
/// verifies an authority token (§10.4.5); those resolve through [`usage_keys`]. A document
/// without such a key is refused.
///
/// # Errors
/// [`Denied::KeysMalformed`].
pub fn key_set(body: &[u8], allowed: &BTreeSet<Algorithm>) -> Result<KeySet, Denied> {
    let doc = json::parse(body, MAX_JWKS).map_err(|_| Denied::KeysMalformed)?;
    let Some(Json::Array(keys)) = doc.get("keys") else {
        return Err(Denied::KeysMalformed);
    };
    let mut set = KeySet {
        keys: BTreeMap::new(),
        allowed: allowed.clone(),
    };
    for jwk in keys {
        let Some(key) = public_key(jwk) else { continue };
        let kid = thumbprint(&key);
        let declared = jwk
            .get("kid")
            .and_then(Json::as_str)
            .and_then(|k| b64url_decode(k).ok());
        if declared.as_deref() != Some(kid.as_slice()) {
            continue;
        }
        set.insert(kid, key).map_err(|_| Denied::KeysMalformed)?;
    }
    if set.keys.is_empty() {
        return Err(Denied::KeysMalformed);
    }
    Ok(set)
}
