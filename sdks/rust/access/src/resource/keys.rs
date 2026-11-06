//! The realm JWKS at the resource server (§9.9.3 rule 7, §9.11.2, §13.11 EP-4, MD-6, MD-7):
//! the keys that verify authority tokens, read from a document the caller fetched, within the
//! `key_epoch` window when it was fetched earlier. A key's `kid` is its RFC 7638 thumbprint
//! (CR-24); the algorithm allowlist comes from the resource server's configuration, never from
//! the document (MD-3).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::model::TrustedTime;
use access_kernel::verify::cose::{Algorithm, KeySet, PublicKey};
use access_kernel::verify::key_scope::thumbprint;

use super::Denied;
use crate::transport::Answer;

/// Largest JWKS document read (§14.6).
pub const MAX_JWKS: usize = 64 * 1024;

/// Default `key_epoch`: how long a fetched JWKS stays usable (MD-6, PD: 1 hour).
pub const DEFAULT_KEY_EPOCH_MS: u64 = 60 * 60 * 1000;

/// Longest `key_epoch` a resource server may configure (MD-6: 24 hours).
pub const MAX_KEY_EPOCH_MS: u64 = 24 * 60 * 60 * 1000;

/// What the key port hands back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keys {
    /// A fresh fetch of the JWKS.
    Fetched(Answer),
    /// The last JWKS the caller fetched, and when.
    Cached {
        /// The document.
        body: Vec<u8>,
        /// Trusted time of the fetch, Unix milliseconds.
        fetched_at: TrustedTime,
    },
}

/// The key port: the realm's JWKS.
pub trait KeySource {
    /// The JWKS, fetched now or as cached.
    fn jwks(&self) -> Keys;
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

/// Reads a JWKS document into the key set the tokens verify under: every Ed25519 or P-256
/// key whose `kid` is its thumbprint; other keys are not authority keys (MD-3) and are left
/// out. A document without such a key is refused.
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

/// The key set from what the port handed back: a 200 with a readable document, or a cached
/// document fetched no more than `key_epoch_ms` ago (§9.11.2: a JWKS that cannot be refreshed
/// serves within the `key_epoch` window, not beyond it).
///
/// # Errors
/// [`Denied`].
pub fn resolve(
    keys: Keys,
    allowed: &BTreeSet<Algorithm>,
    now: TrustedTime,
    key_epoch_ms: u64,
) -> Result<KeySet, Denied> {
    match keys {
        Keys::Fetched(Answer::Unanswered(fault)) => Err(Denied::KeysUnavailable(fault)),
        Keys::Fetched(Answer::Response(r)) if r.status != 200 => Err(Denied::KeysStatus(r.status)),
        Keys::Fetched(Answer::Response(r)) => key_set(&r.body, allowed),
        Keys::Cached { body, fetched_at } => {
            let age = now.checked_sub(fetched_at).ok_or(Denied::KeysStale)?;
            if age > key_epoch_ms {
                return Err(Denied::KeysStale);
            }
            key_set(&body, allowed)
        }
    }
}
