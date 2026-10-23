//! SD-JWT presentations (RFC 9901) under CR-55 m.7.
//!
//! Every disclosure must be referenced exactly once; decoy digests are ignored; a disclosure may
//! not overwrite an existing claim. A payload with `cnf` requires a key binding JWT.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

use super::Backend;
use super::cose::{Algorithm, KeySet, PublicKey};
use super::jws::{
    self, ClaimError, JwsError, MAX_PAYLOAD, Origin, verify_compact, verify_with_key,
};
use crate::json::{self, Json, JsonError, b64url_decode, b64url_encode};
use crate::model::TrustedTime;

/// What the verifier expects of a presentation.
#[derive(Clone, Copy, Debug)]
pub struct Rules<'a> {
    /// Expected issuer-signed JWT `typ`.
    pub typ: &'a str,
    /// Expected key binding `aud`.
    pub audience: &'a str,
    /// Expected key binding `nonce`.
    pub nonce: &'a str,
    /// Verifier time.
    pub now: TrustedTime,
    /// Skew for the key binding `iat`, in milliseconds.
    pub skew_ms: u64,
}

/// A verified presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Issuer-signed JWT.
    pub issuer: jws::Verified,
    /// Claims with the presented disclosures applied, without `_sd` and `_sd_alg`.
    pub claims: Json,
    /// Whether a key binding JWT was verified.
    pub holder_bound: bool,
}

/// Why a presentation is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SdJwtError {
    /// Not `<jwt>~<disclosure>~…~[<kb-jwt>]`.
    #[error("not an SD-JWT presentation")]
    Format,
    /// Issuer JWT or key binding JWT rejected.
    #[error("jws: {0}")]
    Jws(#[from] JwsError),
    /// Payload or a disclosure is not strict I-JSON.
    #[error("json: {0}")]
    Json(#[from] JsonError),
    /// `_sd_alg` other than `sha-256`.
    #[error("hash algorithm not allowed")]
    HashAlgorithm,
    /// Malformed disclosure or `_sd` structure.
    #[error("malformed disclosure")]
    Disclosure,
    /// A disclosure is presented twice or referenced twice.
    #[error("duplicate disclosure")]
    Duplicate,
    /// A presented disclosure is not referenced by the payload.
    #[error("unreferenced disclosure")]
    Unreferenced,
    /// A disclosure would overwrite an existing claim.
    #[error("claim name collision")]
    Collision,
    /// Key binding required but absent, or present without `cnf`.
    #[error("key binding mismatch")]
    KeyBinding,
    /// `cnf.jwk` is not an accepted key.
    #[error("bad confirmation key")]
    ConfirmationKey,
    /// Key binding claims wrong.
    #[error("key binding claims: {0}")]
    Claims(#[from] ClaimError),
}

const KB_TYP: &str = "kb+jwt";

fn digest_of(disclosure: &str) -> String {
    b64url_encode(&Sha256::digest(disclosure.as_bytes()))
}

enum Disclosed {
    Property(String, Json),
    Element(Json),
}

fn parse_disclosure(encoded: &str) -> Result<Disclosed, SdJwtError> {
    let raw = b64url_decode(encoded).map_err(|_| SdJwtError::Disclosure)?;
    let Json::Array(items) = json::parse(&raw, MAX_PAYLOAD)? else {
        return Err(SdJwtError::Disclosure);
    };
    match items.as_slice() {
        [Json::Str(_), Json::Str(name), value] => {
            if name == "_sd" || name == "..." {
                return Err(SdJwtError::Disclosure);
            }
            Ok(Disclosed::Property(name.clone(), value.clone()))
        }
        [Json::Str(_), value] => Ok(Disclosed::Element(value.clone())),
        _ => Err(SdJwtError::Disclosure),
    }
}

struct Pool {
    by_digest: BTreeMap<String, Disclosed>,
    used: BTreeSet<String>,
}

impl Pool {
    fn take(&mut self, digest: &str) -> Result<Option<Disclosed>, SdJwtError> {
        if !self.used.insert(String::from(digest)) {
            return Err(SdJwtError::Duplicate);
        }
        Ok(self.by_digest.remove(digest))
    }

    fn resolve(&mut self, value: Json, depth: usize) -> Result<Json, SdJwtError> {
        let next = depth
            .checked_add(1)
            .filter(|d| *d <= json::MAX_DEPTH)
            .ok_or(SdJwtError::Json(JsonError::Depth))?;
        match value {
            Json::Object(members) => {
                let mut out: Vec<(String, Json)> = Vec::new();
                let mut digests = Vec::new();
                for (k, v) in members {
                    if k == "_sd" {
                        let Json::Array(list) = v else {
                            return Err(SdJwtError::Disclosure);
                        };
                        for d in list {
                            let Json::Str(d) = d else {
                                return Err(SdJwtError::Disclosure);
                            };
                            digests.push(d);
                        }
                    } else if k == "..." {
                        return Err(SdJwtError::Disclosure);
                    } else {
                        out.push((k, self.resolve(v, next)?));
                    }
                }
                for d in digests {
                    match self.take(&d)? {
                        None => {}
                        Some(Disclosed::Property(name, v)) => {
                            if out.iter().any(|(k, _)| *k == name) {
                                return Err(SdJwtError::Collision);
                            }
                            let resolved = self.resolve(v, next)?;
                            out.push((name, resolved));
                        }
                        Some(Disclosed::Element(_)) => return Err(SdJwtError::Disclosure),
                    }
                }
                Ok(Json::Object(out))
            }
            Json::Array(items) => {
                let mut out = Vec::new();
                for item in items {
                    if let Json::Object(m) = &item
                        && let [(k, Json::Str(d))] = m.as_slice()
                        && k == "..."
                    {
                        match self.take(d)? {
                            None => {}
                            Some(Disclosed::Element(v)) => out.push(self.resolve(v, next)?),
                            Some(Disclosed::Property(..)) => return Err(SdJwtError::Disclosure),
                        }
                        continue;
                    }
                    out.push(self.resolve(item, next)?);
                }
                Ok(Json::Array(out))
            }
            other => Ok(other),
        }
    }
}

fn confirmation_key(claims: &Json) -> Result<Option<PublicKey>, SdJwtError> {
    let Some(cnf) = claims.get("cnf") else {
        return Ok(None);
    };
    let jwk = cnf.get("jwk").ok_or(SdJwtError::ConfirmationKey)?;
    let field = |name: &str| -> Result<Vec<u8>, SdJwtError> {
        let s = jwk
            .get(name)
            .and_then(Json::as_str)
            .ok_or(SdJwtError::ConfirmationKey)?;
        b64url_decode(s).map_err(|_| SdJwtError::ConfirmationKey)
    };
    let kty = jwk.get("kty").and_then(Json::as_str);
    let crv = jwk.get("crv").and_then(Json::as_str);
    let key = match (kty, crv) {
        (Some("OKP"), Some("Ed25519")) => PublicKey::Ed25519(
            <[u8; 32]>::try_from(field("x")?.as_slice())
                .map_err(|_| SdJwtError::ConfirmationKey)?,
        ),
        (Some("EC"), Some("P-256")) => {
            let (x, y) = (field("x")?, field("y")?);
            if x.len() != 32 || y.len() != 32 {
                return Err(SdJwtError::ConfirmationKey);
            }
            PublicKey::P256([&[0x04][..], &x, &y].concat())
        }
        _ => return Err(SdJwtError::ConfirmationKey),
    };
    key.check().map_err(|_| SdJwtError::ConfirmationKey)?;
    Ok(Some(key))
}

fn check_key_binding(
    backend: &impl Backend,
    kb: &str,
    key: &PublicKey,
    allowed: &BTreeSet<Algorithm>,
    sd_hash: &str,
    rules: &Rules<'_>,
) -> Result<(), SdJwtError> {
    let payload = verify_with_key(backend, kb, key, allowed, KB_TYP)?;
    let claims = json::parse(&payload, MAX_PAYLOAD)?;
    if claims.get("aud").and_then(Json::as_str) != Some(rules.audience) {
        return Err(ClaimError::Audience.into());
    }
    if claims.get("nonce").and_then(Json::as_str) != Some(rules.nonce)
        || claims.get("sd_hash").and_then(Json::as_str) != Some(sd_hash)
    {
        return Err(SdJwtError::KeyBinding);
    }
    let iat = claims
        .get("iat")
        .and_then(Json::as_int)
        .ok_or(ClaimError::Time)?;
    let now = i64::try_from(rules.now.checked_div(1000).ok_or(ClaimError::Time)?)
        .map_err(|_| ClaimError::Time)?;
    let skew = i64::try_from(rules.skew_ms.checked_div(1000).ok_or(ClaimError::Time)?)
        .map_err(|_| ClaimError::Time)?;
    let lo = now.checked_sub(skew).ok_or(ClaimError::Time)?;
    let hi = now.checked_add(skew).ok_or(ClaimError::Time)?;
    if iat < lo {
        return Err(ClaimError::Expired.into());
    }
    if iat > hi {
        return Err(ClaimError::NotYetValid.into());
    }
    Ok(())
}

/// Verifies an SD-JWT presentation (RFC 9901, CR-55 m.7).
///
/// # Errors
/// [`SdJwtError`].
pub fn verify(
    backend: &impl Backend,
    presentation: &str,
    keys: &KeySet,
    rules: &Rules<'_>,
    origin: Origin,
) -> Result<Verified, SdJwtError> {
    let (prefix, kb) = presentation.rsplit_once('~').ok_or(SdJwtError::Format)?;
    let mut pieces = prefix.split('~');
    let jwt = pieces.next().ok_or(SdJwtError::Format)?;
    let issuer = verify_compact(backend, jwt, keys, rules.typ, origin)?;
    let mut pool = Pool {
        by_digest: BTreeMap::new(),
        used: BTreeSet::new(),
    };
    for d in pieces {
        if pool
            .by_digest
            .insert(digest_of(d), parse_disclosure(d)?)
            .is_some()
        {
            return Err(SdJwtError::Duplicate);
        }
    }
    let payload = json::parse(&issuer.payload, MAX_PAYLOAD)?;
    let Json::Object(top) = payload else {
        return Err(SdJwtError::Disclosure);
    };
    let mut members = Vec::new();
    for (k, v) in top {
        if k == "_sd_alg" {
            if v.as_str() != Some("sha-256") {
                return Err(SdJwtError::HashAlgorithm);
            }
        } else {
            members.push((k, v));
        }
    }
    let claims = pool.resolve(Json::Object(members), 0)?;
    if !pool.by_digest.is_empty() {
        return Err(SdJwtError::Unreferenced);
    }
    let holder_bound = match (confirmation_key(&claims)?, kb.is_empty()) {
        (None, true) => false,
        (Some(key), false) => {
            let sd_hash = b64url_encode(&Sha256::digest(
                presentation
                    .get(..prefix.len().checked_add(1).ok_or(SdJwtError::Format)?)
                    .ok_or(SdJwtError::Format)?,
            ));
            check_key_binding(backend, kb, &key, &keys.allowed, &sd_hash, rules)?;
            true
        }
        _ => return Err(SdJwtError::KeyBinding),
    };
    Ok(Verified {
        issuer,
        claims,
        holder_bound,
    })
}

#[cfg(test)]
mod tests;
