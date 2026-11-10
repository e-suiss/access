//! SD-JWT VC presentations (RFC 9901, SD-JWT VC; HAIP; Ek B 4829, 4832): the issuer-signed JWT
//! (`typ` `dc+sd-jwt`, ES256, key named by `x5c` or `kid`), its disclosures and the key binding
//! JWT. Every presented disclosure is referenced exactly once, decoys are ignored, a disclosure
//! never overwrites a claim, and holder binding is always required. The path of every applied
//! disclosure is kept, so DCQL can refuse a disclosure nobody asked for.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::model::TrustedTime;
use access_kernel::verify::Backend;
use access_kernel::verify::cose::{Algorithm, PublicKey};
use access_kernel::verify::jws::{check_times, verify_with_key};

use super::dcql::{Path, Step};

/// Largest presentation.
pub const MAX_PRESENTATION: usize = 96 * 1024;
/// Largest issuer JWT header (an `x5c` chain of a few certificates).
pub const MAX_HEADER: usize = 16 * 1024;
/// Largest payload or disclosure.
pub const MAX_JSON: usize = 64 * 1024;
/// Most disclosures in one presentation.
pub const MAX_DISCLOSURES: usize = 64;
/// Most certificates in `x5c`.
pub const MAX_CHAIN: usize = 4;
/// Deepest nesting the disclosures are resolved through.
pub const MAX_DEPTH: usize = 16;
/// The issuer JWT `typ`.
pub const TYP: &str = "dc+sd-jwt";
/// The key binding JWT `typ`.
pub const KB_TYP: &str = "kb+jwt";

/// Why a presentation is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SdJwtVcError {
    /// Not `<jwt>~<disclosure>~…~<kb-jwt>`.
    #[error("sd-jwt-format")]
    Format,
    /// A header member outside `alg`, `typ`, `kid`, `x5c`, or none of `kid` and `x5c`.
    #[error("sd-jwt-header")]
    Header,
    /// Not ES256 (HAIP).
    #[error("sd-jwt-alg")]
    Algorithm,
    /// Not `dc+sd-jwt`.
    #[error("sd-jwt-typ")]
    Type,
    /// The issuer signature does not verify.
    #[error("sd-jwt-signature")]
    Signature,
    /// The payload or a disclosure is not strict I-JSON, or has the wrong shape.
    #[error("sd-jwt-disclosure")]
    Disclosure,
    /// A disclosure presented or referenced twice.
    #[error("sd-jwt-duplicate")]
    Duplicate,
    /// A presented disclosure the payload does not reference.
    #[error("sd-jwt-unreferenced")]
    Unreferenced,
    /// A disclosure would overwrite a claim.
    #[error("sd-jwt-collision")]
    Collision,
    /// `_sd_alg` other than `sha-256`.
    #[error("sd-jwt-hash-alg")]
    HashAlgorithm,
    /// `iss`, `vct` or a time is missing or out of range.
    #[error("sd-jwt-claims")]
    Claims,
    /// No usable `cnf.jwk`, or the key binding JWT is missing or wrong.
    #[error("sd-jwt-key-binding")]
    KeyBinding,
}

impl SdJwtVcError {
    /// Stable code.
    #[must_use]
    pub fn code(self) -> String {
        self.to_string()
    }
}

/// The issuer JWT header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// `kid`, when the key comes from issuer metadata or a DID document.
    pub kid: Option<String>,
    /// `x5c`, DER, leaf first.
    pub x5c: Vec<Vec<u8>>,
}

/// A presentation read but not verified yet: the caller finds the issuer's key from the header
/// and the payload's `iss`, then calls [`Parsed::verify`].
#[derive(Clone, Debug)]
pub struct Parsed<'a> {
    /// The header.
    pub header: Header,
    /// The issuer-signed payload as signed (disclosures not applied).
    pub payload: Json,
    signing_input: &'a str,
    signature: Vec<u8>,
    disclosures: Vec<&'a str>,
    kb: &'a str,
    prefix: &'a str,
}

/// What the verifier expects of the key binding.
#[derive(Clone, Copy, Debug)]
pub struct Rules<'a> {
    /// The key binding `aud`: the verifier's `client_id`.
    pub audience: &'a str,
    /// The key binding `nonce`: the request's nonce.
    pub nonce: &'a str,
    /// Verifier time, milliseconds.
    pub now: TrustedTime,
    /// Clock skew, milliseconds.
    pub skew_ms: u64,
    /// How old a key binding `iat` may be, milliseconds.
    pub kb_max_age_ms: u64,
}

/// A verified presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presented {
    /// The claims with the presented disclosures applied, without `_sd` and `_sd_alg`.
    pub claims: Json,
    /// The path of every applied disclosure.
    pub disclosed: Vec<Path>,
    /// The holder key from `cnf.jwk`, proven by the key binding JWT.
    pub holder: PublicKey,
}

fn header(bytes: &[u8]) -> Result<Header, SdJwtVcError> {
    let Json::Object(members) = json::parse(bytes, MAX_HEADER).map_err(|_| SdJwtVcError::Header)?
    else {
        return Err(SdJwtVcError::Header);
    };
    let (mut alg, mut typ, mut kid, mut x5c) = (None, None, None, None);
    for (k, v) in &members {
        match (k.as_str(), v) {
            ("alg", Json::Str(s)) => alg = Some(s.as_str()),
            ("typ", Json::Str(s)) => typ = Some(s.as_str()),
            ("kid", Json::Str(s)) if !s.is_empty() && s.len() <= 255 => kid = Some(s.clone()),
            ("x5c", Json::Array(items)) if !items.is_empty() && items.len() <= MAX_CHAIN => {
                let mut chain = Vec::with_capacity(items.len());
                for i in items {
                    let der = i
                        .as_str()
                        .and_then(standard_b64_decode)
                        .ok_or(SdJwtVcError::Header)?;
                    chain.push(der);
                }
                x5c = Some(chain);
            }
            _ => return Err(SdJwtVcError::Header),
        }
    }
    if alg != Some("ES256") {
        return Err(SdJwtVcError::Algorithm);
    }
    if typ != Some(TYP) {
        return Err(SdJwtVcError::Type);
    }
    if kid.is_none() && x5c.is_none() {
        return Err(SdJwtVcError::Header);
    }
    Ok(Header {
        kid,
        x5c: x5c.unwrap_or_default(),
    })
}

/// RFC 4648 §4 base64 with padding, as `x5c` carries certificates (RFC 7515 §4.1.6).
#[must_use]
pub fn standard_b64_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(4) || s.is_empty() {
        return None;
    }
    let trimmed = s.trim_end_matches('=');
    if s.len().saturating_sub(trimmed.len()) > 2 {
        return None;
    }
    let url: String = trimmed
        .chars()
        .map(|c| match c {
            '+' => Some('-'),
            '/' => Some('_'),
            '-' | '_' => None,
            c => Some(c),
        })
        .collect::<Option<String>>()?;
    b64url_decode(&url).ok()
}

/// Splits and reads a presentation.
///
/// # Errors
/// [`SdJwtVcError`].
pub fn parse(presentation: &str) -> Result<Parsed<'_>, SdJwtVcError> {
    if presentation.len() > MAX_PRESENTATION {
        return Err(SdJwtVcError::Format);
    }
    let cut = presentation.rfind('~').ok_or(SdJwtVcError::Format)?;
    let prefix = presentation.get(..=cut).ok_or(SdJwtVcError::Format)?;
    let kb = presentation
        .get(cut.saturating_add(1)..)
        .ok_or(SdJwtVcError::Format)?;
    let body = prefix.strip_suffix('~').ok_or(SdJwtVcError::Format)?;
    let mut pieces = body.split('~');
    let jwt = pieces.next().ok_or(SdJwtVcError::Format)?;
    let disclosures: Vec<&str> = pieces.collect();
    if disclosures.len() > MAX_DISCLOSURES || disclosures.iter().any(|d| d.is_empty()) {
        return Err(SdJwtVcError::Format);
    }
    let mut parts = jwt.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(SdJwtVcError::Format);
    };
    let end = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(SdJwtVcError::Format)?;
    let header = header(&b64url_decode(h).map_err(|_| SdJwtVcError::Format)?)?;
    let payload = json::parse(
        &b64url_decode(p).map_err(|_| SdJwtVcError::Format)?,
        MAX_JSON,
    )
    .map_err(|_| SdJwtVcError::Disclosure)?;
    if !matches!(payload, Json::Object(_)) {
        return Err(SdJwtVcError::Disclosure);
    }
    Ok(Parsed {
        header,
        payload,
        signing_input: jwt.get(..end).ok_or(SdJwtVcError::Format)?,
        signature: b64url_decode(s).map_err(|_| SdJwtVcError::Format)?,
        disclosures,
        kb,
        prefix,
    })
}

enum Disclosure {
    Member(String, Json),
    Element(Json),
}

fn disclosure(d: &str) -> Result<Disclosure, SdJwtVcError> {
    let raw = b64url_decode(d).map_err(|_| SdJwtVcError::Disclosure)?;
    let Json::Array(items) = json::parse(&raw, MAX_JSON).map_err(|_| SdJwtVcError::Disclosure)?
    else {
        return Err(SdJwtVcError::Disclosure);
    };
    let mut it = items.into_iter();
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(Json::Str(_)), Some(Json::Str(name)), Some(value), None) => {
            if name == "_sd" || name == "..." || name == "_sd_alg" {
                return Err(SdJwtVcError::Disclosure);
            }
            Ok(Disclosure::Member(name, value))
        }
        (Some(Json::Str(_)), Some(value), None, None) => Ok(Disclosure::Element(value)),
        _ => Err(SdJwtVcError::Disclosure),
    }
}

/// The digest an issuer puts in `_sd` for a disclosure (RFC 9901 §4.2.3).
#[must_use]
pub fn digest_of(d: &str) -> String {
    b64url_encode(&suiss_crypto::digest::sha256(d.as_bytes()))
}

struct Pool {
    by_digest: BTreeMap<String, Disclosure>,
    seen: BTreeSet<String>,
    disclosed: Vec<Path>,
}

fn with(path: &Path, step: Step) -> Path {
    let mut p = path.clone();
    p.push(step);
    p
}

impl Pool {
    fn take(&mut self, digest: &str) -> Result<Option<Disclosure>, SdJwtVcError> {
        if !self.seen.insert(String::from(digest)) {
            return Err(SdJwtVcError::Duplicate);
        }
        Ok(self.by_digest.remove(digest))
    }

    fn resolve(&mut self, v: Json, path: &Path, depth: usize) -> Result<Json, SdJwtVcError> {
        if depth > MAX_DEPTH {
            return Err(SdJwtVcError::Disclosure);
        }
        let next = depth.saturating_add(1);
        match v {
            Json::Object(members) => {
                let mut out: Vec<(String, Json)> = Vec::with_capacity(members.len());
                let mut digests = Vec::new();
                for (k, v) in members {
                    if k == "_sd" {
                        let Json::Array(items) = v else {
                            return Err(SdJwtVcError::Disclosure);
                        };
                        for i in items {
                            let Json::Str(d) = i else {
                                return Err(SdJwtVcError::Disclosure);
                            };
                            digests.push(d);
                        }
                    } else if k == "..." || k == "_sd_alg" {
                        return Err(SdJwtVcError::Disclosure);
                    } else {
                        let p = with(path, Step::Key(k.clone()));
                        out.push((k, self.resolve(v, &p, next)?));
                    }
                }
                for d in digests {
                    match self.take(&d)? {
                        None => {}
                        Some(Disclosure::Element(_)) => return Err(SdJwtVcError::Disclosure),
                        Some(Disclosure::Member(name, value)) => {
                            if out.iter().any(|(k, _)| *k == name) {
                                return Err(SdJwtVcError::Collision);
                            }
                            let p = with(path, Step::Key(name.clone()));
                            self.disclosed.push(p.clone());
                            let value = self.resolve(value, &p, next)?;
                            out.push((name, value));
                        }
                    }
                }
                Ok(Json::Object(out))
            }
            Json::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let index = u64::try_from(out.len()).map_err(|_| SdJwtVcError::Disclosure)?;
                    let p = with(path, Step::Index(index));
                    if let Json::Object(m) = &item
                        && let [(k, Json::Str(d))] = m.as_slice()
                        && k == "..."
                    {
                        match self.take(d)? {
                            None => {}
                            Some(Disclosure::Member(..)) => {
                                return Err(SdJwtVcError::Disclosure);
                            }
                            Some(Disclosure::Element(value)) => {
                                self.disclosed.push(p.clone());
                                out.push(self.resolve(value, &p, next)?);
                            }
                        }
                    } else {
                        out.push(self.resolve(item, &p, next)?);
                    }
                }
                Ok(Json::Array(out))
            }
            other => Ok(other),
        }
    }
}

/// The holder key in `cnf.jwk`: an EC P-256 key (HAIP).
///
/// # Errors
/// [`SdJwtVcError::KeyBinding`].
pub fn confirmation_key(claims: &Json) -> Result<PublicKey, SdJwtVcError> {
    let jwk = claims
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .ok_or(SdJwtVcError::KeyBinding)?;
    jwk_p256(jwk).ok_or(SdJwtVcError::KeyBinding)
}

/// An EC P-256 JWK's key.
#[must_use]
pub fn jwk_p256(jwk: &Json) -> Option<PublicKey> {
    let field = |name: &str| {
        jwk.get(name)
            .and_then(Json::as_str)
            .and_then(|s| b64url_decode(s).ok())
    };
    if jwk.get("kty").and_then(Json::as_str) != Some("EC")
        || jwk.get("crv").and_then(Json::as_str) != Some("P-256")
        || jwk.get("d").is_some()
    {
        return None;
    }
    let (x, y) = (field("x")?, field("y")?);
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let key = PublicKey::P256([&[0x04][..], &x, &y].concat());
    key.check().ok()?;
    Some(key)
}

fn millis(seconds: i64) -> Option<u64> {
    u64::try_from(seconds).ok()?.checked_mul(1000)
}

impl Parsed<'_> {
    /// The payload's `iss`.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.payload.get("iss").and_then(Json::as_str)
    }

    /// The payload's `vct`.
    #[must_use]
    pub fn vct(&self) -> Option<&str> {
        self.payload.get("vct").and_then(Json::as_str)
    }

    /// Verifies the issuer signature with `issuer`, applies the disclosures and checks the key
    /// binding JWT.
    ///
    /// # Errors
    /// [`SdJwtVcError`].
    pub fn verify(
        &self,
        backend: &impl Backend,
        issuer: &PublicKey,
        rules: &Rules<'_>,
    ) -> Result<Presented, SdJwtVcError> {
        let PublicKey::P256(sec1) = issuer else {
            return Err(SdJwtVcError::Algorithm);
        };
        access_kernel::verify::p256(
            backend,
            sec1,
            self.signing_input.as_bytes(),
            &self.signature,
            false,
        )
        .map_err(|_| SdJwtVcError::Signature)?;
        if self.issuer().is_none_or(str::is_empty) || self.vct().is_none_or(str::is_empty) {
            return Err(SdJwtVcError::Claims);
        }
        check_times(&self.payload, rules.now, rules.skew_ms).map_err(|_| SdJwtVcError::Claims)?;
        let mut pool = Pool {
            by_digest: BTreeMap::new(),
            seen: BTreeSet::new(),
            disclosed: Vec::new(),
        };
        for d in &self.disclosures {
            if pool
                .by_digest
                .insert(digest_of(d), disclosure(d)?)
                .is_some()
            {
                return Err(SdJwtVcError::Duplicate);
            }
        }
        let Json::Object(top) = self.payload.clone() else {
            return Err(SdJwtVcError::Disclosure);
        };
        let mut members = Vec::with_capacity(top.len());
        for (k, v) in top {
            if k == "_sd_alg" {
                if v.as_str() != Some("sha-256") {
                    return Err(SdJwtVcError::HashAlgorithm);
                }
            } else {
                members.push((k, v));
            }
        }
        let claims = pool.resolve(Json::Object(members), &Vec::new(), 0)?;
        if !pool.by_digest.is_empty() {
            return Err(SdJwtVcError::Unreferenced);
        }
        let holder = confirmation_key(&claims)?;
        self.key_binding(backend, &holder, rules)?;
        Ok(Presented {
            claims,
            disclosed: pool.disclosed,
            holder,
        })
    }

    fn key_binding(
        &self,
        backend: &impl Backend,
        holder: &PublicKey,
        rules: &Rules<'_>,
    ) -> Result<(), SdJwtVcError> {
        if self.kb.is_empty() {
            return Err(SdJwtVcError::KeyBinding);
        }
        let allowed = BTreeSet::from([Algorithm::Es256]);
        let payload = verify_with_key(backend, self.kb, holder, &allowed, KB_TYP)
            .map_err(|_| SdJwtVcError::KeyBinding)?;
        let claims = json::parse(&payload, MAX_JSON).map_err(|_| SdJwtVcError::KeyBinding)?;
        let text = |name: &str| claims.get(name).and_then(Json::as_str);
        if text("aud") != Some(rules.audience)
            || text("nonce") != Some(rules.nonce)
            || text("sd_hash") != Some(digest_of(self.prefix).as_str())
        {
            return Err(SdJwtVcError::KeyBinding);
        }
        let iat = claims
            .get("iat")
            .and_then(Json::as_int)
            .and_then(millis)
            .ok_or(SdJwtVcError::KeyBinding)?;
        let latest = rules
            .now
            .checked_add(rules.skew_ms)
            .ok_or(SdJwtVcError::KeyBinding)?;
        let earliest = rules
            .now
            .saturating_sub(rules.kb_max_age_ms.saturating_add(rules.skew_ms));
        if iat > latest || iat < earliest {
            return Err(SdJwtVcError::KeyBinding);
        }
        Ok(())
    }
}

/// The resolved claim at `path`, if every step exists (`Every` is not a lookup step).
#[must_use]
pub fn lookup<'j>(claims: &'j Json, path: &Path) -> Option<&'j Json> {
    let mut at = claims;
    for step in path {
        at = match (step, at) {
            (Step::Key(k), Json::Object(_)) => at.get(k)?,
            (Step::Index(i), Json::Array(items)) => items.get(usize::try_from(*i).ok()?)?,
            _ => return None,
        };
    }
    Some(at)
}
