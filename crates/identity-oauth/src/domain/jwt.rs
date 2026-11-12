//! JWKS reading and the JWT checks of the authorization server: `private_key_jwt` client
//! assertions (RFC 7523 §3, §10.4.5) and the realm's own tokens it reads back
//! (`id_token_hint`, access tokens at `/userinfo`, `/introspect` and `/revoke`).

use std::collections::BTreeSet;

use access_crypto::oauth::{ClientAlg, ClientKey, opaque_digest, verify_client_signature};
use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::verify::cose::{Algorithm, KeySet, PublicKey};
use access_kernel::verify::jws::{MAX_HEADER, MAX_PAYLOAD, MAX_TOKEN};

/// Largest JWKS document read (§14.6).
pub const MAX_JWKS: usize = 64 * 1024;

/// Most keys read from one JWKS.
pub const MAX_KEYS: usize = 32;

/// Client assertion algorithms the realm accepts; RS256 only in the identity plane (CR-2,
/// §11.4.5 (a)). The metadata announces the same list.
pub const ASSERTION_ALGS: [ClientAlg; 2] = [ClientAlg::Es256, ClientAlg::Rs256];

/// Longest lifetime of a client assertion, from now to `exp` (PD).
pub const MAX_ASSERTION_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// Clock skew for JWT time claims (§10.4.5: ±60 s, PD).
pub const SKEW_MS: u64 = 60_000;

/// Longest `jti` accepted.
pub const MAX_JTI: usize = 256;

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Why a JWT or JWKS is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwtError {
    /// Not a compact JWS, or a part is not canonical.
    #[error("format")]
    Format,
    /// The header is outside the profile.
    #[error("header")]
    Header,
    /// The algorithm is not allowed (MD-3, IDI-6).
    #[error("algorithm")]
    Algorithm,
    /// No key fits.
    #[error("key")]
    Key,
    /// The signature does not verify.
    #[error("signature")]
    Signature,
    /// A claim is missing or wrong.
    #[error("claims")]
    Claims,
    /// Expired, not yet valid, or too long-lived.
    #[error("time")]
    Time,
    /// The JWKS is malformed or holds private key material.
    #[error("jwks")]
    Jwks,
}

/// A public key from a JWKS with its `kid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    /// `kid`, when present.
    pub kid: Option<String>,
    /// The key.
    pub key: ClientKey,
}

fn members(v: &Json) -> Option<&[(String, Json)]> {
    match v {
        Json::Object(m) => Some(m),
        _ => None,
    }
}

fn text<'a>(m: &'a [(String, Json)], name: &str) -> Option<&'a str> {
    m.iter()
        .find(|(k, _)| k == name)
        .and_then(|(_, v)| v.as_str())
}

fn bytes(m: &[(String, Json)], name: &str) -> Result<Vec<u8>, JwtError> {
    text(m, name)
        .and_then(|s| b64url_decode(s).ok())
        .ok_or(JwtError::Jwks)
}

fn jwk(m: &[(String, Json)]) -> Result<Jwk, JwtError> {
    if m.iter().any(|(k, _)| PRIVATE_MEMBERS.contains(&k.as_str())) {
        return Err(JwtError::Jwks);
    }
    let key = match (text(m, "kty"), text(m, "crv")) {
        (Some("EC"), Some("P-256")) => {
            let (x, y) = (bytes(m, "x")?, bytes(m, "y")?);
            if x.len() != 32 || y.len() != 32 {
                return Err(JwtError::Jwks);
            }
            let mut sec1 = vec![4];
            sec1.extend(x);
            sec1.extend(y);
            ClientKey::P256(sec1)
        }
        (Some("OKP"), Some("Ed25519")) => {
            ClientKey::Ed25519(bytes(m, "x")?.try_into().map_err(|_| JwtError::Jwks)?)
        }
        (Some("RSA"), None) => ClientKey::Rsa {
            n: bytes(m, "n")?,
            e: bytes(m, "e")?,
        },
        _ => return Err(JwtError::Jwks),
    };
    if text(m, "use").is_some_and(|u| u != "sig") {
        return Err(JwtError::Jwks);
    }
    Ok(Jwk {
        kid: text(m, "kid").map(String::from),
        key,
    })
}

/// The public keys of a JWKS document. Keys of an unknown type are skipped; a document
/// holding private key material is refused whole.
///
/// # Errors
/// [`JwtError::Jwks`].
pub fn parse_jwks(doc: &[u8]) -> Result<Vec<Jwk>, JwtError> {
    let top = json::parse(doc, MAX_JWKS).map_err(|_| JwtError::Jwks)?;
    let Some(Json::Array(keys)) = top.get("keys") else {
        return Err(JwtError::Jwks);
    };
    let mut out = Vec::new();
    for k in keys.iter().take(MAX_KEYS) {
        let m = members(k).ok_or(JwtError::Jwks)?;
        match jwk(m) {
            Ok(j) => out.push(j),
            Err(_) if m.iter().any(|(k, _)| PRIVATE_MEMBERS.contains(&k.as_str())) => {
                return Err(JwtError::Jwks);
            }
            Err(_) => {}
        }
    }
    Ok(out)
}

/// The realm's own keys as a Kernel key set: `kid` is the base64url RFC 7638 thumbprint
/// (CR-24).
///
/// # Errors
/// [`JwtError::Jwks`].
pub fn realm_key_set(doc: &[u8]) -> Result<KeySet, JwtError> {
    let mut set = KeySet::default();
    // CR-41 m.3, OP-159 m.3 (o)
    for (kid, alg, key) in akp_keys(doc)? {
        set.allowed.insert(alg);
        set.insert(kid, key).map_err(|_| JwtError::Jwks)?;
    }
    for j in parse_jwks(doc)? {
        let kid: [u8; 32] = j
            .kid
            .as_deref()
            .and_then(|k| b64url_decode(k).ok())
            .and_then(|k| k.try_into().ok())
            .ok_or(JwtError::Jwks)?;
        let (alg, key) = match j.key {
            ClientKey::P256(sec1) => (Algorithm::Es256, PublicKey::P256(sec1)),
            ClientKey::Ed25519(pk) => (Algorithm::Ed25519, PublicKey::Ed25519(pk)),
            ClientKey::Rsa { .. } => continue,
        };
        set.allowed.insert(alg);
        set.insert(kid, key).map_err(|_| JwtError::Jwks)?;
    }
    Ok(set)
}

/// The `AKP` keys of a realm JWKS with their mandatory `alg` and exact length (RFC 9964, CR-41
/// m.3); any other key is left to [`parse_jwks`].
fn akp_keys(doc: &[u8]) -> Result<Vec<([u8; 32], Algorithm, PublicKey)>, JwtError> {
    let top = json::parse(doc, MAX_JWKS).map_err(|_| JwtError::Jwks)?;
    let Some(Json::Array(keys)) = top.get("keys") else {
        return Err(JwtError::Jwks);
    };
    let mut out = Vec::new();
    for k in keys.iter().take(MAX_KEYS) {
        let m = members(k).ok_or(JwtError::Jwks)?;
        if text(m, "kty") != Some("AKP") {
            continue;
        }
        if m.iter().any(|(k, _)| k == "priv") {
            return Err(JwtError::Jwks);
        }
        let pq = text(m, "alg")
            .and_then(|a| {
                access_kernel::verify::pq::PqAlgorithm::ALL
                    .into_iter()
                    .find(|p| p.jose() == a)
            })
            .ok_or(JwtError::Jwks)?;
        let public = bytes(m, "pub")?;
        if public.len() != pq.public_key_len() {
            return Err(JwtError::Jwks);
        }
        let kid: [u8; 32] = text(m, "kid")
            .and_then(|k| b64url_decode(k).ok())
            .and_then(|k| k.try_into().ok())
            .ok_or(JwtError::Jwks)?;
        out.push((kid, pq.algorithm(), PublicKey::MlDsa(pq.algorithm(), public)));
    }
    Ok(out)
}

struct Parts<'a> {
    header: Json,
    input: &'a str,
    payload: Json,
    signature: Vec<u8>,
}

fn split(token: &str) -> Result<Parts<'_>, JwtError> {
    if token.len() > MAX_TOKEN {
        return Err(JwtError::Format);
    }
    let mut it = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(JwtError::Format);
    };
    let end = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(JwtError::Format)?;
    let decode = |part: &str| b64url_decode(part).map_err(|_| JwtError::Format);
    Ok(Parts {
        header: json::parse(&decode(h)?, MAX_HEADER).map_err(|_| JwtError::Header)?,
        input: token.get(..end).ok_or(JwtError::Format)?,
        payload: json::parse(&decode(p)?, MAX_PAYLOAD).map_err(|_| JwtError::Claims)?,
        signature: decode(s)?,
    })
}

fn int(claims: &Json, name: &str) -> Result<Option<u64>, JwtError> {
    claims
        .get(name)
        .map(|v| {
            v.as_int()
                .and_then(|s| u64::try_from(s).ok())
                .and_then(|s| s.checked_mul(1000))
                .ok_or(JwtError::Time)
        })
        .transpose()
}

/// Whether `key` is of the type `alg` verifies with (RFC 7517 §4.4): a key of another type is
/// never a candidate, so a JWKS holding an EC and an RSA key selects one.
const fn fits(alg: ClientAlg, key: &ClientKey) -> bool {
    matches!(
        (alg, key),
        (ClientAlg::Es256, ClientKey::P256(_))
            | (ClientAlg::Ed25519, ClientKey::Ed25519(_))
            | (ClientAlg::Rs256, ClientKey::Rsa { .. })
    )
}

/// What a verified client assertion yields for the replay cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    /// The client it authenticates.
    pub client_id: String,
    /// The replay key: a digest of the client and `jti` (OP-146 m.5 (f)).
    pub replay_key: [u8; 32],
    /// `exp`, Unix milliseconds; the replay entry lives on its day.
    pub exp_ms: u64,
}

/// The client a `private_key_jwt` assertion names in `sub`, read before its keys are fetched;
/// the signature is checked later by [`verify_assertion`].
///
/// # Errors
/// [`JwtError`].
pub fn assertion_subject(token: &str) -> Result<String, JwtError> {
    let parts = split(token)?;
    parts
        .payload
        .get("sub")
        .and_then(Json::as_str)
        .map(String::from)
        .ok_or(JwtError::Claims)
}

/// The single audience a client assertion names, read before its keys are fetched: a caller
/// outside a realm's own endpoints finds the realm by it (OP-149 m.4). The signature and the
/// audience are checked later by [`verify_assertion`].
///
/// # Errors
/// [`JwtError`].
pub fn assertion_audience(token: &str) -> Result<String, JwtError> {
    let parts = split(token)?;
    match parts.payload.get("aud") {
        Some(Json::Str(a)) => Some(a.clone()),
        Some(Json::Array(a)) if a.len() == 1 => a.first().and_then(Json::as_str).map(String::from),
        _ => None,
    }
    .ok_or(JwtError::Claims)
}

/// The audiences a client assertion may name: the issuer or the token endpoint (§10.4.5).
#[derive(Clone, Copy, Debug)]
pub struct AssertionRules<'a> {
    /// The client that is authenticating.
    pub client_id: &'a str,
    /// The realm issuer.
    pub issuer: &'a str,
    /// The endpoint that received it.
    pub endpoint: &'a str,
    /// Now, Unix milliseconds.
    pub now_ms: u64,
    /// Whether the client opted in to RS256 (§11.4.5 (a), OP-154 m.3 (l)); ES256 otherwise.
    pub rs256: bool,
}

/// RFC 7523 §3, §10.4.5: verifies a client assertion against the client's keys. `alg` comes
/// from the allowlist, never from the header alone (IDI-6); `iss` = `sub` = `client_id`; `aud`
/// is a single value, the issuer or the endpoint; `exp` is required and at most
/// [`MAX_ASSERTION_LIFETIME_MS`] ahead; `jti` is required.
///
/// # Errors
/// [`JwtError`].
pub fn verify_assertion(
    token: &str,
    keys: &[Jwk],
    rules: &AssertionRules<'_>,
) -> Result<Assertion, JwtError> {
    let parts = split(token)?;
    let header = members(&parts.header).ok_or(JwtError::Header)?;
    if header
        .iter()
        .any(|(k, v)| !matches!(k.as_str(), "alg" | "kid" | "typ") || v.as_str().is_none())
    {
        return Err(JwtError::Header);
    }
    let alg = text(header, "alg")
        .and_then(ClientAlg::from_name)
        .filter(|a| ASSERTION_ALGS.contains(a) && (*a != ClientAlg::Rs256 || rules.rs256))
        .ok_or(JwtError::Algorithm)?;
    if text(header, "typ").is_some_and(|t| t != "JWT" && t != "client-authentication+jwt") {
        return Err(JwtError::Header);
    }
    let kid = text(header, "kid");
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|k| kid.is_none_or(|id| k.kid.as_deref() == Some(id)) && fits(alg, &k.key))
        .collect();
    let [key] = candidates.as_slice() else {
        return Err(JwtError::Key);
    };
    verify_client_signature(alg, &key.key, parts.input.as_bytes(), &parts.signature)
        .map_err(|_| JwtError::Signature)?;
    assertion_claims(&parts.payload, rules)
}

/// A client-signed JWT whose signature verified: its claims and `typ`.
pub(crate) struct ClientSigned {
    pub(crate) claims: Json,
    pub(crate) typ: Option<String>,
}

/// Verifies a client-signed JWT against the client's keys with an algorithm from the client's
/// allowlist, never from the header alone (IDI-6, MD-3): ES256, and RS256 only when `rs256`.
/// The header holds only `alg`, `kid` and `typ`.
pub(crate) fn verify_client_jws(
    token: &str,
    keys: &[Jwk],
    rs256: bool,
) -> Result<ClientSigned, JwtError> {
    let parts = split(token)?;
    let header = members(&parts.header).ok_or(JwtError::Header)?;
    let profiled = header
        .iter()
        .all(|(k, v)| matches!(k.as_str(), "alg" | "kid" | "typ") && v.as_str().is_some());
    if !profiled {
        return Err(JwtError::Header);
    }
    let alg = text(header, "alg")
        .and_then(ClientAlg::from_name)
        .filter(|a| ASSERTION_ALGS.contains(a) && (*a != ClientAlg::Rs256 || rs256))
        .ok_or(JwtError::Algorithm)?;
    let kid = text(header, "kid");
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|k| kid.is_none_or(|id| k.kid.as_deref() == Some(id)) && fits(alg, &k.key))
        .collect();
    let [key] = candidates.as_slice() else {
        return Err(JwtError::Key);
    };
    verify_client_signature(alg, &key.key, parts.input.as_bytes(), &parts.signature)
        .map_err(|_| JwtError::Signature)?;
    Ok(ClientSigned {
        typ: text(header, "typ").map(String::from),
        claims: parts.payload,
    })
}

/// The `kid` an assertion's header names, read before its signature is checked.
#[must_use]
pub fn assertion_kid(token: &str) -> Option<String> {
    let parts = split(token).ok()?;
    parts
        .header
        .get("kid")
        .and_then(Json::as_str)
        .map(String::from)
}

/// Whether `keys` hold no key with the `kid` the assertion names: the authorization server then
/// fetches the client's JWKS again, at most once a minute (§10.4.5, Ek B 5098).
#[must_use]
pub fn kid_unknown(token: &str, keys: &[Jwk]) -> bool {
    assertion_kid(token).is_some_and(|kid| !keys.iter().any(|k| k.kid.as_deref() == Some(&kid)))
}

/// OP-148 m.16 (l), CR-3: verifies a `client_secret_jwt` assertion with the secret shared with
/// that one client. The header holds `alg` (HS256) and optionally `typ` and `kid`; the claims
/// follow [`verify_assertion`].
///
/// # Errors
/// [`JwtError`].
pub fn verify_secret_assertion(
    token: &str,
    secret: &[u8],
    rules: &AssertionRules<'_>,
) -> Result<Assertion, JwtError> {
    let parts = split(token)?;
    let header = members(&parts.header).ok_or(JwtError::Header)?;
    let profiled = header
        .iter()
        .all(|(k, v)| matches!(k.as_str(), "alg" | "kid" | "typ") && v.as_str().is_some());
    if !profiled {
        return Err(JwtError::Header);
    }
    if text(header, "alg") != Some(access_crypto::client_secret_jwt::ALG) {
        return Err(JwtError::Algorithm);
    }
    if text(header, "typ").is_some_and(|t| t != "JWT" && t != "client-authentication+jwt") {
        return Err(JwtError::Header);
    }
    access_crypto::client_secret_jwt::verify(secret, parts.input.as_bytes(), &parts.signature)
        .map_err(|_| JwtError::Signature)?;
    assertion_claims(&parts.payload, rules)
}

fn assertion_claims(c: &Json, rules: &AssertionRules<'_>) -> Result<Assertion, JwtError> {
    let claim = |name: &str| c.get(name).and_then(Json::as_str);
    if claim("iss") != Some(rules.client_id) || claim("sub") != Some(rules.client_id) {
        return Err(JwtError::Claims);
    }
    let aud = match c.get("aud") {
        Some(Json::Str(a)) => Some(a.as_str()),
        Some(Json::Array(a)) if a.len() == 1 => a.first().and_then(Json::as_str),
        _ => None,
    };
    if !aud.is_some_and(|a| a == rules.issuer || a == rules.endpoint) {
        return Err(JwtError::Claims);
    }
    let jti = claim("jti")
        .filter(|j| !j.is_empty() && j.len() <= MAX_JTI)
        .ok_or(JwtError::Claims)?;
    let exp = int(c, "exp")?.ok_or(JwtError::Time)?;
    let latest = rules.now_ms.saturating_add(SKEW_MS);
    if exp.saturating_add(SKEW_MS) < rules.now_ms
        || exp > rules.now_ms.saturating_add(MAX_ASSERTION_LIFETIME_MS)
        || int(c, "iat")?.is_some_and(|t| t > latest)
        || int(c, "nbf")?.is_some_and(|t| t > latest)
    {
        return Err(JwtError::Time);
    }
    let mut key_input = rules.client_id.as_bytes().to_vec();
    key_input.push(0);
    key_input.extend_from_slice(jti.as_bytes());
    Ok(Assertion {
        client_id: String::from(rules.client_id),
        replay_key: opaque_digest("access/client-assertion/v1", &key_input),
        exp_ms: exp,
    })
}

/// The algorithms the realm's own tokens are accepted with.
#[must_use]
pub fn realm_algorithms() -> BTreeSet<Algorithm> {
    [Algorithm::Es256, Algorithm::Ed25519].into_iter().collect()
}

/// The resource server's own check of a realm access token (`at+jwt`) with the realm JWKS it
/// already holds: signature, `iss`, its audience and times with [`SKEW_MS`]. No database,
/// introspection or network is asked, so it answers the same while the identity database is
/// down; the bound is the token's declared lifetime, never a window (§13.11 EP-4, EP-6, U39,
/// HL-22, OP-45 rule 1). `None` is DENY.
#[must_use]
pub fn verify_local(
    jwks: &[u8],
    token: &str,
    issuer: &str,
    audience: &str,
    now_ms: u64,
) -> Option<Json> {
    use access_kernel::verify::jws::{ClaimRules, Origin, check_claims, verify_compact};
    let keys = realm_key_set(jwks).ok()?;
    let v = verify_compact(
        &access_crypto::AwsLcBackend,
        token,
        &keys,
        crate::domain::tokens::ACCESS_TYP,
        Origin::Native,
    )
    .ok()?;
    check_claims(
        &v.payload,
        &ClaimRules {
            issuer,
            audience,
            now: now_ms,
            skew_ms: SKEW_MS,
        },
    )
    .ok()
}

#[cfg(test)]
mod tests;
