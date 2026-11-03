//! DPoP proof profile (RFC 9449 §4.3; §10.4.3, §12.2.1, IDP-11, TN-28, MD-18): the stateless
//! steps of the 12-step validation. The server nonce and the `jti` replay check need keyed and
//! stored state, so they are the caller's ([`Step::Nonce`], [`Step::Jti`]).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use sha2::{Digest as _, Sha256};

use super::cose::{Algorithm, PublicKey};
use super::key_scope::thumbprint;
use super::{Backend, SignatureError, ed25519, p256};
use crate::json::{self, Json, JsonError, b64url_decode, b64url_encode};
use crate::model::TrustedTime;

/// `typ` of a DPoP proof (RFC 9449 §4.2).
pub const DPOP_TYP: &str = "dpop+jwt";

/// Largest DPoP proof accepted, checked before decoding.
pub const MAX_PROOF: usize = 8 * 1024;

/// Largest proof header accepted.
pub const MAX_HEADER: usize = 2048;

/// Largest proof payload accepted.
pub const MAX_PAYLOAD: usize = 4096;

/// Longest `jti` accepted; the replay key is fixed-length whatever its size (TN-30).
pub const MAX_JTI: usize = 256;

/// Longest `nonce` accepted.
pub const MAX_NONCE: usize = 256;

/// Longest `htu` or request URI accepted.
pub const MAX_URI: usize = 2048;

/// The 12 steps of the DPoP profile (§10.4.3 m.1, §12.2.1), in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// One `DPoP` header holding a well-formed JWT with `jti`, `htm`, `htu` and `iat`.
    Shape,
    /// `typ` is `dpop+jwt`.
    Type,
    /// `alg` is asymmetric, fully specified and in the metadata allowlist (MD-3).
    Algorithm,
    /// `jwk` is a public key of the algorithm's type, without private members.
    Jwk,
    /// The signature verifies with `jwk`.
    Signature,
    /// `htm` is the request method.
    Method,
    /// `htu` is the request URI after RFC 3986 normalisation, without query and fragment.
    Uri,
    /// `iat` is within the acceptance window.
    Iat,
    /// `jti` has not been seen within the replay window (the caller's, TN-30).
    Jti,
    /// `nonce` is a current server nonce (the caller's, TN-29).
    Nonce,
    /// `ath` is the hash of the presented access token (resource server).
    Ath,
    /// The key is the one the token or grant is bound to (`cnf.jkt`, `dpop_jkt`).
    Jkt,
}

/// Why a DPoP proof is rejected by the stateless steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DpopError {
    /// Not three dot-separated parts, or too large.
    #[error("not a compact JWS")]
    Format,
    /// A part is not canonical base64url.
    #[error("bad base64url")]
    Base64,
    /// Header or payload is not strict I-JSON.
    #[error("json: {0}")]
    Json(#[from] JsonError),
    /// A header parameter outside `typ`, `alg`, `jwk`, or one of them missing.
    #[error("header not in profile")]
    Header,
    /// A required claim is missing, of the wrong type or too long.
    #[error("claim {0}")]
    Claim(&'static str),
    /// `typ` is not `dpop+jwt`.
    #[error("unexpected typ")]
    Type,
    /// `alg` is not allowed, not fully specified (`EdDSA`), or not the key's type.
    #[error("algorithm not allowed")]
    Algorithm,
    /// `jwk` is not a supported, canonical public key.
    #[error("jwk")]
    Jwk,
    /// `jwk` carries private key members.
    #[error("jwk is private")]
    PrivateKey,
    /// The signature does not verify.
    #[error("signature: {0}")]
    Signature(#[from] SignatureError),
    /// `htm` is not the request method.
    #[error("htm")]
    Method,
    /// `htu` is not a valid HTTP URI, or not the request URI.
    #[error("htu")]
    Uri,
    /// The request URI given by the caller is not a valid HTTP URI.
    #[error("request uri")]
    Target,
    /// `iat` is outside the acceptance window.
    #[error("iat")]
    Iat,
    /// `ath` is missing or not the hash of the access token.
    #[error("ath")]
    Ath,
    /// The key is not the bound one.
    #[error("jkt")]
    Jkt,
}

impl DpopError {
    /// The profile step that failed.
    #[must_use]
    pub const fn step(self) -> Step {
        match self {
            Self::Format | Self::Base64 | Self::Json(_) | Self::Header | Self::Claim(_) => {
                Step::Shape
            }
            Self::Type => Step::Type,
            Self::Algorithm => Step::Algorithm,
            Self::Jwk | Self::PrivateKey => Step::Jwk,
            Self::Signature(_) => Step::Signature,
            Self::Method => Step::Method,
            Self::Uri | Self::Target => Step::Uri,
            Self::Iat => Step::Iat,
            Self::Ath => Step::Ath,
            Self::Jkt => Step::Jkt,
        }
    }

    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Format => "dpop-format",
            Self::Base64 => "dpop-base64",
            Self::Json(_) => "dpop-json",
            Self::Header => "dpop-header",
            Self::Claim(_) => "dpop-claim",
            Self::Type => "dpop-typ",
            Self::Algorithm => "dpop-alg",
            Self::Jwk => "dpop-jwk",
            Self::PrivateKey => "dpop-jwk-private",
            Self::Signature(_) => "dpop-signature",
            Self::Method => "dpop-htm",
            Self::Uri => "dpop-htu",
            Self::Target => "dpop-target",
            Self::Iat => "dpop-iat",
            Self::Ath => "dpop-ath",
            Self::Jkt => "dpop-jkt",
        }
    }
}

/// What the verifier expects of a proof.
#[derive(Clone, Copy, Debug)]
pub struct ProofRules<'a> {
    /// The request method, compared case-sensitively (RFC 9110 §9.1).
    pub method: &'a str,
    /// The request's target URI as the server sees it; normalised here.
    pub uri: &'a str,
    /// Algorithms the client or resource metadata allows (MD-3); never from the proof.
    pub allowed: &'a BTreeSet<Algorithm>,
    /// Verifier time.
    pub now: TrustedTime,
    /// How long after `iat` a proof is accepted, in milliseconds.
    pub lifetime_ms: u64,
    /// Clock skew tolerance in milliseconds.
    pub skew_ms: u64,
    /// The access token presented with the proof; requires a matching `ath` (resource server).
    pub access_token: Option<&'a str>,
    /// The thumbprint the token or grant is bound to (`cnf.jkt`, `dpop_jkt`, refresh binding).
    pub bound_jkt: Option<&'a [u8; 32]>,
}

/// A proof that passed the stateless steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Algorithm.
    pub algorithm: Algorithm,
    /// The proof key.
    pub key: PublicKey,
    /// Its RFC 7638 thumbprint, the value of `cnf.jkt`.
    pub jkt: [u8; 32],
    /// `jti`.
    pub jti: String,
    /// `htm`.
    pub htm: String,
    /// `htu` after normalisation.
    pub htu: String,
    /// `iat` in milliseconds.
    pub iat: TrustedTime,
    /// `nonce`, when present.
    pub nonce: Option<String>,
}

/// The `ath` value of an access token: base64url SHA-256 of its ASCII form (RFC 9449 §4.2).
#[must_use]
pub fn ath(access_token: &str) -> String {
    b64url_encode(&Sha256::digest(access_token.as_bytes()))
}

/// The base64url form of a thumbprint, as in `cnf.jkt` and `dpop_jkt`.
#[must_use]
pub fn jkt_text(jkt: &[u8; 32]) -> String {
    b64url_encode(jkt)
}

/// A `cnf.jkt` or `dpop_jkt` value back to its thumbprint.
///
/// # Errors
/// [`DpopError::Jkt`] when it is not canonical base64url of 32 bytes.
pub fn parse_jkt(text: &str) -> Result<[u8; 32], DpopError> {
    let raw = b64url_decode(text).map_err(|_| DpopError::Jkt)?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| DpopError::Jkt)
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" { 443 } else { 80 }
}

const fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

const fn path_char(b: u8) -> bool {
    unreserved(b)
        || matches!(
            b,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
        )
}

const fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

fn percent_normalise(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hi = hex(*bytes.get(i.checked_add(1)?)?)?;
            let lo = hex(*bytes.get(i.checked_add(2)?)?)?;
            let v = hi.checked_mul(16)?.checked_add(lo)?;
            if unreserved(v) {
                out.push(char::from(v));
            } else {
                out.push('%');
                out.push(char::from(
                    b"0123456789ABCDEF".get(usize::from(hi)).copied()?,
                ));
                out.push(char::from(
                    b"0123456789ABCDEF".get(usize::from(lo)).copied()?,
                ));
            }
            i = i.checked_add(3)?;
        } else if path_char(b) {
            out.push(char::from(b));
            i = i.checked_add(1)?;
        } else {
            return None;
        }
    }
    Some(out)
}

fn remove_dot_segments(path: &str) -> String {
    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();
    let count = segments.len();
    let mut out: Vec<&str> = Vec::new();
    for (i, segment) in segments.iter().enumerate() {
        let last = i.checked_add(1) == Some(count);
        match *segment {
            "." => {}
            ".." => {
                out.pop();
            }
            s => {
                out.push(s);
                continue;
            }
        }
        if last {
            out.push("");
        }
    }
    let mut result = String::new();
    for segment in out {
        result.push('/');
        result.push_str(segment);
    }
    if result.is_empty() {
        result.push('/');
    }
    result
}

fn host_ok(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[') {
        return inner.strip_suffix(']').is_some_and(|ip| {
            !ip.is_empty()
                && ip
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        });
    }
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// The RFC 3986 normal form of an HTTP(S) URI without query and fragment, as `htu` is
/// compared (§6.2.2 syntax-based and §6.2.3 scheme-based normalisation; TN-28): lower-case
/// scheme and host, the default port dropped, percent-encodings of unreserved characters
/// decoded and the others upper-cased, dot segments removed, and an empty path made `/`.
/// User information is rejected; `None` when `uri` is not an absolute `http` or `https` URI.
#[must_use]
pub fn normalize_htu(uri: &str) -> Option<String> {
    if uri.len() > MAX_URI || !uri.is_ascii() {
        return None;
    }
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rfind(':') {
        Some(i) if !authority.get(i..).is_some_and(|tail| tail.contains(']')) => {
            let (h, p) = authority.split_at(i);
            (h, p.get(1..).unwrap_or_default())
        }
        _ => (authority, ""),
    };
    let host = host.to_ascii_lowercase();
    if !host_ok(&host) {
        return None;
    }
    let port = if port.is_empty() {
        None
    } else if port.bytes().all(|b| b.is_ascii_digit()) && port.len() <= 5 {
        let n: u32 = port.parse().ok()?;
        let n = u16::try_from(n).ok()?;
        (n != default_port(&scheme)).then_some(n)
    } else {
        return None;
    };
    let path = remove_dot_segments(&percent_normalise(path)?);
    let mut out = scheme;
    out.push_str("://");
    out.push_str(&host);
    if let Some(port) = port {
        out.push(':');
        let _ = write!(out, "{port}");
    }
    out.push_str(&path);
    Some(out)
}

struct Header {
    alg: String,
    typ: String,
    jwk: Json,
}

fn header(bytes: &[u8]) -> Result<Header, DpopError> {
    let Json::Object(members) = json::parse(bytes, MAX_HEADER)? else {
        return Err(DpopError::Header);
    };
    if members
        .iter()
        .any(|(k, _)| !matches!(k.as_str(), "alg" | "typ" | "jwk"))
    {
        return Err(DpopError::Header);
    }
    let mut alg = None;
    let mut typ = None;
    let mut jwk = None;
    for (k, v) in members {
        match (k.as_str(), v) {
            ("alg", Json::Str(s)) => alg = Some(s),
            ("typ", Json::Str(s)) => typ = Some(s),
            ("jwk", v @ Json::Object(_)) => jwk = Some(v),
            _ => return Err(DpopError::Header),
        }
    }
    match (alg, typ, jwk) {
        (Some(alg), Some(typ), Some(jwk)) => Ok(Header { alg, typ, jwk }),
        _ => Err(DpopError::Header),
    }
}

const PRIVATE_MEMBERS: [&str; 9] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"];

fn coordinate(jwk: &Json, name: &str) -> Result<[u8; 32], DpopError> {
    let raw = jwk
        .get(name)
        .and_then(Json::as_str)
        .ok_or(DpopError::Jwk)
        .and_then(|s| b64url_decode(s).map_err(|_| DpopError::Jwk))?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| DpopError::Jwk)
}

fn public_key(jwk: &Json) -> Result<PublicKey, DpopError> {
    let Json::Object(members) = jwk else {
        return Err(DpopError::Jwk);
    };
    if members
        .iter()
        .any(|(k, _)| PRIVATE_MEMBERS.contains(&k.as_str()))
    {
        return Err(DpopError::PrivateKey);
    }
    for (k, v) in members {
        let ok = match k.as_str() {
            "kty" | "crv" | "x" | "y" | "alg" | "kid" | "use" => matches!(v, Json::Str(_)),
            "key_ops" => matches!(v, Json::Array(_)),
            "ext" => matches!(v, Json::Bool(_)),
            _ => false,
        };
        if !ok {
            return Err(DpopError::Jwk);
        }
    }
    let text = |name: &str| jwk.get(name).and_then(Json::as_str);
    let key = match (text("kty"), text("crv")) {
        (Some("EC"), Some("P-256")) => {
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(4);
            sec1.extend_from_slice(&coordinate(jwk, "x")?);
            sec1.extend_from_slice(&coordinate(jwk, "y")?);
            PublicKey::P256(sec1)
        }
        (Some("OKP"), Some("Ed25519")) if jwk.get("y").is_none() => {
            PublicKey::Ed25519(coordinate(jwk, "x")?)
        }
        _ => return Err(DpopError::Jwk),
    };
    key.check().map_err(|_| DpopError::Jwk)?;
    Ok(key)
}

fn algorithm(name: &str) -> Option<Algorithm> {
    match name {
        "ES256" => Some(Algorithm::Es256),
        "Ed25519" => Some(Algorithm::Ed25519),
        _ => None,
    }
}

fn claim<'a>(claims: &'a Json, name: &'static str, max: usize) -> Result<&'a str, DpopError> {
    claims
        .get(name)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max)
        .ok_or(DpopError::Claim(name))
}

fn iat_ms(claims: &Json) -> Result<TrustedTime, DpopError> {
    let seconds = claims
        .get("iat")
        .and_then(Json::as_int)
        .ok_or(DpopError::Claim("iat"))?;
    u64::try_from(seconds)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .ok_or(DpopError::Iat)
}

fn iat_window(iat: TrustedTime, rules: &ProofRules<'_>) -> Result<(), DpopError> {
    let latest = rules.now.checked_add(rules.skew_ms).ok_or(DpopError::Iat)?;
    let until = iat
        .checked_add(rules.lifetime_ms)
        .and_then(|t| t.checked_add(rules.skew_ms))
        .ok_or(DpopError::Iat)?;
    if iat > latest || rules.now > until {
        return Err(DpopError::Iat);
    }
    Ok(())
}

/// Verifies the stateless steps of a DPoP proof (§10.4.3 m.1; RFC 9449 §4.3 checks 2–12
/// without nonce and replay): shape and required claims, `typ`, `alg` against the allowlist,
/// public `jwk`, signature, `htm`, normalised `htu`, `iat` window, `ath` and the bound key.
/// The caller checks the nonce and records `jti` with [`Proof`] afterwards.
///
/// # Errors
/// [`DpopError`]; [`DpopError::step`] names the failed step.
pub fn verify_proof(
    backend: &impl Backend,
    proof: &str,
    rules: &ProofRules<'_>,
) -> Result<Proof, DpopError> {
    if proof.len() > MAX_PROOF {
        return Err(DpopError::Format);
    }
    let mut parts = proof.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(DpopError::Format);
    };
    let header = header(&b64url_decode(h).map_err(|_| DpopError::Base64)?)?;
    let payload = b64url_decode(p).map_err(|_| DpopError::Base64)?;
    let signature = b64url_decode(s).map_err(|_| DpopError::Base64)?;
    let claims = json::parse(&payload, MAX_PAYLOAD)?;
    if !matches!(claims, Json::Object(_)) {
        return Err(DpopError::Claim("payload"));
    }
    let jti = claim(&claims, "jti", MAX_JTI)?;
    let htm = claim(&claims, "htm", 32)?;
    let htu = claim(&claims, "htu", MAX_URI)?;
    let iat = iat_ms(&claims)?;
    let nonce = match claims.get("nonce") {
        None => None,
        Some(_) => Some(claim(&claims, "nonce", MAX_NONCE)?),
    };
    // IDP-11 step 2
    if header.typ != DPOP_TYP {
        return Err(DpopError::Type);
    }
    // IDP-11 step 3, MD-3
    let alg = algorithm(&header.alg)
        .filter(|a| rules.allowed.contains(a) && a.enabled())
        .ok_or(DpopError::Algorithm)?;
    // IDP-11 step 4
    let key = public_key(&header.jwk)?;
    // IDP-11 step 5
    let input_len = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(DpopError::Format)?;
    let input = proof.get(..input_len).ok_or(DpopError::Format)?.as_bytes();
    match (&key, alg) {
        (PublicKey::Ed25519(pk), Algorithm::Ed25519) => ed25519(backend, pk, input, &signature)?,
        (PublicKey::P256(pk), Algorithm::Es256) => p256(backend, pk, input, &signature, false)?,
        _ => return Err(DpopError::Algorithm),
    }
    // IDP-11 step 6
    if htm != rules.method {
        return Err(DpopError::Method);
    }
    // IDP-11 step 7, TN-28
    let target = normalize_htu(rules.uri).ok_or(DpopError::Target)?;
    let htu = normalize_htu(htu).ok_or(DpopError::Uri)?;
    if htu != target {
        return Err(DpopError::Uri);
    }
    // IDP-11 step 8
    iat_window(iat, rules)?;
    // IDP-11 step 11
    if let Some(token) = rules.access_token {
        let presented = claims.get("ath").and_then(Json::as_str);
        if presented != Some(ath(token).as_str()) {
            return Err(DpopError::Ath);
        }
    }
    let jkt = thumbprint(&key);
    // IDP-11 step 12, TN-31
    if rules.bound_jkt.is_some_and(|bound| *bound != jkt) {
        return Err(DpopError::Jkt);
    }
    Ok(Proof {
        algorithm: alg,
        key,
        jkt,
        jti: String::from(jti),
        htm: String::from(htm),
        htu,
        iat,
        nonce: nonce.map(String::from),
    })
}

#[cfg(test)]
mod tests;
