//! SVID checks (§11.12.1, AG-30, `draft-ietf-oauth-spiffe-client-auth-02` §3.1, §3.2).
//!
//! A JWT-SVID names its SPIFFE ID in `sub`, carries `aud` with the authorization server's
//! issuer as its only value and `exp`, and verifies under a `jwt-svid` key of its own trust
//! domain's bundle. An X.509-SVID chains to that bundle's `x509-svid` roots, is a leaf with the
//! `digitalSignature` key usage and names exactly one SPIFFE ID as its URI SAN. Either way the
//! result is a workload identity, an actor-binding input (L25), never authority.

use access_crypto::oauth::{ClientAlg, opaque_digest, verify_client_signature};
use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::verify::jws::{MAX_HEADER, MAX_PAYLOAD, MAX_TOKEN};

use crate::domain::bundle::{self, Bundle};
use crate::domain::workload::{Scheme, WorkloadId};
use crate::domain::x509::{self, CRL_SIGN, Cert, DIGITAL_SIGNATURE, KEY_CERT_SIGN};

/// The client assertion type of a JWT-SVID (`draft-ietf-oauth-spiffe-client-auth` §3.1).
pub const JWT_SPIFFE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";

/// The longest a JWT-SVID may still live when presented (PD): five minutes, the SPIRE default
/// lifetime.
pub const MAX_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// Clock skew for JWT time claims (§10.4.5: ±60 s).
pub const SKEW_MS: u64 = 60_000;

/// Why an SVID is refused; every case is `invalid_client` at the token endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SvidError {
    /// Not a compact JWS, a certificate, or outside the profile.
    #[error("format")]
    Format,
    /// The SPIFFE ID is malformed or of another trust domain than the bundle.
    #[error("spiffe id")]
    Id,
    /// No bundle key fits, or the bundle is too old to verify anything.
    #[error("key")]
    Key,
    /// The signature or the chain does not verify.
    #[error("signature")]
    Signature,
    /// `aud` is not the issuer alone.
    #[error("audience")]
    Audience,
    /// Expired, not yet valid, or too long-lived.
    #[error("time")]
    Time,
}

/// A verified SVID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The workload it names.
    pub id: WorkloadId,
    /// `exp` of a JWT-SVID, Unix milliseconds; `None` for an X.509-SVID, whose life is its
    /// certificate's and the connection's.
    pub exp_ms: Option<u64>,
    /// What a JWT-SVID's one use is recorded under: a digest of its `jti`, or of the whole
    /// token when it has none.
    pub replay_key: Option<[u8; 32]>,
}

/// When a bundle was fetched, as its freshness rule needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freshness {
    /// When it was fetched, Unix milliseconds.
    pub fetched_ms: u64,
    /// Now, Unix milliseconds.
    pub now_ms: u64,
}

impl Freshness {
    fn check(self, b: &Bundle) -> Result<(), SvidError> {
        // OP-154 m.3 (r)
        if bundle::usable(self.fetched_ms, b.refresh_interval_s(), self.now_ms) {
            Ok(())
        } else {
            Err(SvidError::Key)
        }
    }
}

struct Parts<'a> {
    header: Json,
    input: &'a str,
    payload: Json,
    signature: Vec<u8>,
}

fn split(token: &str) -> Result<Parts<'_>, SvidError> {
    if token.len() > MAX_TOKEN {
        return Err(SvidError::Format);
    }
    let mut it = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(SvidError::Format);
    };
    let end = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(SvidError::Format)?;
    let decode = |part: &str| b64url_decode(part).map_err(|_| SvidError::Format);
    Ok(Parts {
        header: json::parse(&decode(h)?, MAX_HEADER).map_err(|_| SvidError::Format)?,
        input: token.get(..end).ok_or(SvidError::Format)?,
        payload: json::parse(&decode(p)?, MAX_PAYLOAD).map_err(|_| SvidError::Format)?,
        signature: decode(s)?,
    })
}

fn time(c: &Json, name: &str) -> Result<Option<u64>, SvidError> {
    c.get(name)
        .map(|v| {
            v.as_int()
                .and_then(|s| u64::try_from(s).ok())
                .and_then(|s| s.checked_mul(1000))
                .ok_or(SvidError::Time)
        })
        .transpose()
}

/// The SPIFFE ID a JWT-SVID names in `sub`, read before its trust domain's bundle is fetched;
/// nothing is verified yet.
///
/// # Errors
/// [`SvidError`].
pub fn jwt_subject(token: &str) -> Result<WorkloadId, SvidError> {
    let parts = split(token)?;
    let sub = parts
        .payload
        .get("sub")
        .and_then(Json::as_str)
        .ok_or(SvidError::Id)?;
    let id = WorkloadId::parse(sub).map_err(|_| SvidError::Id)?;
    if id.scheme() == Scheme::Spiffe {
        Ok(id)
    } else {
        Err(SvidError::Id)
    }
}

/// AG-30, §11.12.1: verifies a JWT-SVID against its trust domain's `bundle` for the
/// authorization server `issuer`. `alg` is ES256 from the allowlist, never from the header
/// alone (IDI-6); `typ`, when present, is `JWT` or `JOSE`; `kid` names one `jwt-svid` key;
/// `sub` is a SPIFFE ID of the bundle's trust domain; `aud` holds `issuer` and nothing else;
/// `exp` is required and at most [`MAX_LIFETIME_MS`] ahead.
///
/// # Errors
/// [`SvidError`].
pub fn verify_jwt(
    token: &str,
    bundle: &Bundle,
    issuer: &str,
    at: Freshness,
) -> Result<Verified, SvidError> {
    at.check(bundle)?;
    let parts = split(token)?;
    let Json::Object(header) = &parts.header else {
        return Err(SvidError::Format);
    };
    if header
        .iter()
        .any(|(k, v)| !matches!(k.as_str(), "alg" | "kid" | "typ") || v.as_str().is_none())
    {
        return Err(SvidError::Format);
    }
    let field = |name: &str| parts.header.get(name).and_then(Json::as_str);
    if field("alg") != Some("ES256") {
        return Err(SvidError::Format);
    }
    if field("typ").is_some_and(|t| t != "JWT" && t != "JOSE") {
        return Err(SvidError::Format);
    }
    let kid = field("kid").ok_or(SvidError::Key)?;
    let candidates: Vec<_> = bundle.jwt_keys.iter().filter(|k| k.kid == kid).collect();
    let [key] = candidates.as_slice() else {
        return Err(SvidError::Key);
    };
    verify_client_signature(
        ClientAlg::Es256,
        &key.key,
        parts.input.as_bytes(),
        &parts.signature,
    )
    .map_err(|_| SvidError::Signature)?;
    let c = &parts.payload;
    let id = c
        .get("sub")
        .and_then(Json::as_str)
        .and_then(|s| WorkloadId::parse(s).ok())
        .filter(|id| id.scheme() == Scheme::Spiffe && id.trust_domain() == bundle.trust_domain)
        .ok_or(SvidError::Id)?;
    let aud = match c.get("aud") {
        Some(Json::Str(a)) => Some(a.as_str()),
        Some(Json::Array(a)) if a.len() == 1 => a.first().and_then(Json::as_str),
        _ => None,
    };
    if aud != Some(issuer) {
        return Err(SvidError::Audience);
    }
    let exp = time(c, "exp")?.ok_or(SvidError::Time)?;
    let latest = at.now_ms.saturating_add(SKEW_MS);
    if exp.saturating_add(SKEW_MS) < at.now_ms
        || exp
            > at.now_ms
                .saturating_add(MAX_LIFETIME_MS)
                .saturating_add(SKEW_MS)
        || time(c, "iat")?.is_some_and(|t| t > latest)
        || time(c, "nbf")?.is_some_and(|t| t > latest)
    {
        return Err(SvidError::Time);
    }
    let replay_input = match c.get("jti").and_then(Json::as_str) {
        Some(j) if !j.is_empty() && j.len() <= 256 => {
            let mut k = Vec::from(id.as_str().as_bytes());
            k.push(0);
            k.extend_from_slice(j.as_bytes());
            k
        }
        Some(_) => return Err(SvidError::Format),
        None => Vec::from(token.as_bytes()),
    };
    Ok(Verified {
        id,
        exp_ms: Some(exp),
        replay_key: Some(opaque_digest("access/jwt-svid/v1", &replay_input)),
    })
}

/// AG-30, §11.15: verifies the client certificate chain `chain` (leaf first, DER) presented
/// over mutual TLS as an X.509-SVID of `bundle`'s trust domain at `at`: path validation to the
/// bundle's `x509-svid` roots for client authentication, a leaf (`cA` false) with
/// `digitalSignature` and neither `keyCertSign` nor `cRLSign`, and exactly one URI SAN, a
/// SPIFFE ID of that trust domain.
///
/// # Errors
/// [`SvidError`].
pub fn verify_x509(
    chain: &[Vec<u8>],
    bundle: &Bundle,
    at: Freshness,
) -> Result<Verified, SvidError> {
    at.check(bundle)?;
    let (leaf, intermediates) = chain.split_first().ok_or(SvidError::Format)?;
    if bundle.x509_roots.is_empty() {
        return Err(SvidError::Key);
    }
    let roots: Vec<&[u8]> = bundle.x509_roots.iter().map(Vec::as_slice).collect();
    x509::verify_chain(
        leaf,
        intermediates,
        &roots,
        at.now_ms / 1000,
        x509::client_auth(),
    )
    .map_err(|_| SvidError::Signature)?;
    let cert = Cert::parse(leaf).map_err(|_| SvidError::Format)?;
    if cert.is_ca().map_err(|_| SvidError::Format)? != Some(false) {
        return Err(SvidError::Format);
    }
    let usage = cert
        .key_usage()
        .map_err(|_| SvidError::Format)?
        .ok_or(SvidError::Format)?;
    if usage & DIGITAL_SIGNATURE == 0 || usage & (KEY_CERT_SIGN | CRL_SIGN) != 0 {
        return Err(SvidError::Format);
    }
    let uris = cert.san_uris().map_err(|_| SvidError::Format)?;
    let [uri] = uris.as_slice() else {
        return Err(SvidError::Id);
    };
    let id = WorkloadId::parse(uri)
        .ok()
        .filter(|id| id.scheme() == Scheme::Spiffe && id.trust_domain() == bundle.trust_domain)
        .ok_or(SvidError::Id)?;
    Ok(Verified {
        id,
        exp_ms: None,
        replay_key: None,
    })
}

/// The one `uniformResourceIdentifier` of a certificate's subjectAltName; `None` when it has
/// none, more than one, or does not parse. Read after TLS verified the chain (OP-155 m.3 (c):
/// a gateway's identity).
#[must_use]
pub fn x509_uri(leaf: &[u8]) -> Option<String> {
    let cert = Cert::parse(leaf).ok()?;
    let uris = cert.san_uris().ok()?;
    let [uri] = uris.as_slice() else {
        return None;
    };
    Some(String::from(*uri))
}

/// The SPIFFE ID an X.509-SVID names, read before its trust domain's bundle is fetched;
/// nothing is verified yet.
///
/// # Errors
/// [`SvidError`].
pub fn x509_subject(leaf: &[u8]) -> Result<WorkloadId, SvidError> {
    let cert = Cert::parse(leaf).map_err(|_| SvidError::Format)?;
    let uris = cert.san_uris().map_err(|_| SvidError::Format)?;
    let [uri] = uris.as_slice() else {
        return Err(SvidError::Id);
    };
    WorkloadId::parse(uri)
        .ok()
        .filter(|id| id.scheme() == Scheme::Spiffe)
        .ok_or(SvidError::Id)
}

#[cfg(test)]
mod tests;
