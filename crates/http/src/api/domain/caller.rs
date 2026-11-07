//! Who calls the management API (OP-151 m.3 (c), TN-110, TN-119, TN-130): a read presents a
//! holder-bound (DPoP) token of the surface's audience with the read scope, living at most 60
//! minutes; a write presents the caller's AIS, signed with a live Instance key of the surface's
//! domain. A bearer token is never a management credential, and no token writes.

use access_kernel::ais::{CONTENT_TYPE, SKEW_MS, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{self, KeySet, PublicKey};
use suiss_crypto::dcbor::{self, Limits, Value};

use super::SurfaceScope;
use crate::api::ports::ReadToken;

/// Longest read token lifetime (OP-151 m.3 (c)).
pub const MAX_TOKEN_LIFETIME_MS: u64 = 60 * 60 * 1000;

/// Clock skew allowed on a token's `iat`.
pub const TOKEN_SKEW_MS: u64 = 60_000;

/// The header carrying the AIS, unpadded base64url of its `COSE_Sign1`.
pub const AIS_HEADER: &str = "x-access-ais";

/// The body member carrying the AIS instead of the header.
pub const AIS_FIELD: &str = "ais";

/// Largest AIS accepted.
pub const MAX_AIS: usize = 16 * 1024;

/// Why a caller is refused. Each maps to one stable problem code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// No usable read token.
    #[error("invalid token")]
    InvalidToken,
    /// The token is for another surface.
    #[error("wrong audience")]
    WrongAudience,
    /// The token lives longer than 60 minutes.
    #[error("token lifetime")]
    TokenLifetime,
    /// The token lacks the route's scope.
    #[error("insufficient scope")]
    InsufficientScope,
    /// A write without an AIS.
    #[error("AIS required")]
    AisRequired,
    /// A malformed AIS.
    #[error("AIS invalid")]
    AisInvalid,
    /// An AIS no live Instance key of the surface's domain verifies, or for another domain or
    /// mode.
    #[error("AIS rejected")]
    AisRejected,
}

/// A verified read caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadCaller {
    /// The surface it reads.
    pub scope: SurfaceScope,
    /// Its token.
    pub token: ReadToken,
}

/// A verified write caller: the Instance key's thumbprint and the statement it signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteCaller {
    /// RFC 7638 thumbprint of the Instance key.
    pub kid: [u8; 32],
    /// The signed statement.
    pub statement: Statement,
    /// The `COSE_Sign1` as received, for the Exercise.
    pub ais: Vec<u8>,
}

impl WriteCaller {
    /// The `Idempotency-Key` this write must carry: its AIS nonce, unpadded base64url (TN-126).
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        b64url_encode(&self.statement.nonce)
    }
}

/// How the request authenticates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorization<'a> {
    /// No `Authorization`.
    None,
    /// `Authorization: DPoP <token>`, sent once.
    Dpop(&'a str),
    /// Anything else: a bearer token, another scheme, or the header twice.
    Unusable,
}

/// Reads the `Authorization` header values.
#[must_use]
pub fn authorization<'a>(values: &[&'a str]) -> Authorization<'a> {
    match values {
        [] => Authorization::None,
        [one] => match one.split_once(' ') {
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("dpop") => {
                let token = token.trim();
                if token.is_empty() || token.contains(' ') {
                    Authorization::Unusable
                } else {
                    Authorization::Dpop(token)
                }
            }
            _ => Authorization::Unusable,
        },
        _ => Authorization::Unusable,
    }
}

/// Holds a verified token against the surface and the route's scope (OP-151 m.3 (a), (c)).
///
/// # Errors
/// [`Refusal`].
pub fn check_read(
    token: &ReadToken,
    scope: &SurfaceScope,
    required: &str,
    now_ms: u64,
) -> Result<(), Refusal> {
    if token.audience != scope.audience() {
        return Err(Refusal::WrongAudience);
    }
    if token.expires_at_ms <= now_ms || token.issued_at_ms > now_ms.saturating_add(TOKEN_SKEW_MS) {
        return Err(Refusal::InvalidToken);
    }
    if token.expires_at_ms.saturating_sub(token.issued_at_ms) > MAX_TOKEN_LIFETIME_MS {
        return Err(Refusal::TokenLifetime);
    }
    if !token.scopes.iter().any(|s| s == required) {
        return Err(Refusal::InsufficientScope);
    }
    Ok(())
}

/// The AIS bytes from the header value, or from the body's `ais` member.
///
/// # Errors
/// [`Refusal::AisRequired`] when neither carries one, [`Refusal::AisInvalid`] when it is not
/// base64url, too large, or given twice.
pub fn ais_bytes(header: &[&str], body: &[u8]) -> Result<Vec<u8>, Refusal> {
    let from_body = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get(AIS_FIELD).cloned());
    let text = match (header, from_body) {
        ([], None) => return Err(Refusal::AisRequired),
        ([h], None) => (*h).to_owned(),
        ([], Some(serde_json::Value::String(s))) => s,
        _ => return Err(Refusal::AisInvalid),
    };
    if text.len() > MAX_AIS.saturating_mul(2) {
        return Err(Refusal::AisInvalid);
    }
    let bytes = b64url_decode(&text).map_err(|_| Refusal::AisInvalid)?;
    if bytes.is_empty() || bytes.len() > MAX_AIS {
        return Err(Refusal::AisInvalid);
    }
    Ok(bytes)
}

/// The `kid` an AIS names in its protected header.
///
/// # Errors
/// [`Refusal::AisInvalid`].
pub fn ais_kid(sign1: &[u8]) -> Result<[u8; 32], Refusal> {
    let parsed = cose::parse_sign1(sign1).map_err(|_| Refusal::AisInvalid)?;
    let Ok(Value::Map(entries)) = dcbor::decode(&parsed.protected, Limits::CEILING) else {
        return Err(Refusal::AisInvalid);
    };
    entries
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Unsigned(cose::KID), Value::Bytes(b)) => {
                <[u8; 32]>::try_from(b.as_slice()).ok()
            }
            _ => None,
        })
        .ok_or(Refusal::AisInvalid)
}

/// Verifies an AIS with the Instance `key` found for its `kid`, and checks it is a `commit`
/// statement for `domain`, not signed in the future. The rest of the statement (intent, basis,
/// capacity, PEP) is checked by ADP `commit` against the Exercise it compiles to (PI-7).
///
/// # Errors
/// [`Refusal::AisRejected`].
pub fn verify_ais(
    sign1: Vec<u8>,
    kid: [u8; 32],
    key: &PublicKey,
    domain: &Digest,
    now_ms: u64,
) -> Result<WriteCaller, Refusal> {
    let mut keys = KeySet::default();
    keys.insert(kid, key.clone())
        .map_err(|_| Refusal::AisRejected)?;
    keys.allowed.extend([
        cose::Algorithm::Ed25519,
        cose::Algorithm::Esp256,
        cose::Algorithm::Es256,
    ]);
    let verified = cose::verify_sign1(&PureBackend, &sign1, &keys, CONTENT_TYPE)
        .map_err(|_| Refusal::AisRejected)?;
    let value =
        dcbor::decode(&verified.payload, Limits::CEILING).map_err(|_| Refusal::AisRejected)?;
    let statement = Statement::from_value(&value).map_err(|_| Refusal::AisRejected)?;
    if statement.domain != *domain
        || statement.mode != Mode::Commit
        || statement.iat > now_ms.saturating_add(SKEW_MS)
    {
        return Err(Refusal::AisRejected);
    }
    Ok(WriteCaller {
        kid,
        statement,
        ais: sign1,
    })
}
