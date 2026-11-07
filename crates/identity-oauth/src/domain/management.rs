//! Management read tokens (TN-130, TN-27, OP-151 m.3 (a), (c)): RFC 9068 access tokens the
//! realm issues for the management surfaces, one audience each (`access-admin:realm:<slug>`
//! with scope `realm.read`, `access-admin:platform` with scope `platform.read`), always bound
//! by `cnf.jkt` (RFC 9449), living at most 60 minutes, and naming the Instance they were issued
//! to so that its termination ends them. They read; nothing writes with them (MD-14).
//!
//! A caller with its own Instance key gets one by an RFC 8693 token exchange whose subject
//! token is an AIS in `check` mode over [`exchange_intent`], signed by a live Instance key of
//! the realm's governing domain, with a DPoP proof by that same key: the token's `cnf.jkt` is
//! the Instance key itself. The console BFF gets one for a signed-in session's device Instance,
//! bound to the BFF's own DPoP key of that session (TN-128).

use access_crypto::AwsLcBackend;
use access_kernel::ais::{CONTENT_TYPE, SKEW_MS as AIS_SKEW_MS, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{self, KeySet, PublicKey};
use access_kernel::verify::jws::{MAX_PAYLOAD, Origin, verify_compact};
use serde_json::json;
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::digest::context_digest;

use super::jwt::{JwtError, SKEW_MS};
use super::tokens::ACCESS_TYP;

/// The read scope of the realm-admin surface.
pub const REALM_READ: &str = "realm.read";

/// The read scope of the platform-admin surface.
pub const PLATFORM_READ: &str = "platform.read";

/// The platform-admin surface's audience.
pub const PLATFORM_AUDIENCE: &str = "access-admin:platform";

/// The realm-admin surface's audience prefix; the slug follows.
pub const REALM_AUDIENCE_PREFIX: &str = "access-admin:realm:";

/// Longest lifetime of a management read token (TN-130, OP-151 m.3 (c)).
pub const MAX_READ_TTL_MS: u64 = 60 * 60 * 1000;

/// Lifetime of the read tokens this realm issues (PD, within [`MAX_READ_TTL_MS`]).
pub const READ_TTL_MS: u64 = 15 * 60 * 1000;

/// RFC 8693 §2.1 `grant_type`.
pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The `subject_token_type` of an AIS subject token: unpadded base64url of its `COSE_Sign1`.
pub const AIS_TOKEN_TYPE: &str = "urn:suiss:access:token-type:ais";

/// RFC 8693 §3 `issued_token_type` of an access token.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The digest context of an exchange's AIS intent.
pub const EXCHANGE_CONTEXT: &str = "access/management-read/v1";

/// The `client_id` of the console BFF's read tokens.
pub const CONSOLE_CLIENT: &str = "access-console";

/// The claim naming the Instance a token was issued to.
pub const INSTANCE_CLAIM: &str = "access_instance";

/// The claim naming the console session a token was issued to.
pub const CONSOLE_SESSION_CLAIM: &str = "access_console_sid";

/// Largest AIS accepted as a subject token.
pub const MAX_SUBJECT_TOKEN: usize = 16 * 1024;

/// A management surface a read token is for (OP-151 m.3 (a)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Surface {
    /// The realm-admin surface of the realm with this slug.
    Realm(String),
    /// The platform-admin surface.
    Platform,
}

impl Surface {
    /// Its one audience.
    #[must_use]
    pub fn audience(&self) -> String {
        match self {
            Self::Realm(slug) => format!("{REALM_AUDIENCE_PREFIX}{slug}"),
            Self::Platform => String::from(PLATFORM_AUDIENCE),
        }
    }

    /// Its one read scope.
    #[must_use]
    pub const fn scope(&self) -> &'static str {
        match self {
            Self::Realm(_) => REALM_READ,
            Self::Platform => PLATFORM_READ,
        }
    }

    /// The surface an audience names; `None` for any other text.
    #[must_use]
    pub fn of(audience: &str) -> Option<Self> {
        if audience == PLATFORM_AUDIENCE {
            return Some(Self::Platform);
        }
        let slug = audience.strip_prefix(REALM_AUDIENCE_PREFIX)?;
        super::issuer::check_slug(slug)
            .is_ok()
            .then(|| Self::Realm(String::from(slug)))
    }
}

/// What an exchange's AIS signs as its intent: the audience and the scope it asks for.
#[must_use]
pub fn exchange_intent(audience: &str, scope: &str) -> Digest {
    let mut canonical =
        Vec::with_capacity(audience.len().saturating_add(scope.len()).saturating_add(1));
    canonical.extend_from_slice(audience.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(scope.as_bytes());
    Digest(context_digest(EXCHANGE_CONTEXT, &canonical).0)
}

/// Why an exchange's subject token is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SubjectError {
    /// Not an AIS: not base64url, too large, or no 32-byte `kid`.
    #[error("format")]
    Format,
    /// Not signed by the named Instance key, not a `check` statement over this exchange's
    /// intent in the realm's domain, or not signed within the skew.
    #[error("rejected")]
    Rejected,
}

/// The AIS bytes and the Instance `kid` its protected header names.
///
/// # Errors
/// [`SubjectError::Format`].
pub fn subject_token(text: &str) -> Result<(Vec<u8>, [u8; 32]), SubjectError> {
    if text.len() > MAX_SUBJECT_TOKEN.saturating_mul(2) {
        return Err(SubjectError::Format);
    }
    let bytes = b64url_decode(text).map_err(|_| SubjectError::Format)?;
    if bytes.is_empty() || bytes.len() > MAX_SUBJECT_TOKEN {
        return Err(SubjectError::Format);
    }
    let parsed = cose::parse_sign1(&bytes).map_err(|_| SubjectError::Format)?;
    let Ok(dcbor::Value::Map(entries)) = dcbor::decode(&parsed.protected, Limits::CEILING) else {
        return Err(SubjectError::Format);
    };
    let kid = entries
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (dcbor::Value::Unsigned(cose::KID), dcbor::Value::Bytes(b)) => {
                <[u8; 32]>::try_from(b.as_slice()).ok()
            }
            _ => None,
        })
        .ok_or(SubjectError::Format)?;
    Ok((bytes, kid))
}

/// Verifies an exchange's AIS with the Instance `key` found for its `kid` (TN-130): a `check`
/// statement (CT0: reading is not consent) for `domain` over `intent`, signed within the AIS
/// skew of `now_ms` either way.
///
/// # Errors
/// [`SubjectError::Rejected`].
pub fn verify_subject(
    sign1: &[u8],
    kid: [u8; 32],
    key: &PublicKey,
    domain: &Digest,
    intent: &Digest,
    now_ms: u64,
) -> Result<Statement, SubjectError> {
    let mut keys = KeySet::default();
    keys.insert(kid, key.clone())
        .map_err(|_| SubjectError::Rejected)?;
    keys.allowed.extend([
        cose::Algorithm::Esp256,
        cose::Algorithm::Es256,
        cose::Algorithm::Ed25519,
    ]);
    let verified = cose::verify_sign1(&PureBackend, sign1, &keys, CONTENT_TYPE)
        .map_err(|_| SubjectError::Rejected)?;
    let value =
        dcbor::decode(&verified.payload, Limits::CEILING).map_err(|_| SubjectError::Rejected)?;
    let s = Statement::from_value(&value).map_err(|_| SubjectError::Rejected)?;
    let fresh =
        s.iat <= now_ms.saturating_add(AIS_SKEW_MS) && now_ms <= s.iat.saturating_add(AIS_SKEW_MS);
    if s.mode != Mode::Check || s.domain != *domain || s.intent != *intent || !fresh {
        return Err(SubjectError::Rejected);
    }
    Ok(s)
}

/// The facts behind one read token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadFacts<'a> {
    /// The issuing realm's issuer.
    pub issuer: &'a str,
    /// The surface it reads.
    pub surface: &'a Surface,
    /// Who holds it, pseudonymous: the account's external id, or the Instance's thumbprint.
    pub sub: &'a str,
    /// `client_id`: [`CONSOLE_CLIENT`], or the Instance's thumbprint.
    pub client_id: &'a str,
    /// The Instance it was issued to; its termination ends the token.
    pub instance: [u8; 32],
    /// The DPoP key it is bound to (RFC 9449 `cnf.jkt`).
    pub jkt: [u8; 32],
    /// The console session it was issued to, if any; its end ends the token.
    pub console_session: Option<[u8; 16]>,
    /// The account's `session_epoch` at issue, if issued to an account's session (OP-21).
    pub rev: Option<i64>,
    /// Issue time, Unix milliseconds.
    pub now_ms: u64,
    /// Lifetime, at most [`MAX_READ_TTL_MS`].
    pub ttl_ms: u64,
}

/// The read token's claims (RFC 9068 §2.2): one audience, one read scope, bound by `cnf.jkt`.
#[must_use]
pub fn read_token_claims(f: &ReadFacts<'_>, jti: &str) -> Vec<u8> {
    let ttl = f.ttl_ms.min(MAX_READ_TTL_MS);
    let mut claims = json!({
        "iss": f.issuer,
        "sub": f.sub,
        "aud": f.surface.audience(),
        "client_id": f.client_id,
        "iat": f.now_ms / 1000,
        "exp": f.now_ms.saturating_add(ttl) / 1000,
        "jti": jti,
        "scope": f.surface.scope(),
        "cnf": { "jkt": b64url_encode(&f.jkt) },
        INSTANCE_CLAIM: b64url_encode(&f.instance),
    });
    if let serde_json::Value::Object(m) = &mut claims {
        if let Some(sid) = f.console_session {
            m.insert(CONSOLE_SESSION_CLAIM.into(), b64url_encode(&sid).into());
        }
        if let Some(rev) = f.rev {
            m.insert("rev".into(), rev.into());
        }
    }
    claims.to_string().into_bytes()
}

/// A read token whose signature verified, as its claims say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadClaims {
    /// `iss`.
    pub iss: String,
    /// `sub`.
    pub sub: String,
    /// The one audience.
    pub aud: String,
    /// The scopes.
    pub scopes: Vec<String>,
    /// `iat`, Unix milliseconds.
    pub iat_ms: u64,
    /// `exp`, Unix milliseconds.
    pub exp_ms: u64,
    /// `cnf.jkt`.
    pub jkt: [u8; 32],
    /// The Instance it was issued to.
    pub instance: [u8; 32],
    /// The console session it was issued to.
    pub console_session: Option<[u8; 16]>,
    /// The account's `session_epoch` at issue.
    pub rev: Option<i64>,
}

fn text(c: &Json, name: &str) -> Option<String> {
    c.get(name).and_then(Json::as_str).map(String::from)
}

fn fixed<const N: usize>(c: Option<&Json>) -> Option<[u8; N]> {
    let t = c?.as_str()?;
    <[u8; N]>::try_from(b64url_decode(t).ok()?.as_slice()).ok()
}

fn millis(c: &Json, name: &str) -> Option<u64> {
    c.get(name)
        .and_then(Json::as_int)
        .and_then(|s| u64::try_from(s).ok())
        .and_then(|s| s.checked_mul(1000))
}

/// The unverified `aud` of a token, to pick the realm whose keys verify it; nothing is trusted
/// before [`read_claims`].
#[must_use]
pub fn unverified_audience(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = b64url_decode(payload).ok()?;
    let c = json::parse(&bytes, MAX_PAYLOAD).ok()?;
    text(&c, "aud")
}

/// Verifies a read token's signature with the issuing realm's `keys` and `typ` `at+jwt`, and
/// reads its claims; `issuer` must be its `iss`. Time, audience and scope are the caller's
/// checks (`access_http::api::domain::caller::check_read`).
///
/// # Errors
/// [`JwtError`].
pub fn read_claims(token: &str, keys: &KeySet, issuer: &str) -> Result<ReadClaims, JwtError> {
    let v = verify_compact(&AwsLcBackend, token, keys, ACCESS_TYP, Origin::Native)
        .map_err(|_| JwtError::Signature)?;
    let c = json::parse(&v.payload, MAX_PAYLOAD).map_err(|_| JwtError::Claims)?;
    if text(&c, "iss").as_deref() != Some(issuer) {
        return Err(JwtError::Claims);
    }
    let (Some(sub), Some(aud), Some(scope)) = (text(&c, "sub"), text(&c, "aud"), text(&c, "scope"))
    else {
        return Err(JwtError::Claims);
    };
    let (Some(iat_ms), Some(exp_ms)) = (millis(&c, "iat"), millis(&c, "exp")) else {
        return Err(JwtError::Time);
    };
    let jkt = fixed::<32>(c.get("cnf").and_then(|cnf| cnf.get("jkt"))).ok_or(JwtError::Claims)?;
    let instance = fixed::<32>(c.get(INSTANCE_CLAIM)).ok_or(JwtError::Claims)?;
    let console_session = match c.get(CONSOLE_SESSION_CLAIM) {
        None => None,
        Some(v) => Some(fixed::<16>(Some(v)).ok_or(JwtError::Claims)?),
    };
    let rev = match c.get("rev") {
        None => None,
        Some(v) => Some(v.as_int().ok_or(JwtError::Claims)?),
    };
    Ok(ReadClaims {
        iss: issuer.to_owned(),
        sub,
        aud,
        scopes: scope
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        iat_ms,
        exp_ms,
        jkt,
        instance,
        console_session,
        rev,
    })
}

/// Whether `claims` are within their lifetime at `now_ms`, with the JWT skew on `iat`.
#[must_use]
pub const fn live(claims: &ReadClaims, now_ms: u64) -> bool {
    claims.exp_ms > now_ms && claims.iat_ms <= now_ms.saturating_add(SKEW_MS)
}

#[cfg(test)]
mod tests;
