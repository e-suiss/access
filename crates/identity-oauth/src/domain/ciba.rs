//! CIBA as an invitation (OpenID CIBA Core 1.0 PROFILE, IDP-14, §10.5.3, §9.14.5 k.2, OP-155 m.3
//! (l)): a backchannel request names a `REQUIRE_ACTION` the client already received, by its
//! `exercise_ref` and the RAR `kind=intent` detail of the intent it is about, and asks the realm
//! to call the person to their Approval Surface. The answer is the person's AAS; the CIBA answer
//! is neither a contribution nor authority (PI-3). Poll is the default, ping optional, push never.

use access_kernel::json::{Json, b64url_decode};

use crate::domain::authority::{Detail, Kind, parse_details};
use crate::domain::jwt::{Jwk, JwtError, MAX_ASSERTION_LIFETIME_MS, SKEW_MS, verify_client_jws};
use crate::domain::request::Params;

/// Longest `binding_message`, in characters (OP-155 m.3 (l)).
pub const BINDING_MESSAGE_MAX: usize = 32;
/// The polling interval a request starts with, seconds.
pub const INTERVAL_S: u32 = 5;
/// The longest a request waits for the person, whatever else allows (OP-155 m.3 (l)).
pub const MAX_LIFETIME_MS: u64 = 10 * 60 * 1000;
/// The shortest lifetime worth inviting the person for.
pub const MIN_LIFETIME_MS: u64 = 30_000;
/// The parameter carrying the `exercise_ref` of the `REQUIRE_ACTION` (§9.9.5).
pub const EXERCISE_REF_PARAM: &str = "access_exercise_ref";
/// Longest `client_notification_token` kept.
pub const MAX_NOTIFICATION_TOKEN: usize = 1024;
/// Longest `login_hint`.
pub const MAX_LOGIN_HINT: usize = 256;
/// The Approval Surface page an invitation links to, under the issuer.
pub const PAGE_PATH: &str = "/login";

const HANDLE_CONTEXT: &str = "access/ciba-auth-req-id/v1";

/// Why a backchannel request is refused, by its CIBA Core §13 error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CibaError {
    /// Malformed, a missing or second hint, `user_code`, or push asked for.
    #[error("invalid_request")]
    Request,
    /// `openid` is not asked for, or the scope is malformed.
    #[error("invalid_scope")]
    Scope,
    /// The binding message is too long or not text.
    #[error("invalid_binding_message")]
    BindingMessage,
    /// A free `login_hint` the realm does not accept, or a hint that names no one this client
    /// may name.
    #[error("unknown_user_id")]
    UnknownUser,
    /// The `login_hint_token` or `id_token_hint` does not verify or is expired.
    #[error("expired_login_hint_token")]
    HintToken,
    /// The `authorization_details` are not one `intent` detail.
    #[error("invalid_authorization_details")]
    Details,
    /// The client may not use CIBA, or must send a signed request and did not.
    #[error("unauthorized_client")]
    Client,
}

impl CibaError {
    /// The CIBA `error`.
    #[must_use]
    pub const fn error(self) -> &'static str {
        match self {
            Self::Request => "invalid_request",
            Self::Scope => "invalid_scope",
            Self::BindingMessage => "invalid_binding_message",
            Self::UnknownUser => "unknown_user_id",
            Self::HintToken => "expired_login_hint_token",
            Self::Details => "invalid_authorization_details",
            Self::Client => "unauthorized_client",
        }
    }

    /// The HTTP status (CIBA Core §13).
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Client => 401,
            _ => 400,
        }
    }
}

/// The hint that names the person (CIBA Core §7.1): exactly one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hint {
    /// A client-signed JWT naming the pairwise `sub` the client knows.
    LoginHintToken(String),
    /// An ID token this realm issued to the client.
    IdTokenHint(String),
    /// A free identifier, only with the realm's flag, enumeration-safe.
    LoginHint(String),
}

/// The `exercise_ref` of the `REQUIRE_ACTION` a request invites the person to answer (§9.9.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExerciseRef {
    /// The governing domain.
    pub domain: [u8; 32],
    /// The nonce.
    pub nonce: Vec<u8>,
}

/// A backchannel request, read from its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackchannelRequest {
    /// The hint.
    pub hint: Hint,
    /// The scope, space separated, with `openid`.
    pub scope: String,
    /// The binding message, shown on both devices; never binding.
    pub binding_message: Option<String>,
    /// The `REQUIRE_ACTION`.
    pub exercise: ExerciseRef,
    /// The intent digest it is about, from the `kind=intent` detail.
    pub intent: [u8; 32],
    /// The detail as parsed.
    pub detail: Detail,
    /// The `authorization_details` as sent.
    pub details: String,
    /// The ping mode's bearer token.
    pub notification_token: Option<String>,
    /// The client's `requested_expiry`, ms.
    pub requested_ms: Option<u64>,
}

/// Whether `m` can be a binding message: 1 to [`BINDING_MESSAGE_MAX`] characters of text.
#[must_use]
pub fn binding_message_ok(m: &str) -> bool {
    let n = m.chars().count();
    (1..=BINDING_MESSAGE_MAX).contains(&n) && !m.chars().any(char::is_control)
}

/// The digest of an `auth_req_id` the realm keeps (CR-38).
#[must_use]
pub fn handle_hash(handle: &[u8]) -> [u8; 32] {
    access_crypto::oauth::opaque_digest(HANDLE_CONTEXT, handle)
}

fn digest_of(text: &str) -> Option<[u8; 32]> {
    let raw = text.strip_prefix("sha-256:")?;
    b64url_decode(raw)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
}

/// Reads `access_exercise_ref`: `{"domain": b64url(32), "nonce": b64url(16..=64)}`, the shape of
/// `authorization_remediation.exercise_ref` (§9.9.5).
///
/// # Errors
/// [`CibaError::Request`].
pub fn exercise_ref(raw: &str) -> Result<ExerciseRef, CibaError> {
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|_| CibaError::Request)?;
    let o = v.as_object().ok_or(CibaError::Request)?;
    if o.len() != 2 {
        return Err(CibaError::Request);
    }
    let bytes = |k: &str| {
        o.get(k)
            .and_then(serde_json::Value::as_str)
            .and_then(|s| b64url_decode(s).ok())
    };
    let domain = bytes("domain")
        .and_then(|d| <[u8; 32]>::try_from(d).ok())
        .ok_or(CibaError::Request)?;
    let nonce = bytes("nonce")
        .filter(|n| (16..=64).contains(&n.len()))
        .ok_or(CibaError::Request)?;
    Ok(ExerciseRef { domain, nonce })
}

/// Reads a backchannel request (CIBA Core §7.1, OP-155 m.3 (l)). `login_hint` is taken only
/// when `free_hint` (the realm's flag); `user_code` is not supported; a `request_context` or
/// any push parameter is refused.
///
/// # Errors
/// [`CibaError`].
pub fn read(p: &Params, free_hint: bool) -> Result<BackchannelRequest, CibaError> {
    // IDP-14
    if p.get("user_code").is_some() || p.get("client_notification_endpoint").is_some() {
        return Err(CibaError::Request);
    }
    let hints = [
        p.get("login_hint_token")
            .map(|h| Hint::LoginHintToken(String::from(h))),
        p.get("id_token_hint")
            .map(|h| Hint::IdTokenHint(String::from(h))),
        p.get("login_hint")
            .map(|h| Hint::LoginHint(String::from(h))),
    ];
    let mut given = hints.into_iter().flatten();
    let (Some(hint), None) = (given.next(), given.next()) else {
        return Err(CibaError::Request);
    };
    if let Hint::LoginHint(h) = &hint {
        // §10.2.1
        if !free_hint {
            return Err(CibaError::UnknownUser);
        }
        if h.is_empty() || h.len() > MAX_LOGIN_HINT || h.chars().any(char::is_control) {
            return Err(CibaError::Request);
        }
    }
    let scope = p.get("scope").ok_or(CibaError::Scope)?;
    if scope.len() > 2048
        || scope.chars().any(char::is_control)
        || !scope.split(' ').any(|s| s == "openid")
    {
        return Err(CibaError::Scope);
    }
    let binding_message = match p.get("binding_message") {
        Some(m) if binding_message_ok(m) => Some(String::from(m)),
        Some(_) => return Err(CibaError::BindingMessage),
        None => None,
    };
    let exercise = exercise_ref(p.get(EXERCISE_REF_PARAM).ok_or(CibaError::Request)?)?;
    let details = p
        .get(crate::domain::authority::DETAILS_PARAM)
        .ok_or(CibaError::Details)?;
    // §9.14.5 k.2
    let (kind, parsed) = parse_details(details, "").map_err(|_| CibaError::Details)?;
    let (Kind::Intent, Some(detail)) = (kind, parsed.into_iter().next()) else {
        return Err(CibaError::Details);
    };
    let intent = detail
        .intent
        .as_deref()
        .and_then(digest_of)
        .ok_or(CibaError::Details)?;
    let notification_token = match p.get("client_notification_token") {
        Some(t)
            if !t.is_empty()
                && t.len() <= MAX_NOTIFICATION_TOKEN
                && t.bytes().all(|b| b.is_ascii_graphic()) =>
        {
            Some(String::from(t))
        }
        Some(_) => return Err(CibaError::Request),
        None => None,
    };
    let requested_ms = match p.get("requested_expiry") {
        Some(e) => Some(
            e.parse::<u64>()
                .ok()
                .filter(|s| *s > 0)
                .and_then(|s| s.checked_mul(1000))
                .ok_or(CibaError::Request)?,
        ),
        None => None,
    };
    Ok(BackchannelRequest {
        hint,
        scope: String::from(scope),
        binding_message,
        exercise,
        intent,
        detail,
        details: String::from(details),
        notification_token,
        requested_ms,
    })
}

/// How long the request waits (OP-155 m.3 (l)): at most the intent's validity, the
/// client's `requested_expiry` and [`MAX_LIFETIME_MS`]. `None` when less than
/// [`MIN_LIFETIME_MS`] is left: there is nothing worth inviting the person for.
#[must_use]
pub fn lifetime_ms(intent_until: u64, requested_ms: Option<u64>, now: u64) -> Option<u64> {
    let left = intent_until.saturating_sub(now);
    let life = left
        .min(requested_ms.unwrap_or(MAX_LIFETIME_MS))
        .min(MAX_LIFETIME_MS);
    (life >= MIN_LIFETIME_MS).then_some(life)
}

/// The pairwise `sub` a `login_hint_token` names (OP-155 m.3 (l)): a JWT the client signed with
/// a key it registered, `iss` the client, `aud` the issuer, with `iat` and `exp` at most five
/// minutes apart.
///
/// # Errors
/// [`CibaError::HintToken`].
pub fn login_hint_subject(
    token: &str,
    keys: &[Jwk],
    client_id: &str,
    issuer: &str,
    rs256: bool,
    now: u64,
) -> Result<String, CibaError> {
    let signed =
        verify_client_jws(token, keys, rs256).map_err(|_: JwtError| CibaError::HintToken)?;
    if signed.typ.as_deref().is_some_and(|t| t != "JWT") {
        return Err(CibaError::HintToken);
    }
    let c = &signed.claims;
    let text = |n: &str| c.get(n).and_then(Json::as_str);
    let ms = |n: &str| {
        c.get(n)
            .and_then(Json::as_int)
            .and_then(|s| u64::try_from(s).ok())
            .and_then(|s| s.checked_mul(1000))
    };
    let aud_ok = match c.get("aud") {
        Some(Json::Str(a)) => a == issuer,
        Some(Json::Array(a)) => a.len() == 1 && a.first().and_then(Json::as_str) == Some(issuer),
        _ => false,
    };
    let (Some(exp), Some(iat)) = (ms("exp"), ms("iat")) else {
        return Err(CibaError::HintToken);
    };
    if text("iss") != Some(client_id)
        || !aud_ok
        || exp.saturating_add(SKEW_MS) < now
        || iat > now.saturating_add(SKEW_MS)
        || exp.saturating_sub(iat) > MAX_ASSERTION_LIFETIME_MS
    {
        return Err(CibaError::HintToken);
    }
    text("sub")
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .map(String::from)
        .ok_or(CibaError::HintToken)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use access_kernel::json::b64url_encode;

    use super::*;

    fn params(extra: &[(&str, &str)]) -> Params {
        let digest = b64url_encode(&[7; 32]);
        let mut pairs: Vec<(String, String)> = vec![
            ("scope".into(), "openid".into()),
            ("login_hint_token".into(), "a.b.c".into()),
            (
                EXERCISE_REF_PARAM.into(),
                format!(
                    r#"{{"domain":"{}","nonce":"{}"}}"#,
                    b64url_encode(&[1; 32]),
                    b64url_encode(&[2; 16])
                ),
            ),
            (
                "authorization_details".into(),
                format!(
                    r#"[{{"type":"work:commit:1","kind":"intent","schema":"sha-256:{digest}","intent":"sha-256:{digest}"}}]"#
                ),
            ),
        ];
        for (k, v) in extra {
            pairs.retain(|(n, _)| n != k);
            if !v.is_empty() {
                pairs.push(((*k).into(), (*v).into()));
            }
        }
        Params::new(pairs).unwrap()
    }

    // OP-155 m.3 (l), §9.14.5 k.2
    #[test]
    fn a_request_names_one_hint_one_intent_and_the_exercise_ref() {
        let r = read(&params(&[]), false).unwrap();
        assert_eq!(r.intent, [7; 32]);
        assert_eq!(r.exercise.domain, [1; 32]);
        assert_eq!(r.exercise.nonce, vec![2; 16]);
        assert!(matches!(r.hint, Hint::LoginHintToken(_)));
        let two = params(&[("id_token_hint", "x.y.z")]);
        assert_eq!(read(&two, false), Err(CibaError::Request));
        let none = params(&[("login_hint_token", "")]);
        assert_eq!(read(&none, false), Err(CibaError::Request));
        let bounds = params(&[(
            "authorization_details",
            r#"[{"type":"work:commit:1","kind":"bounds","schema":"sha-256:AA"}]"#,
        )]);
        assert_eq!(read(&bounds, false), Err(CibaError::Details));
        assert_eq!(
            read(&params(&[("scope", "profile")]), false),
            Err(CibaError::Scope)
        );
    }

    // IDP-14, §10.5.3, Ek B 5043
    #[test]
    fn push_and_user_codes_are_refused() {
        let push = params(&[("client_notification_endpoint", "https://rp.example/cb")]);
        assert_eq!(read(&push, false), Err(CibaError::Request));
        assert_eq!(
            read(&params(&[("user_code", "1234")]), false),
            Err(CibaError::Request)
        );
    }

    // §10.2.1, §10.5.3
    #[test]
    fn a_free_login_hint_needs_the_realm_flag() {
        let p = params(&[("login_hint_token", ""), ("login_hint", "ada@example.com")]);
        assert_eq!(read(&p, false), Err(CibaError::UnknownUser));
        assert!(matches!(read(&p, true).unwrap().hint, Hint::LoginHint(_)));
    }

    // OP-155 m.3 (l), §10.5.3
    #[test]
    fn the_binding_message_is_short_text() {
        assert!(binding_message_ok("Code 4F2Q"));
        assert!(binding_message_ok(&"é".repeat(32)));
        assert!(!binding_message_ok(&"a".repeat(33)));
        assert!(!binding_message_ok(""));
        assert!(!binding_message_ok("a\nb"));
        let long = params(&[("binding_message", &"x".repeat(33))]);
        assert_eq!(read(&long, false), Err(CibaError::BindingMessage));
    }

    // OP-155 m.3 (l)
    #[test]
    fn a_request_lives_at_most_ten_minutes_and_the_intent() {
        assert_eq!(lifetime_ms(10_000_000, None, 1_000), Some(MAX_LIFETIME_MS));
        assert_eq!(lifetime_ms(121_000, None, 1_000), Some(120_000));
        assert_eq!(lifetime_ms(10_000_000, Some(60_000), 1_000), Some(60_000));
        assert_eq!(lifetime_ms(20_000, None, 1_000), None);
    }
}
