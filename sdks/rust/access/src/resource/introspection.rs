//! RFC 7662 introspection of an authority token at the resource server (§9.9.3 rule 5, §10.4.3,
//! §13.4 G48, MD-8, OP-150 m.9 (i)): the authority plane answers `at_least` its head and names
//! the position in `as_of`. `active: false`, a 5xx, no answer and an unreadable body are all
//! DENY; the answer is read only for what it proves about this token.

use access_kernel::json::{self, Json};
use access_kernel::model::TrustedTime;

use super::Denied;
use crate::transport::Answer;

/// Largest introspection body read (§14.6).
pub const MAX_BODY: usize = 64 * 1024;

/// The introspection port: `POST /introspect` for one token.
pub trait Introspector {
    /// The answer, as served.
    fn introspect(&self, token: &str) -> Answer;
}

/// An active answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Active {
    /// The claims the answer carries.
    pub claims: Json,
    /// The head position the answer reflects.
    pub as_of: u64,
}

fn as_of(claims: &Json) -> Option<u64> {
    match claims.get("as_of")? {
        Json::Int(i) => u64::try_from(*i).ok(),
        Json::Str(s) if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        _ => None,
    }
}

/// Reads an answer: 200 with a JSON object whose `active` is `true`, `aud` is this resource
/// server, `exp` is after `now` and `as_of` is a position.
///
/// # Errors
/// [`Denied`].
pub fn active(
    answer: Answer,
    audience: &str,
    now: TrustedTime,
    skew_ms: u64,
) -> Result<Active, Denied> {
    let response = match answer {
        Answer::Unanswered(fault) => return Err(Denied::IntrospectionUnavailable(fault)),
        Answer::Response(r) if r.status != 200 => {
            return Err(Denied::IntrospectionStatus(r.status));
        }
        Answer::Response(r) => r,
    };
    let claims =
        json::parse(&response.body, MAX_BODY).map_err(|_| Denied::IntrospectionMalformed)?;
    if !matches!(claims, Json::Object(_)) {
        return Err(Denied::IntrospectionMalformed);
    }
    match claims.get("active") {
        Some(Json::Bool(true)) => {}
        Some(Json::Bool(false)) => return Err(Denied::Inactive),
        _ => return Err(Denied::IntrospectionMalformed),
    }
    // AG-8, §9.9.3 rule 1
    if claims.get("aud").and_then(Json::as_str) != Some(audience) {
        return Err(Denied::IntrospectionAudience);
    }
    let exp = claims
        .get("exp")
        .and_then(Json::as_int)
        .and_then(|e| u64::try_from(e).ok())
        .and_then(|e| e.checked_mul(1000))
        .ok_or(Denied::IntrospectionMalformed)?;
    if now > exp.saturating_add(skew_ms) {
        return Err(Denied::IntrospectionExpired);
    }
    let as_of = as_of(&claims).ok_or(Denied::IntrospectionMalformed)?;
    Ok(Active { claims, as_of })
}
