//! `WWW-Authenticate` challenges (RFC 6750 §3, RFC 9449 §7.1, RFC 9470 §3, RFC 9728 §5.1;
//! §9.9.5, §11.5.1 SHOULD, §11.5.6 #1, #6 to #9, RS-M3, RS-M6). Every challenge names the
//! metadata URL; an operation's scopes go into one challenge; `offline_access` never does.
//! A required action (`REQUIRE_ACTION`) is told apart from missing scope, and both from a
//! refusal: the client steps up, asks for scope, or goes to the Approval Surface, never guesses.

use alloc::string::String;
use alloc::vec::Vec;

use super::prm::{Binding, OFFLINE_ACCESS, ProtectedResource, scope_token};
use crate::resource::{Denied, StepUp};

/// Why the request is challenged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// No credentials: 401 without an error code (RFC 6750 §3.1).
    Missing,
    /// A token that is invalid, expired, for another audience or unbound: 401 `invalid_token`.
    InvalidToken,
    /// The token's bounds do not cover the operation: 403 `insufficient_scope` with every
    /// scope the operation needs.
    InsufficientScope(Vec<String>),
    /// The user's authentication is too weak or too old: 401
    /// `insufficient_user_authentication` (RFC 9470).
    UserAuthentication(StepUp),
    /// Access answered `REQUIRE_ACTION`: 403 `insufficient_authorization`, never
    /// `insufficient_scope` (§9.9.5).
    Authorization,
}

impl Challenge {
    /// The challenge for a token refusal of [`crate::resource::ResourceServer`]: the bounds
    /// cases ask for `scopes`, a step-up asks for the user's authentication, everything else
    /// is an invalid token (§11.5.6 #6).
    #[must_use]
    pub fn of(denied: &Denied, scopes: &[String]) -> Self {
        match denied {
            Denied::Bounds | Denied::Intent | Denied::LocalRequirement => {
                Self::InsufficientScope(scopes.to_vec())
            }
            Denied::StepUp(s) => Self::UserAuthentication(*s),
            _ => Self::InvalidToken,
        }
    }

    /// The HTTP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::Missing | Self::InvalidToken | Self::UserAuthentication(_) => 401,
            Self::InsufficientScope(_) | Self::Authorization => 403,
        }
    }

    const fn error(&self) -> Option<&'static str> {
        match self {
            Self::Missing => None,
            Self::InvalidToken => Some("invalid_token"),
            Self::InsufficientScope(_) => Some("insufficient_scope"),
            Self::UserAuthentication(_) => Some("insufficient_user_authentication"),
            Self::Authorization => Some("insufficient_authorization"),
        }
    }
}

/// The `scope` parameter: each scope once, in the order given, without `offline_access` or a
/// value that is not a scope token; `None` when nothing is left.
#[must_use]
pub fn scope_param(scopes: &[String]) -> Option<String> {
    let mut seen: Vec<&str> = Vec::new();
    for s in scopes {
        if s != OFFLINE_ACCESS && scope_token(s) && !seen.contains(&s.as_str()) {
            seen.push(s);
        }
    }
    (!seen.is_empty()).then(|| seen.join(" "))
}

fn params(out: &mut String, challenge: &Challenge, prm: &ProtectedResource) {
    let mut first = true;
    let mut push = |out: &mut String, k: &str, v: &str| {
        if !first {
            out.push(',');
        }
        first = false;
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(v);
        out.push('"');
    };
    if let Some(e) = challenge.error() {
        push(out, "error", e);
    }
    if let Challenge::InsufficientScope(scopes) = challenge
        && let Some(scope) = scope_param(scopes)
    {
        push(out, "scope", &scope);
    }
    if let Challenge::UserAuthentication(step) = challenge {
        push(out, "max_age", &alloc::format!("{}", step.max_age_s));
        if let Some(a) = step.aal {
            push(
                out,
                "acr_values",
                &alloc::format!("http://idmanagement.gov/ns/assurance/aal/{a}"),
            );
        }
    }
    push(out, "resource_metadata", &prm.metadata_url());
}

/// The `WWW-Authenticate` values: a `Bearer` challenge, and under the DPoP profile a `DPoP`
/// challenge with the accepted `algs` as well (§11.5.6 #1, AG-9). Only send them with a 401
/// or 403: a challenge on a 200 means nothing (§11.5.6 #2).
#[must_use]
pub fn www_authenticate(challenge: &Challenge, prm: &ProtectedResource) -> Vec<String> {
    let mut bearer = String::from("Bearer");
    params(&mut bearer, challenge, prm);
    let mut out = alloc::vec![bearer];
    if let Binding::Dpop(algs) = prm.binding() {
        let mut dpop = String::from("DPoP algs=\"");
        dpop.push_str(&algs.join(" "));
        dpop.push('"');
        let mut rest = String::new();
        params(&mut rest, challenge, prm);
        dpop.push(',');
        dpop.push_str(&rest);
        out.push(dpop);
    }
    out
}
