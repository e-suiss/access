//! The identity side (CMP-17, T41 items 1 and 2, OP-151 m.3 (g)): an OpenID Connect relying
//! party and the client half of DPoP, sans I/O. Discovery, the authorization request (PKCE S256,
//! `state`, `nonce`), the callback, the token response and the ID token are parsed and checked
//! here; the caller's HTTP client moves the bytes. With the `std` feature, [`refresh`] runs one
//! refresh at a time for every concurrent caller (P50, §9.9.3 k.6) and [`replay`] is an
//! in-memory DPoP replay store for a resource server (§10.4.3).
//!
//! Every check fails closed: an unknown answer is a refusal, never a session (TI-9). SAML SP
//! helpers belong to their protocol stage; the MCP client helpers are in `mcp::client`
//! (feature `mcp`).

use alloc::string::String;
use core::fmt::Write as _;

pub mod discovery;
pub mod dpop;
pub mod pkce;
#[cfg(feature = "std")]
pub mod refresh;
#[cfg(feature = "std")]
pub mod replay;
pub mod request;
pub mod token;

/// The random source failed; nothing is built from a missing random value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("random-unavailable")]
pub struct RandomUnavailable;

/// The randomness port: fills `out` from a CSPRNG.
pub trait Random {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`RandomUnavailable`].
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable>;
}

/// `N` random bytes as unpadded base64url.
pub(crate) fn random_text<const N: usize>(rng: &impl Random) -> Result<String, RandomUnavailable> {
    let mut b = [0u8; N];
    rng.fill(&mut b)?;
    Ok(access_kernel::json::b64url_encode(&b))
}

/// The class of an OAuth error answer (RFC 6749 §5.2, RFC 9449 §7, OIDC Core §3.1.2.6). An
/// `error` code the SDK does not know is [`OAuthClass::Refused`], its parent (P15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OAuthClass {
    /// `invalid_request`.
    InvalidRequest,
    /// `invalid_client`.
    InvalidClient,
    /// `invalid_grant`: the code or refresh token is spent, expired or revoked.
    InvalidGrant,
    /// `unauthorized_client`.
    UnauthorizedClient,
    /// `unsupported_grant_type`.
    UnsupportedGrantType,
    /// `invalid_scope`.
    InvalidScope,
    /// `access_denied`.
    AccessDenied,
    /// `login_required`, `interaction_required`, `consent_required`, `account_selection_required`.
    InteractionRequired,
    /// `invalid_dpop_proof`.
    InvalidDpopProof,
    /// `use_dpop_nonce`: retry once with the `DPoP-Nonce` the server sent.
    UseDpopNonce,
    /// `server_error`, `temporarily_unavailable`.
    Unavailable,
    /// Any other code: refused, no more is known.
    Refused,
}

impl OAuthClass {
    /// The class of an `error` code.
    #[must_use]
    pub fn of(code: &str) -> Self {
        match code {
            "invalid_request" | "invalid_request_uri" | "invalid_request_object" => {
                Self::InvalidRequest
            }
            "invalid_client" => Self::InvalidClient,
            "invalid_grant" => Self::InvalidGrant,
            "unauthorized_client" => Self::UnauthorizedClient,
            "unsupported_grant_type" | "unsupported_response_type" => Self::UnsupportedGrantType,
            "invalid_scope" => Self::InvalidScope,
            "access_denied" => Self::AccessDenied,
            "login_required"
            | "interaction_required"
            | "consent_required"
            | "account_selection_required" => Self::InteractionRequired,
            "invalid_dpop_proof" => Self::InvalidDpopProof,
            "use_dpop_nonce" => Self::UseDpopNonce,
            "server_error" | "temporarily_unavailable" => Self::Unavailable,
            _ => Self::Refused,
        }
    }
}

/// `application/x-www-form-urlencoded` of one value (RFC 3986 unreserved kept).
pub(crate) fn form_encode(out: &mut String, value: &str) {
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

/// A form body or query from pairs.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        form_encode(&mut out, k);
        out.push('=');
        form_encode(&mut out, v);
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Decodes one form-encoded component; `None` on a broken escape or non-UTF-8.
pub(crate) fn form_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = alloc::vec::Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'%' => {
                let hi = hex(*bytes.get(i.checked_add(1)?)?)?;
                let lo = hex(*bytes.get(i.checked_add(2)?)?)?;
                out.push(hi.checked_mul(16)?.checked_add(lo)?);
                i = i.checked_add(3)?;
            }
            b'+' => {
                out.push(b' ');
                i = i.checked_add(1)?;
            }
            b => {
                out.push(b);
                i = i.checked_add(1)?;
            }
        }
    }
    String::from_utf8(out).ok()
}
