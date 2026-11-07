//! The BFF's pure rules (OP-63 sans-I/O): the console's security headers, the request origin
//! and CSRF checks, what the proxies forward, and the read proof a browser AIS gives.

use access_kernel::ais::{CONTENT_TYPE, SKEW_MS, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{self, KeySet, PublicKey};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::digest::context_digest;

/// `Content-Security-Policy` of the console (TN-131): nothing but its own scripts, styles and
/// API; `'wasm-unsafe-eval'` lets the Kernel's WebAssembly compile, and nothing else is
/// evaluated.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'";

/// The headers every console page, asset and API answer carries (TN-131, §14.5).
/// Cross-origin isolation is safe: the Kernel's WebAssembly is a same-origin asset.
pub const SECURITY_HEADERS: [(&str, &str); 8] = [
    ("content-security-policy", CONTENT_SECURITY_POLICY),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-embedder-policy", "require-corp"),
    ("cross-origin-resource-policy", "same-origin"),
    (
        "permissions-policy",
        "publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()",
    ),
    ("x-frame-options", "DENY"),
];

/// Adds [`SECURITY_HEADERS`], replacing any the inner answer set.
pub fn secure(h: &mut HeaderMap) {
    for (name, value) in SECURITY_HEADERS {
        h.insert(name, HeaderValue::from_static(value));
    }
}

/// The header carrying the browser's AIS (OP-151 m.3 (e)); the management API's own name.
pub const AIS_HEADER: HeaderName = HeaderName::from_static(crate::api::domain::caller::AIS_HEADER);

/// The digest context of a console read proof.
pub const READ_CONTEXT: &str = "access/console-read/v1";

/// Whether a method changes something and so needs the CSRF checks.
#[must_use]
pub fn unsafe_method(m: &Method) -> bool {
    !matches!(*m, Method::GET | Method::HEAD)
}

/// Why a request is refused before anything else looks at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Passes.
    Pass,
    /// `Origin` is missing or not the configured management origin (TN-131: the `Host` header
    /// is never consulted).
    Origin,
    /// `Sec-Fetch-Site` says another site sent it.
    CrossSite,
}

/// The origin gate (TN-131): a state-changing request names the configured origin in
/// `Origin`; any request a browser marks as cross-site is refused.
#[must_use]
pub fn gate(headers: &HeaderMap, method: &Method, origin: &str) -> Gate {
    let site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    if matches!(site, Some(s) if s != "same-origin" && s != "none") {
        return Gate::CrossSite;
    }
    if unsafe_method(method) {
        let presented: Vec<&str> = headers
            .get_all(axum::http::header::ORIGIN)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if presented != [origin] {
            return Gate::Origin;
        }
    }
    Gate::Pass
}

/// The request headers the admin proxy passes on; everything else (cookies, `Authorization`,
/// `DPoP`, forwarding headers) stays at the BFF.
pub const ADMIN_FORWARDED: [&str; 6] = [
    "content-type",
    "accept",
    "idempotency-key",
    "if-match",
    "if-none-match",
    crate::api::domain::caller::AIS_HEADER,
];

/// The request headers the ADP proxy passes on: its AIS travels in the body (§9.5).
pub const ADP_FORWARDED: [&str; 2] = ["content-type", "accept"];

/// The response headers the proxies hand back to the console.
pub const RETURNED: [&str; 9] = [
    "content-type",
    "etag",
    "link",
    "location",
    "ratelimit",
    "ratelimit-policy",
    "retry-after",
    "request-id",
    "www-authenticate",
];

/// The ADP reads the console may ask for (TN-128): explain, search and the eligibility check.
/// No evaluation is forwarded, so nothing through the BFF is ever recorded or committed.
#[must_use]
pub fn adp_read(rest: &str) -> bool {
    if rest == "explain" || rest == "eligibility:check" {
        return true;
    }
    rest.strip_prefix("search/").is_some_and(|kind| {
        !kind.is_empty()
            && kind.len() <= 64
            && kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    })
}

/// Why a forwarded ADP read is refused (TN-128, OP-151 m.12 (e)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadRefusal {
    /// The body is not one ADP would read; ADP's own protocol error, with the body it is in.
    Malformed(crate::adp::domain::AdpError, crate::adp::domain::Body),
    /// Not the session's own: another domain, another subject than the session's Party, or an
    /// AIS by another key than the session's device Instance.
    Foreign,
}

/// What the session's ADP reads may name (TN-128, OP-151 m.12 (e)): the session's domain only;
/// an eligibility check only for the session's own Party, which `party` is once bound; an AIS,
/// when the body carries one, only by the session's device Instance `instance`. The body is
/// read with ADP's own decoders, so the BFF and ADP see the same request.
///
/// # Errors
/// [`ReadRefusal`].
pub fn adp_read_scope(
    rest: &str,
    body: &[u8],
    max_len: usize,
    domain: &Digest,
    party: Option<[u8; 16]>,
    instance: Option<&[u8; 32]>,
) -> Result<(), ReadRefusal> {
    use crate::adp::domain::{Body, decode_eligibility, decode_explain, decode_search};
    let (decoded, subject) = if rest == "eligibility:check" {
        let (d, subject) = decode_eligibility(body, max_len)
            .map_err(|e| ReadRefusal::Malformed(e, Body::Eligibility))?;
        (d, Some(subject))
    } else if rest == "explain" {
        let (d, _) =
            decode_explain(body, max_len).map_err(|e| ReadRefusal::Malformed(e, Body::Context))?;
        (d, None)
    } else if let Some(kind) = rest.strip_prefix("search/") {
        let (d, _, _) = decode_search(body, max_len, kind)
            .map_err(|e| ReadRefusal::Malformed(e, Body::Context))?;
        (d, None)
    } else {
        return Err(ReadRefusal::Foreign);
    };
    if decoded.request.domain != *domain {
        return Err(ReadRefusal::Foreign);
    }
    if let Some(subject) = subject
        && party != Some(subject.0)
    {
        return Err(ReadRefusal::Foreign);
    }
    if let Some(ais) = &decoded.ais {
        match (crate::api::domain::caller::ais_kid(ais), instance) {
            (Ok(kid), Some(own)) if kid == *own => {}
            _ => return Err(ReadRefusal::Foreign),
        }
    }
    Ok(())
}

/// Whether `rest` is a path the admin proxy may name under `/admin/v1/`: plain segments, no dot
/// segments, no encoded slashes or backslashes, no empty segments.
#[must_use]
pub fn admin_path(rest: &str) -> bool {
    !rest.is_empty()
        && rest.len() <= 1024
        && rest.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && !s.contains('%')
                && !s.contains('\\')
                && s.bytes().all(|b| b.is_ascii_graphic())
        })
}

/// What a read proof binds: the method and the path with its query, as the management API
/// sees them.
#[must_use]
pub fn read_intent(method: &Method, path_and_query: &str) -> Digest {
    let mut canonical = Vec::with_capacity(path_and_query.len().saturating_add(8));
    canonical.extend_from_slice(method.as_str().as_bytes());
    canonical.push(b' ');
    canonical.extend_from_slice(path_and_query.as_bytes());
    Digest(context_digest(READ_CONTEXT, &canonical).0)
}

/// Why a read proof is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The session has no device Instance yet.
    #[error("no instance")]
    NoInstance,
    /// Not signed by the session's Instance key, not a `check` statement for the session's
    /// domain and this request, or not signed within the skew.
    #[error("rejected")]
    Rejected,
}

/// The statement `sign1` carries, verified with the session's device Instance key, signed
/// within [`SKEW_MS`] of now and for the session's domain.
fn session_statement(
    sign1: &[u8],
    instance: Option<(&[u8; 32], &PublicKey)>,
    domain: &Digest,
    now_ms: u64,
) -> Result<Statement, ProofError> {
    let (kid, key) = instance.ok_or(ProofError::NoInstance)?;
    let mut keys = KeySet::default();
    keys.insert(*kid, key.clone())
        .map_err(|_| ProofError::Rejected)?;
    keys.allowed.extend([
        cose::Algorithm::Esp256,
        cose::Algorithm::Es256,
        cose::Algorithm::Ed25519,
    ]);
    let verified = cose::verify_sign1(&PureBackend, sign1, &keys, CONTENT_TYPE)
        .map_err(|_| ProofError::Rejected)?;
    let value =
        dcbor::decode(&verified.payload, Limits::CEILING).map_err(|_| ProofError::Rejected)?;
    let s = Statement::from_value(&value).map_err(|_| ProofError::Rejected)?;
    let fresh = s.iat <= now_ms.saturating_add(SKEW_MS) && now_ms <= s.iat.saturating_add(SKEW_MS);
    if s.domain != *domain || !fresh {
        return Err(ProofError::Rejected);
    }
    Ok(s)
}

/// A read proof (TN-128, OP-151 m.3 (e)): the browser's AIS, signed with the session's device
/// Instance key, in `check` mode (CT0), for the session's domain, over [`read_intent`] of this
/// request, signed within [`SKEW_MS`] of now. Only then does the BFF attach the session's read
/// token: a cookie without the browser's key reads nothing.
///
/// # Errors
/// [`ProofError`].
pub fn verify_read_proof(
    sign1: &[u8],
    instance: Option<(&[u8; 32], &PublicKey)>,
    domain: &Digest,
    intent: &Digest,
    now_ms: u64,
) -> Result<Statement, ProofError> {
    let s = session_statement(sign1, instance, domain, now_ms)?;
    if s.mode != Mode::Check || s.intent != *intent {
        return Err(ProofError::Rejected);
    }
    Ok(s)
}

/// The ADP writes the console may forward (TN-110, TN-128, OP-151 m.19): one `evaluation` and
/// the export of an allowed `access.audit_export` Exercise, each a `commit` the browser signed.
#[must_use]
pub fn adp_commit(rest: &str) -> bool {
    rest == "evaluation" || rest == "audit/export"
}

/// A forwarded commit (TN-110, TN-128, MD-14): the body's `context` is in `commit` mode for the
/// session's domain and carries an AIS signed with the session's device Instance key, in
/// `commit` mode, for that domain, within [`SKEW_MS`] of now. The BFF never signs; the authority
/// plane still verifies the statement against the intent, nonce and PEP.
///
/// # Errors
/// [`ProofError`].
pub fn verify_commit(
    body: &[u8],
    instance: Option<(&[u8; 32], &PublicKey)>,
    domain: &Digest,
    now_ms: u64,
) -> Result<Statement, ProofError> {
    if instance.is_none() {
        return Err(ProofError::NoInstance);
    }
    let root: serde_json::Value = serde_json::from_slice(body).map_err(|_| ProofError::Rejected)?;
    let context = root.get("context").ok_or(ProofError::Rejected)?;
    let text = |name: &str| context.get(name).and_then(serde_json::Value::as_str);
    let ais = text("ais")
        .and_then(|a| access_kernel::json::b64url_decode(a).ok())
        .ok_or(ProofError::Rejected)?;
    let named = text("domain").and_then(|d| access_kernel::json::b64url_decode(d).ok());
    if text("mode") != Some("commit") || named.as_deref() != Some(&domain.0[..]) {
        return Err(ProofError::Rejected);
    }
    let s = session_statement(&ais, instance, domain, now_ms)?;
    if s.mode != Mode::Commit {
        return Err(ProofError::Rejected);
    }
    Ok(s)
}

/// Copies the headers named in `names` from `from`.
#[must_use]
pub fn pick(from: &HeaderMap, names: &[&str]) -> Vec<(HeaderName, HeaderValue)> {
    names
        .iter()
        .filter_map(|n| HeaderName::from_bytes(n.as_bytes()).ok())
        .flat_map(|n| {
            from.get_all(&n)
                .iter()
                .map(|v| (n.clone(), v.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests;
