//! The account BFF's pure rules (OP-63 sans-I/O): its security headers, its CSRF token, which
//! ADP reads and writes it forwards, what a read must name, and the read proof's intent.

use access_kernel::digest::Digest;
use axum::http::{HeaderMap, HeaderValue, Method};
use suiss_crypto::digest::context_digest;
use suiss_crypto::secret::Secret;

/// `Content-Security-Policy` of the account pages (OP-153 m.3 (t), (w), TN-106): its own
/// scripts, styles and API only; `'wasm-unsafe-eval'` lets the Kernel's WebAssembly compile,
/// nothing else is evaluated. A realm logo is an `<img>` from the page's own origin.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'";

/// The headers every account page, asset and API answer carries (§14.5, OP-153 m.3 (t): the
/// Authority hub is never embedded, `frame-ancestors 'none'`).
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

/// The account pages' PEP at ADP (OP-141 m.23 (a)): every statement the browser signs for a hub
/// read or write names it, so ADP tells these requests apart from every product's.
pub const ACCOUNT_PEP: &str = "access-account";

/// The double-submit CSRF cookie (TN-131).
pub const CSRF_COOKIE: &str = "__Host-access-account-csrf";

/// The request header carrying the CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

const CSRF_CONTEXT: &str = "access/account-csrf/v1";

/// The digest context of an account read proof.
pub const READ_CONTEXT: &str = "access/account-read/v1";

/// The session's CSRF token: a digest of the login session cookie, so it changes with the
/// session and a page on another origin cannot know it.
#[must_use]
pub fn csrf_token(cookie: &Secret<[u8; 32]>) -> String {
    access_kernel::json::b64url_encode(&context_digest(CSRF_CONTEXT, cookie.expose()).0)
}

/// Whether the header and the cookie both carry the session's CSRF token (constant time).
#[must_use]
pub fn csrf_ok(cookie: &Secret<[u8; 32]>, presented: &str, double: &str) -> bool {
    let want = Secret::new(context_digest(CSRF_CONTEXT, cookie.expose()).0);
    match (
        access_kernel::json::b64url_decode(presented),
        access_kernel::json::b64url_decode(double),
    ) {
        (Ok(p), Ok(d)) => want.ct_eq_bytes(&p) & want.ct_eq_bytes(&d),
        _ => false,
    }
}

/// The CSRF cookie: readable by the page's script, never sent cross-site.
#[must_use]
pub fn csrf_cookie(token: &str) -> String {
    format!("{CSRF_COOKIE}={token}; Path=/; Secure; SameSite=Strict")
}

/// The hub's search kinds (L1-ADP-16, OP-153 m.8 (a), (b)): the inventory, the uses, the
/// changes, and the revocation preview of S4.
pub const SEARCH_KINDS: [&str; 4] = ["inventory", "activity", "changes", "revocation-impact"];

/// What a forwarded ADP request is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forwarded {
    /// A read: a hub search or an explanation, in `check` mode.
    Read,
    /// The single write: an `evaluation` in `commit` mode (TN-110).
    Commit,
}

/// What `/account/api/proxy/adp/{rest}` may name; anything else is not found.
#[must_use]
pub fn forwarded(rest: &str) -> Option<Forwarded> {
    if rest == "evaluation" {
        return Some(Forwarded::Commit);
    }
    if rest == "explain" {
        return Some(Forwarded::Read);
    }
    rest.strip_prefix("search/")
        .filter(|k| SEARCH_KINDS.contains(k))
        .map(|_| Forwarded::Read)
}

/// Whether a read body carries a statement at all: the hub reads only as the session's own
/// Instance, never as the anonymous reader (OP-153 m.3 (w)).
#[must_use]
pub fn carries_ais(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/context/ais")
                .and_then(serde_json::Value::as_str)
                .map(|s| !s.is_empty())
        })
        .unwrap_or(false)
}

/// What a read proof binds: the method and the path as the BFF sees them.
#[must_use]
pub fn read_intent(method: &Method, path: &str) -> Digest {
    let mut canonical = Vec::with_capacity(path.len().saturating_add(8));
    canonical.extend_from_slice(method.as_str().as_bytes());
    canonical.push(b' ');
    canonical.extend_from_slice(path.as_bytes());
    Digest(context_digest(READ_CONTEXT, &canonical).0)
}

/// The API base of a page path: `/realms/{slug}/account/api` for a path issuer, else
/// `/account/api`.
#[must_use]
pub fn api_base(slug: Option<&str>) -> String {
    slug.map_or_else(
        || String::from("/account/api"),
        |s| format!("/realms/{s}/account/api"),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-153 m.3 (w), TN-110
    #[test]
    fn only_hub_reads_and_the_commit_are_forwarded() {
        assert_eq!(forwarded("evaluation"), Some(Forwarded::Commit));
        assert_eq!(forwarded("explain"), Some(Forwarded::Read));
        for k in SEARCH_KINDS {
            assert_eq!(forwarded(&format!("search/{k}")), Some(Forwarded::Read));
        }
        for bad in [
            "search/subject",
            "search/",
            "eligibility:check",
            "audit/export",
            "publications",
            "evaluations",
            "search/inventory/x",
        ] {
            assert_eq!(forwarded(bad), None, "{bad}");
        }
    }

    // TN-131
    #[test]
    fn the_csrf_token_is_the_sessions_own() {
        let a = Secret::new([1u8; 32]);
        let b = Secret::new([2u8; 32]);
        let t = csrf_token(&a);
        assert!(csrf_ok(&a, &t, &t));
        assert!(!csrf_ok(&b, &t, &t));
        assert!(!csrf_ok(&a, &t, "x"));
        assert!(!csrf_ok(&a, "", &t));
        assert!(csrf_cookie(&t).contains("SameSite=Strict"));
    }

    // OP-153 m.3 (w)
    #[test]
    fn a_hub_read_needs_a_statement() {
        assert!(carries_ais(br#"{"context":{"ais":"x"}}"#));
        assert!(!carries_ais(br#"{"context":{"ais":""}}"#));
        assert!(!carries_ais(br#"{"context":{}}"#));
        assert!(!carries_ais(b"nope"));
    }

    #[test]
    fn read_proofs_bind_the_request() {
        let a = read_intent(&Method::POST, "/account/api/intents");
        assert_ne!(a, read_intent(&Method::POST, "/console/api/intents"));
        assert_ne!(
            a,
            crate::console::domain::read_intent(&Method::POST, "/account/api/intents")
        );
        assert_eq!(api_base(Some("acme")), "/realms/acme/account/api");
        assert_eq!(api_base(None), "/account/api");
    }
}
