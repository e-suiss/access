//! Size classes for disclosure-sensitive answers (CR-40 m.2, m.3, SAI-43, OP-159 m.3 (s)): the
//! [AU] check and explain answers and the [ID] identifier-first, recovery and registration
//! answers are padded to 1, 2, 4, 8, 16, 32 or 64 KiB with spaces after the JSON value. The
//! content never changes (INV-27) and no delay is added (SEC31): an answer about a basis or an
//! account the caller may not see has the length class of one that does not exist.

use axum::body::{Body, HttpBody as _, to_bytes};
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

/// The size classes, bytes (CR-40 m.3, PD).
pub const CLASSES: [usize; 7] = [
    1024,
    2 * 1024,
    4 * 1024,
    8 * 1024,
    16 * 1024,
    32 * 1024,
    64 * 1024,
];

/// The [AU] answers that are padded, by exact path.
const AUTHORITY: [&str; 4] = [
    "/access/v1/evaluation",
    "/access/v1/evaluations",
    "/access/v1/explain",
    "/access/v1/eligibility:check",
];

/// The [ID] answers that are padded, by path under the realm's host or `/realms/{slug}`: `*`
/// is one path segment.
const IDENTITY: [&str; 8] = [
    "/v1/login/flows",
    "/v1/login/flows/*",
    "/v1/login/link/preview",
    "/v1/login/link/confirm",
    "/v1/recovery",
    "/v1/recovery/*",
    "/v1/recovery/*/extension",
    "/v1/recovery/intents/*",
];

fn matches(pattern: &str, path: &str) -> bool {
    let mut p = pattern.split('/');
    let mut q = path.split('/');
    loop {
        match (p.next(), q.next()) {
            (None, None) => return true,
            (Some("*"), Some(s)) if !s.is_empty() => {}
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

/// Whether the answer to `path` is padded.
#[must_use]
pub fn padded(path: &str) -> bool {
    if AUTHORITY.contains(&path) {
        return true;
    }
    let realm = path
        .strip_prefix("/realms/")
        .and_then(|rest| rest.find('/').and_then(|at| rest.get(at..)))
        .unwrap_or(path);
    IDENTITY.iter().any(|p| matches(p, realm))
}

/// The size class of a body of `len` bytes; `None` above the largest class.
#[must_use]
pub fn class_of(len: usize) -> Option<usize> {
    CLASSES.iter().copied().find(|c| len <= *c)
}

fn json(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            let m = m.trim();
            m.eq_ignore_ascii_case("application/json") || m.ends_with("+json")
        })
}

/// The padding layer: pads a JSON answer to a disclosure-sensitive path to its size class. An
/// answer that is not JSON, is encoded, has no exact length or is larger than 64 KiB passes as
/// it is.
pub async fn pad(request: Request, next: Next) -> Response {
    let wanted = padded(request.uri().path());
    let response = next.run(request).await;
    if !wanted
        || !json(&response)
        || response.status() == StatusCode::NO_CONTENT
        || response.headers().contains_key(header::CONTENT_ENCODING)
    {
        return response;
    }
    let Some(len) = response
        .body()
        .size_hint()
        .exact()
        .and_then(|n| usize::try_from(n).ok())
    else {
        return response;
    };
    let Some(class) = class_of(len) else {
        return response;
    };
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, class).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let mut out = Vec::with_capacity(class);
    out.extend_from_slice(&bytes);
    out.resize(class, b' ');
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(class));
    Response::from_parts(parts, Body::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-40 m.3, SAI-43
    #[test]
    fn the_sensitive_paths_and_classes() {
        assert!(padded("/access/v1/explain"));
        assert!(padded("/v1/login/flows"));
        assert!(padded("/realms/acme/v1/login/flows/flw_1"));
        assert!(padded("/v1/recovery/rcv_1/extension"));
        assert!(!padded("/v1/login/flows/flw_1/extra"));
        assert!(!padded("/v1/login/flows/"));
        assert!(!padded("/access/v1/search/subject"));
        assert!(!padded("/v1/account/preferences"));
        assert_eq!(class_of(0), Some(1024));
        assert_eq!(class_of(1024), Some(1024));
        assert_eq!(class_of(1025), Some(2048));
        assert_eq!(class_of(64 * 1024), Some(64 * 1024));
        assert_eq!(class_of(64 * 1024 + 1), None);
    }
}
