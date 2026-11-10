//! The one request-path canonicalization (TN-113, §12.5.1): every request path is checked here
//! before routing, so the router and every path-based permission compare the same bytes. A path
//! has exactly one accepted spelling; any other spelling of it is refused, never rewritten.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::problem::Problem;

/// Longest accepted request path, in bytes.
pub const MAX_PATH: usize = 2048;

/// Why a path is not canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// Empty, relative or longer than [`MAX_PATH`].
    #[error("path shape")]
    Shape,
    /// A `.` or `..` segment, also percent-encoded.
    #[error("dot segment")]
    Dot,
    /// An empty segment (`//`).
    #[error("empty segment")]
    Empty,
    /// A byte outside the RFC 3986 path characters, a backslash or a control character.
    #[error("character")]
    Character,
    /// Malformed percent-encoding, lower-case hex, or an encoded character that has a plain
    /// spelling or would change the path's structure (`/`, `\`, `%`, `.`).
    #[error("percent-encoding")]
    Encoding,
}

const fn unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

const fn sub_delim(c: u8) -> bool {
    matches!(
        c,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

const fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

fn segment(s: &[u8]) -> Result<(), PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s == b"." || s == b".." {
        return Err(PathError::Dot);
    }
    let mut i = 0_usize;
    while let Some(&c) = s.get(i) {
        if c == b'%' {
            let (Some(h), Some(l)) = (
                s.get(i.saturating_add(1)).copied().and_then(hex),
                s.get(i.saturating_add(2)).copied().and_then(hex),
            ) else {
                return Err(PathError::Encoding);
            };
            let decoded = h.wrapping_mul(16).wrapping_add(l);
            let plain = unreserved(decoded) || sub_delim(decoded) || matches!(decoded, b':' | b'@');
            if plain || matches!(decoded, b'/' | b'\\' | b'%') || decoded < 0x20 || decoded == 0x7f
            {
                return Err(PathError::Encoding);
            }
            i = i.saturating_add(3);
            continue;
        }
        if !(unreserved(c) || sub_delim(c) || matches!(c, b':' | b'@')) {
            return Err(PathError::Character);
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Checks that `path` is canonical: absolute, at most [`MAX_PATH`] bytes, no `.`/`..` or empty
/// segment, only RFC 3986 path characters, and percent-encoding only in upper-case hex for bytes
/// that have no plain spelling and do not change the structure. `/` alone is canonical.
///
/// # Errors
/// [`PathError`].
pub fn check(path: &str) -> Result<(), PathError> {
    let bytes = path.as_bytes();
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return Err(PathError::Shape);
    };
    if bytes.len() > MAX_PATH {
        return Err(PathError::Shape);
    }
    if rest.is_empty() {
        return Ok(());
    }
    rest.split(|&c| c == b'/').try_for_each(segment)
}

/// Envoy's forward-auth check path (OP-156 m.15 (f)). What follows it is the application's own
/// path, carried as data the way `X-Original-URI` carries it for Nginx; it routes nowhere in
/// Access, and the forward-auth rules refuse every ambiguous spelling of it (OP-156 m.15 (d)).
/// An application path such as `/` or `/docs/` ends in `/`, which no Access path may.
pub const FORWARDED_PATH_PREFIX: &str = "/proxy/v1/check/envoy/";

/// The part of `path` that names an Access route: all of it, or Envoy's check path alone.
#[must_use]
pub fn own_part(path: &str) -> &str {
    if path.starts_with(FORWARDED_PATH_PREFIX) {
        FORWARDED_PATH_PREFIX.trim_end_matches('/')
    } else {
        path
    }
}

/// Refuses a request whose path is not canonical before it reaches a route (TN-113).
pub async fn canonical(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if check(own_part(path)).is_err() || path.len() > MAX_PATH {
        return Problem::new(StatusCode::BAD_REQUEST, "path-not-canonical", "Bad Request")
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests;
