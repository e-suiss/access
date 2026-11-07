//! Listing (OP-65, TN-112, §13.7.4): query parameters an endpoint names and nothing else, page
//! size 1 to 100, an opaque cursor sealed over the next position and bound to the list, and the
//! RFC 8288 `Link` header to the next page. There are no page numbers or offsets.

use std::collections::BTreeMap;

/// The page size parameter.
pub const PAGE_SIZE: &str = "page[size]";

/// The cursor parameter.
pub const CURSOR: &str = "cursor";

/// The filter parameter (SCIM subset, TN-112).
pub const FILTER: &str = "filter";

/// Largest page (§13.7.4).
pub const MAX_PAGE: u32 = 100;

/// Page size when none is asked for.
pub const DEFAULT_PAGE: u32 = 50;

/// Longest query string read.
pub const MAX_QUERY: usize = 4096;

/// Why a query is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// A parameter the endpoint does not take, one given twice, or a malformed query.
    #[error("unknown query parameter")]
    Unknown,
    /// `page[size]` outside 1 to 100.
    #[error("page size")]
    PageSize,
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0_usize;
    while let Some(&c) = bytes.get(at) {
        match c {
            b'%' => {
                let high = hex(*bytes.get(at.saturating_add(1))?)?;
                let low = hex(*bytes.get(at.saturating_add(2))?)?;
                out.push(high.wrapping_mul(16).wrapping_add(low));
                at = at.saturating_add(3);
            }
            b'+' => {
                out.push(b' ');
                at = at.saturating_add(1);
            }
            _ => {
                out.push(c);
                at = at.saturating_add(1);
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-encodes `s` for a query component: unreserved characters stay, the rest is `%XX`.
#[must_use]
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push_str(&super::trace::to_hex(&[b]).to_ascii_uppercase());
        }
    }
    out
}

/// The query's parameters, each named in `allowed` and given once.
///
/// # Errors
/// [`QueryError::Unknown`].
pub fn parameters(
    query: Option<&str>,
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, QueryError> {
    let mut out = BTreeMap::new();
    let Some(q) = query.filter(|q| !q.is_empty()) else {
        return Ok(out);
    };
    if q.len() > MAX_QUERY {
        return Err(QueryError::Unknown);
    }
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(k), Some(v)) = (decode(k), decode(v)) else {
            return Err(QueryError::Unknown);
        };
        if !allowed.contains(&k.as_str()) || out.insert(k, v).is_some() {
            return Err(QueryError::Unknown);
        }
    }
    Ok(out)
}

/// The page size asked for, or [`DEFAULT_PAGE`].
///
/// # Errors
/// [`QueryError::PageSize`].
pub fn page_size(params: &BTreeMap<String, String>) -> Result<u32, QueryError> {
    let Some(v) = params.get(PAGE_SIZE) else {
        return Ok(DEFAULT_PAGE);
    };
    let canonical = !v.is_empty() && !v.starts_with('0') && v.bytes().all(|b| b.is_ascii_digit());
    match v.parse::<u32>() {
        Ok(n) if canonical && (1..=MAX_PAGE).contains(&n) => Ok(n),
        _ => Err(QueryError::PageSize),
    }
}

/// The context a cursor is sealed under: the list's route and surface instance and the
/// parameters other than the cursor, so a cursor works only for the list that issued it.
#[must_use]
pub fn cursor_context(route: &str, scope: &str, params: &BTreeMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [
        b"access/admin-cursor/v1".as_slice(),
        route.as_bytes(),
        scope.as_bytes(),
    ] {
        out.extend_from_slice(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        out.extend_from_slice(part);
    }
    for (k, v) in params.iter().filter(|(k, _)| k.as_str() != CURSOR) {
        for part in [k.as_bytes(), v.as_bytes()] {
            out.extend_from_slice(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            out.extend_from_slice(part);
        }
    }
    out
}

/// The RFC 8288 `Link` value to the next page of `path` with `params` and `cursor`.
#[must_use]
pub fn next_link(path: &str, params: &BTreeMap<String, String>, cursor: &str) -> String {
    let mut query: Vec<String> = params
        .iter()
        .filter(|(k, _)| k.as_str() != CURSOR)
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect();
    query.push(format!("{CURSOR}={}", encode(cursor)));
    format!("<{path}?{}>; rel=\"next\"", query.join("&"))
}
