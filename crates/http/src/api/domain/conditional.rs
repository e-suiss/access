//! Optimistic concurrency (OP-65, RFC 9110 §8.8.3, §13.1.1): a resource's version is its strong
//! `ETag`; an update must send `If-Match` naming it (`428` without, `412` on a mismatch).

use access_kernel::json::b64url_encode;

/// Why a conditional update may not go ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Precondition {
    /// No `If-Match`: `428`.
    #[error("If-Match required")]
    Required,
    /// `If-Match` names another version, or the resource does not exist: `412`.
    #[error("If-Match failed")]
    Failed,
}

/// The strong `ETag` of a resource version: an opaque, quoted digest of the resource kind, its
/// id and its version, so tags never reveal or compare across resources.
#[must_use]
pub fn etag(kind: &str, id: &str, version: &[u8]) -> String {
    let mut buf = Vec::new();
    for part in [kind.as_bytes(), id.as_bytes(), version] {
        buf.extend_from_slice(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        buf.extend_from_slice(part);
    }
    let d = suiss_crypto::digest::sha256(&buf);
    let short = d.get(..18).unwrap_or(&d);
    format!("\"{}\"", b64url_encode(short))
}

/// Checks the `If-Match` values against the current strong tag, `None` when the resource does
/// not exist. Weak tags never match (strong comparison, RFC 9110 §13.1.1); `*` matches any
/// existing version.
///
/// # Errors
/// [`Precondition`].
pub fn if_match<'a>(
    values: impl IntoIterator<Item = &'a str>,
    current: Option<&str>,
) -> Result<(), Precondition> {
    let mut seen = false;
    let mut matched = false;
    for value in values {
        for tag in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            seen = true;
            matched |= match (tag, current) {
                ("*", Some(_)) => true,
                (t, Some(c)) => !t.starts_with("W/") && t == c,
                (_, None) => false,
            };
        }
    }
    match (seen, matched) {
        (false, _) => Err(Precondition::Required),
        (true, false) => Err(Precondition::Failed),
        (true, true) => Ok(()),
    }
}
