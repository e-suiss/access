//! Retiring an operation (OP-65 m.2): within a major version only additions; a removal is first
//! announced with `Deprecation` (RFC 9745) and `Sunset` (RFC 8594), and a `Link` to what
//! replaces it.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;

/// When an operation was deprecated and when it goes away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lifecycle {
    /// Deprecated since, Unix seconds.
    pub deprecated_at: i64,
    /// Removed at, Unix seconds.
    pub sunset_at: Option<i64>,
    /// What replaces it, a path or URL.
    pub successor: Option<&'static str>,
}

/// The `Deprecation` value: an RFC 9651 Date, `@<unix seconds>` (RFC 9745 §2.1).
#[must_use]
pub fn deprecation(at: i64) -> String {
    format!("@{at}")
}

/// The `Sunset` value: an HTTP-date (RFC 8594 §3, RFC 9110 §5.6.7).
#[must_use]
pub fn sunset(at: i64) -> Option<String> {
    let t = OffsetDateTime::from_unix_timestamp(at).ok()?;
    let s = t.format(&Rfc2822).ok()?;
    let s = s.strip_suffix(" +0000")?;
    Some(format!("{s} GMT"))
}

impl Lifecycle {
    /// The header fields to send: name and value.
    #[must_use]
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![("deprecation", deprecation(self.deprecated_at))];
        if let Some(s) = self.sunset_at.and_then(sunset) {
            out.push(("sunset", s));
        }
        if let Some(link) = self.successor {
            out.push(("link", format!("<{link}>; rel=\"successor-version\"")));
        }
        out
    }
}
