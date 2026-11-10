//! The realm issuer: an `https` URL fixed when the realm is created and stored on its row; the
//! request's `Host` only selects the realm (TN-10, TN-16, §12.1.2, §17.9.6).

use core::fmt;

/// The longest issuer Access accepts (PD).
pub const MAX_ISSUER: usize = 255;

/// The path prefix of a path-based issuer: `https://<base>/realms/<slug>`.
pub const PATH_PREFIX: &str = "/realms/";

/// Why an issuer or realm base is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssuerError {
    /// Not an `https` URL.
    #[error("not https")]
    Scheme,
    /// The host or port is not a lower-case DNS name with an optional port.
    #[error("bad authority")]
    Authority,
    /// The path has an empty or non-unreserved segment, or a trailing slash.
    #[error("bad path")]
    Path,
    /// Query, fragment or user info present.
    #[error("query, fragment or user info")]
    Extra,
    /// Longer than [`MAX_ISSUER`].
    #[error("too long")]
    Length,
    /// A slug that is not `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$` (TN-16).
    #[error("bad slug")]
    Slug,
}

impl IssuerError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Scheme => "issuer-scheme",
            Self::Authority => "issuer-authority",
            Self::Path => "issuer-path",
            Self::Extra => "issuer-extra",
            Self::Length => "issuer-length",
            Self::Slug => "realm-slug",
        }
    }
}

/// A realm issuer URL: `https`, a lower-case host with an optional port, an optional path of
/// unreserved segments, no trailing slash, no query, fragment or user info. Compared byte for
/// byte (RFC 9207 §2.4, OIDC Discovery §4.3).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Issuer {
    url: String,
    path_at: usize,
}

const SCHEME: &str = "https://";

fn label_ok(label: &str) -> bool {
    let b = label.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b.first().is_some_and(|c| *c != b'-')
        && b.last().is_some_and(|c| *c != b'-')
}

fn host_ok(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && host.split('.').all(label_ok)
}

fn authority_ok(authority: &str) -> bool {
    match authority.split_once(':') {
        None => host_ok(authority),
        Some((host, port)) => {
            host_ok(host)
                && !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|c| c.is_ascii_digit())
                && !port.starts_with('0')
                && port.parse::<u16>().is_ok()
        }
    }
}

fn segment_ok(seg: &str) -> bool {
    !seg.is_empty()
        && seg
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
        && seg != "."
        && seg != ".."
}

/// Checks a realm slug (TN-16, §12.1.2).
///
/// # Errors
/// [`IssuerError::Slug`].
pub fn check_slug(slug: &str) -> Result<(), IssuerError> {
    let b = slug.as_bytes();
    let ok = (3..=63).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b.first().is_some_and(|c| *c != b'-')
        && b.last().is_some_and(|c| *c != b'-');
    if ok { Ok(()) } else { Err(IssuerError::Slug) }
}

impl Issuer {
    /// Parses an issuer.
    ///
    /// # Errors
    /// [`IssuerError`].
    pub fn parse(url: &str) -> Result<Self, IssuerError> {
        if url.len() > MAX_ISSUER {
            return Err(IssuerError::Length);
        }
        let rest = url.strip_prefix(SCHEME).ok_or(IssuerError::Scheme)?;
        if rest.contains(['?', '#', '@']) {
            return Err(IssuerError::Extra);
        }
        let (authority, path) = rest.find('/').map_or((rest, ""), |at| rest.split_at(at));
        if !authority_ok(authority) {
            return Err(IssuerError::Authority);
        }
        if !path.is_empty() {
            let segments = path.strip_prefix('/').ok_or(IssuerError::Path)?;
            if !segments.split('/').all(segment_ok) {
                return Err(IssuerError::Path);
            }
        }
        Ok(Self {
            url: url.to_owned(),
            path_at: SCHEME.len().saturating_add(authority.len()),
        })
    }

    /// The URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Host and optional port.
    #[must_use]
    pub fn authority(&self) -> &str {
        self.url.get(SCHEME.len()..self.path_at).unwrap_or_default()
    }

    /// The path, empty for a host-only issuer.
    #[must_use]
    pub fn path(&self) -> &str {
        self.url.get(self.path_at..).unwrap_or_default()
    }

    /// The URL of an endpoint at `path` (which starts with `/`) under this issuer.
    #[must_use]
    pub fn endpoint(&self, path: &str) -> String {
        let mut out = self.url.clone();
        out.push_str(path);
        out
    }

    /// The URL of an endpoint at `path` under this issuer reached on `port` instead: the mTLS
    /// listener's alias of the endpoint (RFC 8705 §5, OP-155 m.3 (m)).
    #[must_use]
    pub fn endpoint_on_port(&self, port: u16, path: &str) -> String {
        let authority = self.authority();
        let host = match authority.rsplit_once(':') {
            Some((h, p)) if p.bytes().all(|c| c.is_ascii_digit()) => h,
            _ => authority,
        };
        format!("{SCHEME}{host}:{port}{}{path}", self.path())
    }

    /// The RFC 8414 / RFC 9728 well-known URL path of `suffix`: inserted between the host and
    /// the issuer's path (RFC 8414 §3.1).
    #[must_use]
    pub fn well_known_inserted(&self, suffix: &str) -> String {
        format!("/.well-known/{suffix}{}", self.path())
    }

    /// The OIDC Discovery path: appended to the issuer's path (OIDC Discovery §4).
    #[must_use]
    pub fn well_known_appended(&self, suffix: &str) -> String {
        format!("{}/.well-known/{suffix}", self.path())
    }

    /// Whether a request whose authority is `authority` reached this issuer's origin; the
    /// default port 443 is ignored and the comparison is ASCII case-insensitive.
    #[must_use]
    pub fn serves(&self, authority: &str) -> bool {
        let a = authority.strip_suffix(":443").unwrap_or(authority);
        a.eq_ignore_ascii_case(self.authority())
    }
}

impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Issuer").field(&self.url).finish()
    }
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

/// How a new realm's issuer is formed (TN-10, §12.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssuerStyle {
    /// `https://<slug>.<base>`, the default: one origin per realm.
    Subdomain,
    /// `https://<base>/realms/<slug>`: supported, not the default; both well-known variants are
    /// served.
    Path,
}

/// The configured origin realm issuers are formed under: `https://<host>[:port]`, no path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmBase(Issuer);

impl RealmBase {
    /// Parses a base.
    ///
    /// # Errors
    /// [`IssuerError`]; a base with a path is [`IssuerError::Path`].
    pub fn parse(url: &str) -> Result<Self, IssuerError> {
        let issuer = Issuer::parse(url)?;
        if !issuer.path().is_empty() {
            return Err(IssuerError::Path);
        }
        Ok(Self(issuer))
    }

    /// The base URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The issuer of a new realm with `slug`; fixed from then on (TN-16).
    ///
    /// # Errors
    /// [`IssuerError`].
    pub fn issuer(&self, slug: &str, style: IssuerStyle) -> Result<Issuer, IssuerError> {
        check_slug(slug)?;
        let url = match style {
            IssuerStyle::Subdomain => format!("{SCHEME}{slug}.{}", self.0.authority()),
            IssuerStyle::Path => format!("{}{PATH_PREFIX}{slug}", self.0.as_str()),
        };
        Issuer::parse(&url)
    }
}

/// The `iss` authorization response parameter (RFC 9207): `uri` with
/// `iss=<issuer>` appended to its query, form-encoded. Every authorization response carries it,
/// errors included, byte-identical to the metadata `issuer` (AG-7, TN-11).
#[must_use]
pub fn with_iss(uri: &str, issuer: &Issuer) -> String {
    let mut out = String::with_capacity(
        uri.len()
            .saturating_add(issuer.as_str().len().saturating_mul(3)),
    );
    out.push_str(uri);
    out.push(if uri.contains('?') { '&' } else { '?' });
    out.push_str("iss=");
    form_encode(issuer.as_str(), &mut out);
    out
}

/// `application/x-www-form-urlencoded` of `value` into `out`.
pub fn form_encode(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(char::from(b));
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(
                    HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
                ));
                out.push(char::from(
                    HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0'),
                ));
            }
        }
    }
}
