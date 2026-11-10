//! The four forward-auth protocols (IDP-30 (1), OP-156 m.3 (l)): how each engine names the
//! request it asks about and how it reads the answer. Sans-I/O: headers in, headers out.
//!
//! - Nginx `auth_request` passes the request in `X-Original-Method`, `X-Original-URI` and
//!   `X-Forwarded-Host`, and takes only `2xx`, `401` and `403`; a sign-in is `401` with
//!   `Location` and `Set-Cookie`, which its `error_page` turns into the redirect.
//! - Traefik `forwardAuth` and Caddy `forward_auth` pass `X-Forwarded-Method`, `X-Forwarded-Uri`
//!   and `X-Forwarded-Host`, and return any other answer to the browser as it is.
//! - Envoy `ext_authz` in HTTP service mode keeps the method and appends the original path to
//!   the check path; it also returns a non-`200` answer as it is, and removes the headers
//!   `x-envoy-auth-headers-to-remove` names. There is no gRPC mode (OP-155 m.3 (u)).
//!
//! The identity headers an allowed request carries to the application are only ever the ones
//! this answer sets: every engine's configuration overwrites or removes them from what the
//! client sent.

/// One forward-auth protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Engine {
    /// Nginx `auth_request`.
    Nginx,
    /// Traefik `forwardAuth`.
    Traefik,
    /// Caddy `forward_auth`.
    Caddy,
    /// Envoy `ext_authz`, HTTP service mode.
    Envoy,
}

/// Every engine, in the order of `/proxy/v1/check/{engine}`.
pub const ENGINES: [Engine; 4] = [Engine::Nginx, Engine::Traefik, Engine::Caddy, Engine::Envoy];

/// The application token header (OP-156 m.3 (l)).
pub const IDENTITY_HEADER: &str = "access-identity";

/// The plain identity headers, sent only under `idp.proxy.plain_headers` (OP-156 m.3 (l)).
pub const PLAIN_HEADERS: [&str; 2] = ["x-access-user", "x-access-email"];

/// Envoy's list of request headers to remove before the request goes upstream.
pub const ENVOY_REMOVE: &str = "x-envoy-auth-headers-to-remove";

/// Longest forwarded URI read.
pub const MAX_URI: usize = 8192;

/// Longest forwarded host read.
pub const MAX_HOST: usize = 253;

impl Engine {
    /// The engine `word` names.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        ENGINES.into_iter().find(|e| e.word() == word)
    }

    /// Its path word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Nginx => "nginx",
            Self::Traefik => "traefik",
            Self::Caddy => "caddy",
            Self::Envoy => "envoy",
        }
    }

    /// The status of a redirect answer: Nginx `auth_request` cannot pass a `3xx`.
    #[must_use]
    pub const fn redirect_status(self) -> u16 {
        match self {
            Self::Nginx => 401,
            Self::Traefik | Self::Caddy | Self::Envoy => 302,
        }
    }
}

/// The request a proxy asks about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forwarded {
    /// Its method, upper case.
    pub method: String,
    /// The application host it was sent to, lower case, with its port when it named one.
    pub host: String,
    /// Its path.
    pub path: String,
    /// Its query, without `?`.
    pub query: Option<String>,
}

impl Forwarded {
    /// The path and query as the browser sent them.
    #[must_use]
    pub fn uri(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.clone(),
        }
    }

    /// Whether the method changes nothing (RFC 9110 §9.2.1).
    #[must_use]
    pub fn safe(&self) -> bool {
        matches!(self.method.as_str(), "GET" | "HEAD" | "OPTIONS")
    }
}

/// Why the forwarded request cannot be read; the check refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    /// No method, or not an HTTP token.
    #[error("forwarded method")]
    Method,
    /// No host, or not a host name.
    #[error("forwarded host")]
    Host,
    /// No URI, or not an origin-form path.
    #[error("forwarded uri")]
    Uri,
}

impl ForwardError {
    /// The stable reason word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Method => "forwarded-method",
            Self::Host => "forwarded-host",
            Self::Uri => "forwarded-uri",
        }
    }
}

fn method_ok(m: &str) -> bool {
    (1..=16).contains(&m.len()) && m.bytes().all(|b| b.is_ascii_uppercase())
}

fn host_of(h: &str) -> Option<String> {
    let h = h.trim().to_ascii_lowercase();
    let ok = (1..=MAX_HOST).contains(&h.len())
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
        && !h.starts_with(['.', '-', ':']);
    ok.then_some(h)
}

/// The path and query of an origin-form URI (RFC 9112 §3.2.1), or `None`.
fn split_uri(uri: &str) -> Option<(String, Option<String>)> {
    if uri.is_empty()
        || uri.len() > MAX_URI
        || !uri.starts_with('/')
        || uri.bytes().any(|b| b <= b' ' || b == 0x7f || b == b'#')
    {
        return None;
    }
    Some(match uri.split_once('?') {
        Some((p, q)) => (String::from(p), Some(String::from(q))),
        None => (String::from(uri), None),
    })
}

/// The request `engine` asks about.
///
/// `method` is the check request's own method, `suffix` the path Envoy appended to the check
/// path and `query` the check request's query; `header` reads a header of the check request.
///
/// # Errors
/// [`ForwardError`].
pub fn forwarded(
    engine: Engine,
    method: &str,
    (suffix, query): (Option<&str>, Option<&str>),
    header: impl Fn(&str) -> Option<String>,
) -> Result<Forwarded, ForwardError> {
    let (method, uri) = match engine {
        Engine::Nginx => (header("x-original-method"), header("x-original-uri")),
        Engine::Traefik | Engine::Caddy => {
            (header("x-forwarded-method"), header("x-forwarded-uri"))
        }
        Engine::Envoy => {
            let path = match suffix {
                Some(s) => format!("/{s}"),
                None => String::from("/"),
            };
            let uri = match query {
                Some(q) => format!("{path}?{q}"),
                None => path,
            };
            (Some(String::from(method)), Some(uri))
        }
    };
    let method = method
        .map(|m| m.trim().to_owned())
        .filter(|m| method_ok(m))
        .ok_or(ForwardError::Method)?;
    let host = header("x-forwarded-host")
        .or_else(|| {
            matches!(engine, Engine::Envoy)
                .then(|| header("host"))
                .flatten()
        })
        .and_then(|h| host_of(&h))
        .ok_or(ForwardError::Host)?;
    let (path, query) = uri
        .as_deref()
        .and_then(split_uri)
        .ok_or(ForwardError::Uri)?;
    Ok(Forwarded {
        method,
        host,
        path,
        query,
    })
}

/// A cookie of the forwarded request's `Cookie` header.
#[must_use]
pub fn cookie(header: Option<&str>, name: &str) -> Option<String> {
    header?.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name && !v.is_empty()).then(|| String::from(v))
    })
}

#[cfg(test)]
mod tests;
