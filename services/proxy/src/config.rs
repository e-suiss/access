//! The one configuration file (IDP-30 (2), OP-156 m.3 (m)): where Access is, how the proxy
//! proves who it is, where the engine listens, and one `[[app]]` per application host. The same
//! file renders for every engine; changing the engine never changes the file.

use std::net::IpAddr;

use serde::Deserialize;

/// Most applications one file names.
pub const MAX_APPS: usize = 64;

/// Longest file path or URL read.
pub const MAX_TEXT: usize = 2048;

/// Default time a check may take, ms.
pub const CHECK_TIMEOUT_MS: u64 = 2000;

/// Longest a check may take, ms.
pub const MAX_CHECK_TIMEOUT_MS: u64 = 10_000;

/// Why the file is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// Not TOML, or not this file's shape.
    #[error("access-proxy.toml: {0}")]
    Syntax(String),
    /// A value outside the rules; names the field.
    #[error("access-proxy.toml: {0} is not valid")]
    Invalid(&'static str),
    /// Two applications name the same host or policy.
    #[error("access-proxy.toml: app {0} is named twice")]
    Duplicate(String),
    /// The engine needs a value the file leaves out.
    #[error("access-proxy.toml: {engine} needs {field}")]
    Needs {
        /// The engine.
        engine: &'static str,
        /// The missing field.
        field: &'static str,
    },
    /// IDP-30 (3): plain identity headers for an application reachable around the proxy.
    #[error(
        "access-proxy.toml: app {0} asks for plain identity headers, but its upstream is not a loopback address only the proxy can reach"
    )]
    PlainHeadersReachable(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    access: RawAccess,
    listen: RawListen,
    #[serde(default)]
    app: Vec<RawApp>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccess {
    url: String,
    ca: String,
    certificate: String,
    key: String,
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListen {
    address: String,
    certificate: Option<String>,
    key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApp {
    policy: String,
    host: String,
    upstream: String,
    upstream_ca: Option<String>,
    #[serde(default)]
    plain_headers: bool,
}

/// `http` or `https`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `http`.
    Http,
    /// `https`.
    Https,
}

impl Scheme {
    /// Its name.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// An origin: scheme, host and port, nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// Scheme.
    pub scheme: Scheme,
    /// Host name or IP literal, lower case, without brackets.
    pub host: String,
    /// Port.
    pub port: u16,
}

impl Origin {
    /// Whether the host is an IP literal.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// `scheme://host:port`.
    #[must_use]
    pub fn url(&self) -> String {
        match self.ip() {
            Some(IpAddr::V6(_)) => {
                format!("{}://[{}]:{}", self.scheme.word(), self.host, self.port)
            }
            _ => format!("{}://{}:{}", self.scheme.word(), self.host, self.port),
        }
    }

    /// `host:port`, IPv6 in brackets.
    #[must_use]
    pub fn authority(&self) -> String {
        match self.ip() {
            Some(IpAddr::V6(_)) => format!("[{}]:{}", self.host, self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
    }
}

/// Where Access is and how the proxy proves itself to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Access {
    /// Access's mTLS listener, always `https`.
    pub origin: Origin,
    /// PEM trust anchors of Access's server certificate.
    pub ca: String,
    /// PEM client certificate chain; Access names the proxy by its leaf (OP-156 m.15 (a)).
    pub certificate: String,
    /// PEM key of the client certificate.
    pub key: String,
    /// How long one check may take, ms.
    pub timeout_ms: u64,
}

/// Where the engine listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen {
    /// Bind address, IP literal.
    pub ip: IpAddr,
    /// Port.
    pub port: u16,
    /// PEM certificate chain and key for the application hosts; Caddy obtains its own when absent.
    pub tls: Option<(String, String)>,
}

/// One application behind the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    /// The proxy registration in Access whose action and patterns decide (`idp.proxy.register`).
    pub policy: String,
    /// The application host, lower case, with a port when it is not 443.
    pub host: String,
    /// Where the application listens.
    pub upstream: Origin,
    /// PEM trust anchors of an `https` upstream.
    pub upstream_ca: Option<String>,
    /// Whether the plain identity headers are passed on (IDP-30 (3)).
    pub plain_headers: bool,
}

impl App {
    /// The host name without its port.
    #[must_use]
    pub fn hostname(&self) -> &str {
        self.host
            .rsplit_once(':')
            .map_or(self.host.as_str(), |(h, _)| h)
    }
}

/// The whole file, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Access.
    pub access: Access,
    /// The listener.
    pub listen: Listen,
    /// The applications, in file order.
    pub apps: Vec<App>,
}

fn path_ok(p: &str) -> bool {
    (1..=MAX_TEXT).contains(&p.len())
        && p.starts_with('/')
        && !p
            .bytes()
            .any(|b| b < b' ' || b == 0x7f || matches!(b, b'"' | b'\\' | b'{' | b'}' | b'`' | b'$'))
}

fn path(p: String, field: &'static str) -> Result<String, ConfigError> {
    if path_ok(&p) {
        Ok(p)
    } else {
        Err(ConfigError::Invalid(field))
    }
}

/// Whether `name` is a policy (proxy registration) name: lower-case letters, digits and `-`, a
/// letter first.
#[must_use]
pub fn policy_ok(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=63).contains(&b.len())
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn dns_ok(name: &str) -> bool {
    (1..=253).contains(&name.len())
        && name.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

fn app_host(host: &str) -> Option<String> {
    let host = host.to_ascii_lowercase();
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (host.as_str(), None),
    };
    let port_ok = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p != 0 && p != 443));
    (port_ok && name.contains('.') && dns_ok(name)).then_some(host)
}

/// `url` as an origin; a path other than `/`, a query, a fragment or user information is refused.
fn origin(url: &str, field: &'static str) -> Result<Origin, ConfigError> {
    let bad = ConfigError::Invalid(field);
    if url.len() > MAX_TEXT || url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(bad);
    }
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        return Err(bad);
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '?', '#', '@']) || authority.is_empty() {
        return Err(bad);
    }
    let default = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or(ConfigError::Invalid(field))?;
        let port = match after {
            "" => default,
            p => p
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or(ConfigError::Invalid(field))?,
        };
        h.parse::<std::net::Ipv6Addr>()
            .map_err(|_| ConfigError::Invalid(field))?;
        (h.to_ascii_lowercase(), port)
    } else {
        let (h, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h,
                p.parse::<u16>().map_err(|_| ConfigError::Invalid(field))?,
            ),
            None => (authority, default),
        };
        let h = h.to_ascii_lowercase();
        if h.parse::<IpAddr>().is_err() && !dns_ok(&h) {
            return Err(bad);
        }
        (h, port)
    };
    if port == 0 {
        return Err(bad);
    }
    Ok(Origin { scheme, host, port })
}

/// IDP-30 (3), OP-156 m.3 (l): an upstream only the proxy can reach is a loopback address, which
/// holds when the application and the engine share a host or a pod. Anything else may be
/// reachable around the proxy, so plain identity headers are refused for it.
#[must_use]
pub fn only_the_proxy_reaches(upstream: &Origin) -> bool {
    match upstream.ip() {
        Some(ip) => ip.is_loopback(),
        None => upstream.host == "localhost",
    }
}

impl Config {
    /// The file `text`, checked.
    ///
    /// # Errors
    /// [`ConfigError`].
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawFile =
            toml::from_str(text).map_err(|e| ConfigError::Syntax(e.message().to_owned()))?;
        let access_origin = origin(&raw.access.url, "access.url")?;
        if access_origin.scheme != Scheme::Https {
            return Err(ConfigError::Invalid("access.url"));
        }
        let timeout_ms = raw.access.timeout_ms.unwrap_or(CHECK_TIMEOUT_MS);
        if !(1..=MAX_CHECK_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(ConfigError::Invalid("access.timeout_ms"));
        }
        let access = Access {
            origin: access_origin,
            ca: path(raw.access.ca, "access.ca")?,
            certificate: path(raw.access.certificate, "access.certificate")?,
            key: path(raw.access.key, "access.key")?,
            timeout_ms,
        };
        let addr: std::net::SocketAddr = raw
            .listen
            .address
            .parse()
            .map_err(|_| ConfigError::Invalid("listen.address"))?;
        if addr.port() == 0 {
            return Err(ConfigError::Invalid("listen.address"));
        }
        let tls = match (raw.listen.certificate, raw.listen.key) {
            (Some(c), Some(k)) => Some((path(c, "listen.certificate")?, path(k, "listen.key")?)),
            (None, None) => None,
            _ => return Err(ConfigError::Invalid("listen.certificate")),
        };
        let listen = Listen {
            ip: addr.ip(),
            port: addr.port(),
            tls,
        };
        if raw.app.is_empty() || raw.app.len() > MAX_APPS {
            return Err(ConfigError::Invalid("app"));
        }
        let mut apps: Vec<App> = Vec::with_capacity(raw.app.len());
        for a in raw.app {
            if !policy_ok(&a.policy) {
                return Err(ConfigError::Invalid("app.policy"));
            }
            let host = app_host(&a.host).ok_or(ConfigError::Invalid("app.host"))?;
            let upstream = origin(&a.upstream, "app.upstream")?;
            let upstream_ca = a
                .upstream_ca
                .map(|c| path(c, "app.upstream_ca"))
                .transpose()?;
            if upstream.scheme == Scheme::Https && upstream_ca.is_none() {
                return Err(ConfigError::Invalid("app.upstream_ca"));
            }
            if upstream.scheme == Scheme::Http && upstream_ca.is_some() {
                return Err(ConfigError::Invalid("app.upstream_ca"));
            }
            if apps.iter().any(|b| {
                b.policy == a.policy
                    || b.hostname() == host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h)
            }) {
                return Err(ConfigError::Duplicate(a.policy));
            }
            if a.plain_headers && !only_the_proxy_reaches(&upstream) {
                return Err(ConfigError::PlainHeadersReachable(a.policy));
            }
            apps.push(App {
                policy: a.policy,
                host,
                upstream,
                upstream_ca,
                plain_headers: a.plain_headers,
            });
        }
        Ok(Self {
            access,
            listen,
            apps,
        })
    }
}

#[cfg(test)]
mod tests;
