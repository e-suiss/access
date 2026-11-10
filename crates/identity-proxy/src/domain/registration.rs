//! A proxy's registration as a PEP and the `idp.proxy.*` changes that make it (catalog 6,
//! OP-156 m.3 (a), (l)). Sans-I/O: a REST body becomes one change, which the intent binds
//! (EI-25).
//!
//! A registration names the application host the proxy guards, the engine, the OIDC client the
//! browser signs in with (its redirect URI is the host's [`CALLBACK_PATH`]), the proxy's
//! transport identity, and what each request asks the domain: one action on the application's
//! resources, one resource per path pattern. Plain identity headers are off until a separate
//! `idp.proxy.plain_headers` turns them on.

use access_internal_api::idp::IdpAction;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::ActionRef;
use serde_json::{Map, Value as Json, json};
use suiss_crypto::dcbor::Value;

use super::engine::{Engine, MAX_HOST};
use super::route::{CALLBACK_PATH, MAX_ROUTES, route_ok};

/// Longest upstream URL.
pub const MAX_UPSTREAM: usize = 2048;

/// Why a body is not an `idp.proxy.*` change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("proxy registration body")]
pub struct ChangeError;

/// One proxy as registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// Its name, never reused, the first segment of every resource it asks about.
    pub name: String,
    /// The engine in front of the application.
    pub engine: Engine,
    /// The application host, lower case, with a port when it is not 443.
    pub host: String,
    /// Where the application listens behind the proxy, for the plain header setup check.
    pub upstream: Option<String>,
    /// The OIDC client the browser signs in with.
    pub client_id: String,
    /// The proxy's transport identity: its client certificate's or DPoP key's thumbprint.
    pub pep: String,
    /// The action every request asks.
    pub action: ActionRef,
    /// The resource namespace.
    pub namespace: String,
    /// The path patterns, `/` at least.
    pub routes: Vec<String>,
}

impl Registration {
    /// The application's origin: the `aud` of its application token.
    #[must_use]
    pub fn audience(&self) -> String {
        format!("https://{}", self.host)
    }

    /// The OIDC redirect URI on the application host.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!("https://{}{CALLBACK_PATH}", self.host)
    }
}

/// An `idp.proxy.*` change (OP-156 m.3 (a)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyChange {
    /// `idp.proxy.register` (CT2).
    Register(Registration),
    /// `idp.proxy.update` (CT2): the whole registration again, under the same name.
    Update(Registration),
    /// `idp.proxy.retire` (CT1).
    Retire(String),
    /// `idp.proxy.plain_headers` (CT2), after the setup check.
    PlainHeaders(String),
    /// `idp.proxy.plain_headers_close` (CT1).
    PlainHeadersClose(String),
}

/// Whether `name` is a proxy name: lower-case letters, digits and `-`, a letter first.
#[must_use]
pub fn name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=63).contains(&b.len())
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn host_ok(host: &str) -> bool {
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (host, None),
    };
    let port_ok = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p != 0 && p != 443));
    port_ok
        && (1..=MAX_HOST).contains(&name.len())
        && name.contains('.')
        && name.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

fn upstream_ok(u: &str) -> bool {
    u.len() <= MAX_UPSTREAM
        && (u.starts_with("http://") || u.starts_with("https://"))
        && !u.bytes().any(|b| b <= b' ' || b == 0x7f)
}

/// Whether `pep` is a transport identity: the base64url of a 32-byte thumbprint.
#[must_use]
pub fn pep_ok(pep: &str) -> bool {
    pep.len() == 43 && b64url_decode(pep).is_ok_and(|b| b.len() == 32)
}

fn ident_ok(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn text<'a>(m: &'a Map<String, Json>, k: &str) -> Result<&'a str, ChangeError> {
    m.get(k).and_then(Json::as_str).ok_or(ChangeError)
}

fn action_of(v: &Json) -> Result<ActionRef, ChangeError> {
    let m = v.as_object().ok_or(ChangeError)?;
    if m.len() != 4 {
        return Err(ChangeError);
    }
    let schema = b64url_decode(text(m, "schema")?).map_err(|_| ChangeError)?;
    Ok(ActionRef {
        namespace: String::from(text(m, "namespace")?),
        name: String::from(text(m, "name")?),
        major: m.get("major").and_then(Json::as_u64).ok_or(ChangeError)?,
        schema: Digest(<[u8; 32]>::try_from(schema.as_slice()).map_err(|_| ChangeError)?),
    })
}

const MEMBERS: [&str; 9] = [
    "name",
    "engine",
    "host",
    "upstream",
    "client_id",
    "pep",
    "action",
    "namespace",
    "routes",
];

fn registration(m: &Map<String, Json>, name: &str) -> Result<Registration, ChangeError> {
    if m.keys().any(|k| !MEMBERS.contains(&k.as_str())) {
        return Err(ChangeError);
    }
    let routes = match m.get("routes") {
        None => vec![String::from("/")],
        Some(Json::Array(a)) => a
            .iter()
            .map(|r| r.as_str().map(String::from).ok_or(ChangeError))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(ChangeError),
    };
    let r = Registration {
        name: String::from(name),
        engine: Engine::parse(text(m, "engine")?).ok_or(ChangeError)?,
        host: text(m, "host")?.to_ascii_lowercase(),
        upstream: match m.get("upstream") {
            None => None,
            Some(u) => Some(String::from(u.as_str().ok_or(ChangeError)?)),
        },
        client_id: String::from(text(m, "client_id")?),
        pep: String::from(text(m, "pep")?),
        action: action_of(m.get("action").ok_or(ChangeError)?)?,
        namespace: String::from(text(m, "namespace")?),
        routes,
    };
    check(&r)?;
    Ok(r)
}

/// Whether `r` is inside the rules: a proxy name, a host name, an `http(s)` upstream, a
/// transport identity, a client id, an action and namespace, and 1 to 64 distinct patterns
/// that include `/` or name their own.
///
/// # Errors
/// [`ChangeError`].
pub fn check(r: &Registration) -> Result<(), ChangeError> {
    let mut seen = std::collections::BTreeSet::new();
    let routes_ok = !r.routes.is_empty()
        && r.routes.len() <= MAX_ROUTES
        && r.routes
            .iter()
            .all(|p| route_ok(p) && seen.insert(p.to_ascii_lowercase()));
    let ok = name_ok(&r.name)
        && host_ok(&r.host)
        && r.upstream.as_deref().is_none_or(upstream_ok)
        && (1..=128).contains(&r.client_id.len())
        && !r.client_id.bytes().any(|b| b <= b' ')
        && pep_ok(&r.pep)
        && ident_ok(&r.action.namespace)
        && ident_ok(&r.action.name)
        && ident_ok(&r.namespace)
        && routes_ok;
    ok.then_some(()).ok_or(ChangeError)
}

fn object(body: &Json) -> Result<&Map<String, Json>, ChangeError> {
    body.as_object().ok_or(ChangeError)
}

fn empty(body: &Json) -> Result<(), ChangeError> {
    object(body)?.is_empty().then_some(()).ok_or(ChangeError)
}

impl ProxyChange {
    /// `registerProxy`: the registration with its `name`.
    ///
    /// # Errors
    /// [`ChangeError`].
    pub fn register(body: &Json) -> Result<Self, ChangeError> {
        let m = object(body)?;
        let name = text(m, "name")?;
        Ok(Self::Register(registration(m, name)?))
    }

    /// `putProxy` of `name`: the registration again; a `name` member must be the same.
    ///
    /// # Errors
    /// [`ChangeError`].
    pub fn update(name: &str, body: &Json) -> Result<Self, ChangeError> {
        let m = object(body)?;
        if m.get("name").is_some_and(|n| n.as_str() != Some(name)) {
            return Err(ChangeError);
        }
        Ok(Self::Update(registration(m, name)?))
    }

    /// `retireProxy` of `name`: an empty body.
    ///
    /// # Errors
    /// [`ChangeError`].
    pub fn retire(name: &str, body: &Json) -> Result<Self, ChangeError> {
        empty(body)?;
        name_ok(name)
            .then(|| Self::Retire(String::from(name)))
            .ok_or(ChangeError)
    }

    /// `putProxyPlainHeaders` of `name`: `{"enabled": true | false}`.
    ///
    /// # Errors
    /// [`ChangeError`].
    pub fn plain_headers(name: &str, body: &Json) -> Result<Self, ChangeError> {
        let m = object(body)?;
        if !name_ok(name) || m.keys().any(|k| k != "enabled") {
            return Err(ChangeError);
        }
        match m.get("enabled").and_then(Json::as_bool) {
            Some(true) => Ok(Self::PlainHeaders(String::from(name))),
            Some(false) => Ok(Self::PlainHeadersClose(String::from(name))),
            None => Err(ChangeError),
        }
    }

    /// The proxy it changes.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Register(r) | Self::Update(r) => &r.name,
            Self::Retire(n) | Self::PlainHeaders(n) | Self::PlainHeadersClose(n) => n,
        }
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Register(_) => IdpAction::ProxyRegister,
            Self::Update(_) => IdpAction::ProxyUpdate,
            Self::Retire(_) => IdpAction::ProxyRetire,
            Self::PlainHeaders(_) => IdpAction::ProxyPlainHeaders,
            Self::PlainHeadersClose(_) => IdpAction::ProxyPlainHeadersClose,
        }
    }

    /// Whether it is inside the rules.
    ///
    /// # Errors
    /// [`ChangeError`].
    pub fn check(&self) -> Result<(), ChangeError> {
        match self {
            Self::Register(r) | Self::Update(r) => check(r),
            n if name_ok(n.name()) => Ok(()),
            _ => Err(ChangeError),
        }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        match self {
            Self::Register(r) | Self::Update(r) => m(vec![
                ("name", Value::text(&r.name)),
                ("engine", Value::text(r.engine.word())),
                ("host", Value::text(&r.host)),
                (
                    "upstream",
                    Value::text(r.upstream.as_deref().unwrap_or_default()),
                ),
                ("client_id", Value::text(&r.client_id)),
                ("pep", Value::text(&r.pep)),
                (
                    "action",
                    m(vec![
                        ("namespace", Value::text(&r.action.namespace)),
                        ("name", Value::text(&r.action.name)),
                        ("major", Value::Unsigned(r.action.major)),
                        ("schema", Value::Bytes(r.action.schema.0.to_vec())),
                    ]),
                ),
                ("namespace", Value::text(&r.namespace)),
                (
                    "routes",
                    Value::Array(r.routes.iter().map(|p| Value::text(p)).collect()),
                ),
            ]),
            Self::Retire(n) => m(vec![("retire", Value::text(n))]),
            Self::PlainHeaders(n) => m(vec![("plain_headers", Value::text(n))]),
            Self::PlainHeadersClose(n) => m(vec![("plain_headers_close", Value::text(n))]),
        }
    }

    /// Its resource path below the realm's slug.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        vec![String::from("proxy"), String::from(self.name())]
    }
}

/// The registration as stored and read back: the REST body form.
#[must_use]
pub fn to_json(r: &Registration) -> Json {
    json!({
        "name": r.name,
        "engine": r.engine.word(),
        "host": r.host,
        "upstream": r.upstream,
        "client_id": r.client_id,
        "pep": r.pep,
        "action": {
            "namespace": r.action.namespace,
            "name": r.action.name,
            "major": r.action.major,
            "schema": b64url_encode(&r.action.schema.0),
        },
        "namespace": r.namespace,
        "routes": r.routes,
    })
}

/// The registration a stored body names.
///
/// # Errors
/// [`ChangeError`] for a body that is not one.
pub fn from_json(v: &Json) -> Result<Registration, ChangeError> {
    let m = object(v)?;
    let mut m = m.clone();
    if m.get("upstream").is_some_and(Json::is_null) {
        m.remove("upstream");
    }
    let name = String::from(text(&m, "name")?);
    registration(&m, &name)
}

#[cfg(test)]
mod tests;
