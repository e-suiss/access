//! The HTTP and JSON-RPC surface of one MCP request (§11.5.3, §11.5.6 #11, #12, #20 to #24,
//! RS-M14, RS-M15, RS-M19, AG-11): what is refused before any token or decision is looked at.
//!
//! The body is authoritative; a mirrored header that disagrees with it is `-32020`. Header
//! values never carry CR or LF, and a parameter declared secret never travels in a header.
//! `Mcp-Session-Id` is read by nobody and never written. `clientInfo`,
//! `clientCapabilities` and `serverInfo` are not kept: nothing downstream can read them.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::model::Window;

use super::{META_AIS, META_CONTINUE, META_PROTOCOL, META_VALIDITY};

/// Largest JSON-RPC body read.
pub const MAX_BODY: usize = 256 * 1024;

/// JSON-RPC code of a header that disagrees with the body (SEP-2243).
pub const HEADER_MISMATCH: i64 = -32020;

/// The legacy session header, ignored and never emitted (§11.5.3).
pub const SESSION_HEADER: &str = "mcp-session-id";

/// The mirrored method header.
pub const METHOD_HEADER: &str = "mcp-method";

/// The mirrored name header (tool or prompt name, resource URI).
pub const NAME_HEADER: &str = "mcp-name";

/// Prefix of a mirrored tool parameter header.
pub const PARAM_PREFIX: &str = "mcp-param-";

const SENTINEL_OPEN: &str = "=?base64?";
const SENTINEL_CLOSE: &str = "?=";

/// Why a request is refused before authentication. A value, never a pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// GET, DELETE or another method on the MCP endpoint.
    #[error("method-not-allowed")]
    MethodNotAllowed,
    /// An `Origin` that is present and not allowed (DNS rebinding).
    #[error("origin")]
    Origin,
    /// A `Host` this server does not serve (DNS rebinding).
    #[error("host")]
    Host,
    /// A header value with CR, LF or NUL.
    #[error("header-crlf")]
    HeaderCrlf,
    /// A mirrored header disagrees with the body.
    #[error("header-mismatch")]
    HeaderMismatch,
    /// A parameter declared secret arrived in a header.
    #[error("header-secret")]
    HeaderSecret,
    /// The body is not JSON.
    #[error("parse")]
    Parse,
    /// The body is not one JSON-RPC request.
    #[error("invalid-request")]
    InvalidRequest,
    /// `_meta` names no protocol revision.
    #[error("protocol-version")]
    ProtocolVersion,
    /// The body is over [`MAX_BODY`].
    #[error("too-large")]
    TooLarge,
}

impl Rejection {
    /// The HTTP status.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::MethodNotAllowed => 405,
            Self::Origin | Self::Host => 403,
            Self::TooLarge => 413,
            Self::HeaderCrlf
            | Self::HeaderMismatch
            | Self::HeaderSecret
            | Self::Parse
            | Self::InvalidRequest
            | Self::ProtocolVersion => 400,
        }
    }

    /// The JSON-RPC error code.
    #[must_use]
    pub const fn rpc_code(self) -> i64 {
        match self {
            Self::HeaderMismatch => HEADER_MISMATCH,
            Self::Parse | Self::TooLarge => -32700,
            Self::HeaderSecret | Self::ProtocolVersion => -32602,
            Self::MethodNotAllowed
            | Self::Origin
            | Self::Host
            | Self::HeaderCrlf
            | Self::InvalidRequest => -32600,
        }
    }
}

/// Request headers as received: names compared without case.
#[derive(Clone, Copy, Debug)]
pub struct Headers<'a>(pub &'a [(&'a str, &'a str)]);

impl<'a> Headers<'a> {
    /// The first value of `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'a str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }

    /// How many times `name` appears.
    #[must_use]
    pub fn count(&self, name: &str) -> usize {
        self.0
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }

    /// Every `(suffix, value)` of headers named `prefix` + suffix, the suffix lowercased.
    #[must_use]
    pub fn prefixed(&self, prefix: &str) -> Vec<(String, &'a str)> {
        self.0
            .iter()
            .filter_map(|(k, v)| {
                let lower = k.to_ascii_lowercase();
                lower
                    .strip_prefix(prefix)
                    .map(|rest| (String::from(rest), *v))
            })
            .collect()
    }
}

/// §11.5.6 #23: no header value carries CR, LF or NUL.
///
/// # Errors
/// [`Rejection::HeaderCrlf`].
pub fn hygiene(headers: &Headers<'_>) -> Result<(), Rejection> {
    if headers.0.iter().any(|(k, v)| {
        k.bytes()
            .chain(v.bytes())
            .any(|b| matches!(b, b'\r' | b'\n' | 0))
    }) {
        return Err(Rejection::HeaderCrlf);
    }
    Ok(())
}

/// The origins and hosts this server answers (RS-M15, §11.5.6 #20).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Origins {
    /// Allowed `Origin` values, exact (`scheme://host[:port]`).
    pub origins: Vec<String>,
    /// Allowed `Host` values, exact (`host[:port]`).
    pub hosts: Vec<String>,
}

impl Origins {
    /// An `Origin` that is present and not allowed is 403; so is `null`. A `Host` outside the
    /// allowed hosts is 403 too, so a rebound name never reaches this server's logic.
    ///
    /// # Errors
    /// [`Rejection::Origin`], [`Rejection::Host`].
    pub fn check(&self, headers: &Headers<'_>) -> Result<(), Rejection> {
        if headers.count("origin") > 1 || headers.count("host") > 1 {
            return Err(Rejection::Origin);
        }
        if let Some(origin) = headers.get("origin")
            && !self.origins.iter().any(|o| o == origin)
        {
            return Err(Rejection::Origin);
        }
        match headers.get("host") {
            Some(host) if self.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) => Ok(()),
            _ => Err(Rejection::Host),
        }
    }
}

/// A local server binds to this address only (§11.5.6 #21).
pub const LOCAL_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The address is not `127.0.0.1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("local-bind")]
pub struct BindError;

/// §11.5.6 #21: a server running locally listens on `127.0.0.1` and nothing else; not
/// `0.0.0.0`, not `::`, not another loopback address.
///
/// # Errors
/// [`BindError`].
pub fn local_bind(address: IpAddr) -> Result<(), BindError> {
    if address == LOCAL_BIND {
        Ok(())
    } else {
        Err(BindError)
    }
}

/// The Access members of a request's `_meta`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessMeta {
    /// The actor's statement, decoded.
    pub ais: Option<Vec<u8>>,
    /// The validity window it was signed over.
    pub validity: Option<Window>,
    /// The pre-signed `continue` statement of a stream, decoded.
    pub continue_ais: Option<Vec<u8>>,
}

/// One JSON-RPC request, as far as this server reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rpc {
    /// `id`: a string or an integer.
    pub id: Json,
    /// `method`.
    pub method: String,
    /// `params` without `_meta`; `{}` when absent.
    pub params: Json,
    /// The protocol revision `_meta` names.
    pub protocol_version: String,
    /// `requestState` of an MRTR retry, as sent.
    pub request_state: Option<String>,
    /// The Access members of `_meta`.
    pub access: AccessMeta,
}

fn window(v: &Json) -> Option<Window> {
    let from = u64::try_from(v.get("from")?.as_int()?).ok()?;
    let until = u64::try_from(v.get("until")?.as_int()?).ok()?;
    (from < until).then_some(Window { from, until })
}

fn bytes(v: Option<&Json>) -> Result<Option<Vec<u8>>, Rejection> {
    match v {
        None => Ok(None),
        Some(Json::Str(s)) => b64url_decode(s)
            .map(Some)
            .map_err(|_| Rejection::InvalidRequest),
        Some(_) => Err(Rejection::InvalidRequest),
    }
}

/// Parses one JSON-RPC request (§11.5.3): `jsonrpc` 2.0, an `id`, a `method`, `params` an
/// object when present, and `_meta` naming the protocol revision. `clientInfo`,
/// `clientCapabilities` and `serverInfo` are dropped here (AG-11): no later step can read them.
///
/// # Errors
/// [`Rejection`].
pub fn parse(body: &[u8]) -> Result<Rpc, Rejection> {
    if body.len() > MAX_BODY {
        return Err(Rejection::TooLarge);
    }
    let v = json::parse(body, MAX_BODY).map_err(|_| Rejection::Parse)?;
    if v.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
        return Err(Rejection::InvalidRequest);
    }
    let method = String::from(
        v.get("method")
            .and_then(Json::as_str)
            .ok_or(Rejection::InvalidRequest)?,
    );
    let id = match v.get("id") {
        Some(id @ (Json::Str(_) | Json::Int(_))) => id.clone(),
        None if method.starts_with("notifications/") => Json::Null,
        _ => return Err(Rejection::InvalidRequest),
    };
    let (params, meta) = match v.get("params") {
        None => (Json::Object(Vec::new()), None),
        Some(Json::Object(members)) => {
            let mut kept = Vec::new();
            let mut meta = None;
            for (k, val) in members {
                match k.as_str() {
                    "_meta" => meta = Some(val.clone()),
                    // AG-11
                    "clientInfo" | "clientCapabilities" | "capabilities" | "serverInfo" => {}
                    _ => kept.push((k.clone(), val.clone())),
                }
            }
            (Json::Object(kept), meta)
        }
        Some(_) => return Err(Rejection::InvalidRequest),
    };
    let meta = meta.unwrap_or(Json::Object(Vec::new()));
    if !matches!(meta, Json::Object(_)) {
        return Err(Rejection::InvalidRequest);
    }
    let protocol_version = String::from(
        meta.get(META_PROTOCOL)
            .and_then(Json::as_str)
            .ok_or(Rejection::ProtocolVersion)?,
    );
    let request_state = match params.get("requestState") {
        None => None,
        Some(Json::Str(s)) => Some(s.clone()),
        Some(_) => return Err(Rejection::InvalidRequest),
    };
    let validity = match meta.get(META_VALIDITY) {
        None => None,
        Some(w) => Some(window(w).ok_or(Rejection::InvalidRequest)?),
    };
    let access = AccessMeta {
        ais: bytes(meta.get(META_AIS))?,
        validity,
        continue_ais: bytes(meta.get(META_CONTINUE))?,
    };
    Ok(Rpc {
        id,
        method,
        params,
        protocol_version,
        request_state,
        access,
    })
}

/// A header value, with the base64 sentinel `=?base64?…?=` decoded (SEP-2243).
fn header_text(value: &str) -> Option<String> {
    match value
        .strip_prefix(SENTINEL_OPEN)
        .and_then(|v| v.strip_suffix(SENTINEL_CLOSE))
    {
        Some(encoded) => {
            let raw = b64url_decode(encoded.trim_end_matches('='))
                .ok()
                .or_else(|| standard_b64(encoded))?;
            String::from_utf8(raw).ok()
        }
        None => Some(String::from(value)),
    }
}

fn standard_b64(s: &str) -> Option<Vec<u8>> {
    let url: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    b64url_decode(&url).ok()
}

/// A body value as its header form: a string as is, an integer or boolean as written.
fn body_text(v: &Json) -> Option<String> {
    match v {
        Json::Str(s) => Some(s.clone()),
        Json::Int(i) => Some(alloc::format!("{i}")),
        Json::Bool(b) => Some(String::from(if *b { "true" } else { "false" })),
        _ => None,
    }
}

/// The name a method's `Mcp-Name` mirrors.
fn named(rpc: &Rpc) -> Option<&Json> {
    match rpc.method.as_str() {
        "tools/call" | "prompts/get" => rpc.params.get("name"),
        "resources/read" | "resources/subscribe" => rpc.params.get("uri"),
        _ => None,
    }
}

/// RS-M14, §11.5.6 #22, #24: `Mcp-Method`, `Mcp-Name` and every `Mcp-Param-*` equal the body
/// after the sentinel is decoded; a header for a parameter `secret` names is refused even when
/// it matches. The body is authoritative: a header never fills a missing body member.
///
/// # Errors
/// [`Rejection::HeaderMismatch`], [`Rejection::HeaderSecret`].
pub fn consistent(
    headers: &Headers<'_>,
    rpc: &Rpc,
    secret: impl Fn(&str) -> bool,
) -> Result<(), Rejection> {
    if let Some(m) = headers.get(METHOD_HEADER)
        && header_text(m).as_deref() != Some(rpc.method.as_str())
    {
        return Err(Rejection::HeaderMismatch);
    }
    if let Some(n) = headers.get(NAME_HEADER) {
        let body = named(rpc).and_then(body_text);
        if body.is_none() || header_text(n) != body {
            return Err(Rejection::HeaderMismatch);
        }
    }
    let arguments = rpc.params.get("arguments");
    for (name, value) in headers.prefixed(PARAM_PREFIX) {
        if secret(&name) {
            return Err(Rejection::HeaderSecret);
        }
        let body = match arguments {
            Some(Json::Object(members)) => members
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&name))
                .and_then(|(_, v)| body_text(v)),
            _ => None,
        };
        if body.is_none() || header_text(value) != body {
            return Err(Rejection::HeaderMismatch);
        }
    }
    Ok(())
}
