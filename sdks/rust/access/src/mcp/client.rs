//! The MCP client profile (§11.4.3, §11.5.2, §18.3, AG-9): the agent Instance finds the
//! metadata, checks that it names the resource it asked for (RFC 9728 §7.3), asks its
//! authorization server for a token with the RFC 8707 `resource` indicator and a DPoP key
//! ([`crate::auth::dpop::proof`]), and signs the statement of each call over the same intent
//! the server will ask about ([`super::tool::intent`]). Sans I/O; the host moves the bytes.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use access_kernel::json::{self, Json, b64url_encode};
use access_kernel::model::Window;

use super::json::text;
use super::prm::{WELL_KNOWN, split};
use super::{META_AIS, META_CONTINUE, META_PROTOCOL, META_VALIDITY, PROTOCOL_VERSION};

/// Largest metadata document read.
pub const MAX_METADATA: usize = 64 * 1024;

/// Why the client stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Not an absolute `https` URI (or `http://127.0.0.1` for a local server).
    #[error("mcp-uri")]
    Uri,
    /// The metadata is not JSON or misses a member.
    #[error("mcp-metadata")]
    Metadata,
    /// The metadata names another resource (RFC 9728 §7.3).
    #[error("mcp-resource-mismatch")]
    ResourceMismatch,
    /// The resource accepts bearer tokens only: an Access projection is always bound.
    #[error("mcp-unbound")]
    Unbound,
}

/// The canonical server URI (§11.4.3): scheme and host lowercased, no fragment, no query, no
/// trailing slash, default port removed.
///
/// # Errors
/// [`ClientError::Uri`].
pub fn canonical_resource(uri: &str) -> Result<String, ClientError> {
    if uri.contains(['?', '#', ' ', '"', '\\']) {
        return Err(ClientError::Uri);
    }
    let (scheme, rest) = uri.split_once("://").ok_or(ClientError::Uri)?;
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    let mut authority = authority.to_ascii_lowercase();
    if authority.is_empty() || authority.contains('@') {
        return Err(ClientError::Uri);
    }
    match scheme.as_str() {
        "https" => {
            if let Some(a) = authority.strip_suffix(":443") {
                authority = String::from(a);
            }
        }
        "http" if authority == "127.0.0.1" || authority.starts_with("127.0.0.1:") => {}
        _ => return Err(ClientError::Uri),
    }
    let mut out = scheme;
    out.push_str("://");
    out.push_str(&authority);
    out.push_str(path.trim_end_matches('/'));
    Ok(out)
}

/// Where to look for the metadata, in order (§11.5.2): the challenge's `resource_metadata`,
/// then the path-aware well-known URL, then the root one.
#[must_use]
pub fn metadata_urls(resource: &str, challenge: Option<&Challenged>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(m) = challenge.and_then(|c| c.resource_metadata.clone()) {
        out.push(m);
    }
    let (origin, path) = split(resource);
    let path = path.trim_end_matches('/');
    if !path.is_empty() {
        out.push(alloc::format!("{origin}{WELL_KNOWN}{path}"));
    }
    out.push(alloc::format!("{origin}{WELL_KNOWN}"));
    out.dedup();
    out
}

/// What a challenge told the client.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Challenged {
    /// The scheme (`Bearer`, `DPoP`).
    pub scheme: String,
    /// `error`.
    pub error: Option<String>,
    /// `scope`.
    pub scope: Option<String>,
    /// `resource_metadata`.
    pub resource_metadata: Option<String>,
    /// `algs` of a DPoP challenge.
    pub algs: Option<String>,
}

/// Reads one `WWW-Authenticate` value: `scheme` then `k="v"` or `k=v` pairs.
#[must_use]
pub fn parse_challenge(value: &str) -> Option<Challenged> {
    let value = value.trim();
    let (scheme, rest) = value.split_once(' ').unwrap_or((value, ""));
    let mut out = Challenged {
        scheme: String::from(scheme),
        ..Challenged::default()
    };
    let mut rest = rest.trim_start();
    while !rest.is_empty() {
        let (key, after) = rest.split_once('=')?;
        let key = key.trim().trim_start_matches(',').trim();
        let after = after.trim_start();
        let (val, next) = if let Some(quoted) = after.strip_prefix('"') {
            let end = quoted.find('"')?;
            let (v, tail) = quoted.split_at(end);
            (v, tail.get(1..).unwrap_or(""))
        } else {
            after.split_once(',').unwrap_or((after, ""))
        };
        let val = Some(String::from(val.trim()));
        match key {
            "error" => out.error = val,
            "scope" => out.scope = val,
            "resource_metadata" => out.resource_metadata = val,
            "algs" => out.algs = val,
            _ => {}
        }
        rest = next.trim_start().trim_start_matches(',').trim_start();
    }
    Some(out)
}

/// What the client needs from the metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    /// The resource, as published.
    pub resource: String,
    /// The authorization servers, in order.
    pub authorization_servers: Vec<String>,
    /// The scopes published.
    pub scopes: Vec<String>,
    /// DPoP algorithms, when DPoP is required.
    pub dpop_algs: Option<Vec<String>>,
}

fn texts(v: Option<&Json>) -> Option<Vec<String>> {
    match v? {
        Json::Array(items) => items.iter().map(|i| i.as_str().map(String::from)).collect(),
        _ => None,
    }
}

/// Checks a metadata document against the resource the client asked for: `resource` is
/// exactly it (RFC 9728 §7.3), `authorization_servers` has at least one entry, and the tokens
/// are bound (DPoP or mTLS). A bearer-only resource is not an Access PEP.
///
/// # Errors
/// [`ClientError`].
pub fn check_metadata(body: &[u8], asked: &str) -> Result<Discovered, ClientError> {
    let v = json::parse(body, MAX_METADATA).map_err(|_| ClientError::Metadata)?;
    let resource = v
        .get("resource")
        .and_then(Json::as_str)
        .ok_or(ClientError::Metadata)?;
    if canonical_resource(resource)? != canonical_resource(asked)? {
        return Err(ClientError::ResourceMismatch);
    }
    let authorization_servers =
        texts(v.get("authorization_servers")).ok_or(ClientError::Metadata)?;
    if authorization_servers.is_empty() {
        return Err(ClientError::Metadata);
    }
    let dpop = v.get("dpop_bound_access_tokens_required") == Some(&Json::Bool(true));
    let mtls = v.get("tls_client_certificate_bound_access_tokens") == Some(&Json::Bool(true));
    if !dpop && !mtls {
        return Err(ClientError::Unbound);
    }
    Ok(Discovered {
        resource: String::from(resource),
        authorization_servers,
        scopes: texts(v.get("scopes_supported")).unwrap_or_default(),
        dpop_algs: if dpop {
            Some(texts(v.get("dpop_signing_alg_values_supported")).unwrap_or_default())
        } else {
            None
        },
    })
}

fn pct(out: &mut String, s: &str) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

/// The token request members naming the resource (RFC 8707 §2): `resource=<canonical URI>`,
/// form-encoded, and the scopes when there are any.
///
/// # Errors
/// [`ClientError::Uri`].
pub fn token_resource(resource: &str, scopes: &[String]) -> Result<String, ClientError> {
    let mut out = String::from("resource=");
    pct(&mut out, &canonical_resource(resource)?);
    let scopes: Vec<&str> = scopes
        .iter()
        .map(String::as_str)
        .filter(|s| *s != super::prm::OFFLINE_ACCESS)
        .collect();
    if !scopes.is_empty() {
        out.push_str("&scope=");
        pct(&mut out, &scopes.join(" "));
    }
    Ok(out)
}

/// The `_meta` object of a request: the protocol revision, and for a call the statement, its
/// validity window and, for a stream, the pre-signed `continue` statement.
#[must_use]
pub fn meta(ais: Option<&[u8]>, validity: Option<Window>, continue_ais: Option<&[u8]>) -> String {
    let mut out = String::from("{");
    text(&mut out, META_PROTOCOL);
    out.push(':');
    text(&mut out, PROTOCOL_VERSION);
    if let Some(a) = ais {
        out.push(',');
        text(&mut out, META_AIS);
        out.push(':');
        text(&mut out, &b64url_encode(a));
    }
    if let Some(w) = validity {
        out.push(',');
        text(&mut out, META_VALIDITY);
        let _ = write!(out, ":{{\"from\":{},\"until\":{}}}", w.from, w.until);
    }
    if let Some(c) = continue_ais {
        out.push(',');
        text(&mut out, META_CONTINUE);
        out.push(':');
        text(&mut out, &b64url_encode(c));
    }
    out.push('}');
    out
}
