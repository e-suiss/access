//! Client ID Metadata Documents, `draft-ietf-oauth-client-id-metadata-document-02` (§11.3,
//! AG-3…AG-6, OP-154 m.3 (i)): the Client Identifier URL rules, the document's schema, the
//! snapshot digests that tell an authority change from a visual one, and the fetch and cache
//! bounds the identity plane declares. A CIMD client is an OAuth client, never an actor or a
//! Claim issuer (PI-7); what its document says is the client's claim.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::domain::jwt::parse_jwks;

/// Largest document read; the read stops there, whatever `Content-Length` says (§11.3.6).
pub const MAX_DOCUMENT: usize = 5 * 1024;
/// The whole fetch, ms (OP-154 m.3 (i)).
pub const FETCH_TIMEOUT_MS: u64 = 5_000;
/// The connection, ms (OP-154 m.3 (i)).
pub const CONNECT_TIMEOUT_MS: u64 = 2_000;
/// Fetches of one URL per minute (OP-154 m.3 (i)).
pub const PER_URL_PER_MINUTE: u32 = 10;
/// Fetches of one realm per minute (OP-154 m.3 (i)).
pub const PER_REALM_PER_MINUTE: u32 = 100;
/// The `User-Agent` of every CIMD fetch (OP-154 m.3 (i)).
pub const USER_AGENT: &str = "Suiss-Access-CIMD/1";
/// The `Accept` of a document fetch.
pub const ACCEPT: &str = "application/json";
/// Shortest time a document is kept, seconds (OP-154 m.3 (i)).
pub const CACHE_MIN_S: u64 = 300;
/// Longest time a document is kept, seconds (OP-154 m.3 (i)).
pub const CACHE_MAX_S: u64 = 86_400;
/// Largest logo kept (OP-154 m.3 (i)).
pub const MAX_LOGO: usize = 256 * 1024;
/// The logo media types fetched; SVG never is (OP-154 m.3 (i)).
pub const LOGO_TYPES: [&str; 3] = ["image/png", "image/jpeg", "image/webp"];
/// How long a client is new on the consent screen, ms (OP-154 m.3 (i), §11.3.6 §8.9).
pub const NEW_APP_MS: u64 = 7 * 86_400_000;
/// Longest `client_name` kept.
pub const MAX_NAME: usize = 128;
/// Most redirect URIs read.
pub const MAX_REDIRECTS: usize = 32;

/// The document members whose change asks for consent again (AG-5).
pub const AUTHORITY_FIELDS: [&str; 6] = [
    "redirect_uris",
    "token_endpoint_auth_method",
    "scope",
    "grant_types",
    "jwks",
    "jwks_uri",
];
/// The document members whose change is only shown (AG-5).
pub const VISUAL_FIELDS: [&str; 2] = ["client_name", "logo_uri"];
/// The members that name a URL the authorization server could fetch (§11.3.6): each is
/// `https` and is checked like the client identifier itself.
pub const FETCHED_FIELDS: [&str; 6] = [
    "jwks_uri",
    "logo_uri",
    "policy_uri",
    "tos_uri",
    "client_uri",
    "initiate_login_uri",
];

const SYMMETRIC_METHODS: [&str; 3] = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
];

/// Why a Client Identifier URL or a document is refused; every case is `invalid_client` and
/// cancels the authorization request (AG-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CimdError {
    /// Not a Client Identifier URL (§11.3.2).
    #[error("not a client identifier URL")]
    Url,
    /// Not one JSON object, or a member repeats.
    #[error("not a JSON object")]
    Json,
    /// The document's `client_id` is not the URL it was fetched from.
    #[error("client_id does not match the URL")]
    ClientId,
    /// A required member is missing or malformed (`client_name`, `redirect_uris`).
    #[error("required member missing")]
    Missing,
    /// A shared secret: a symmetric method, `client_secret` or private key material (§11.3.1).
    #[error("symmetric secret")]
    Secret,
    /// A method, algorithm or key set the identity plane does not accept.
    #[error("unsupported client authentication")]
    Auth,
    /// A redirect URI is neither `https` nor a loopback one, is a pattern, or a `web` client
    /// names a loopback one (SEP-837, AS-M5).
    #[error("redirect URI refused")]
    Redirect,
    /// An `application_type` other than `web` or `native`.
    #[error("application_type refused")]
    ApplicationType,
    /// A fetched URL member is not an `https` URL Access requests (§11.3.6).
    #[error("embedded URL refused")]
    Embedded,
}

/// RFC 3986 dot segments, user info, fragment and query are refused; the path is required
/// and is not `/`; `localhost` and IP literals never are client identifiers (§11.3.2). The URL
/// is compared as an exact string afterwards: nothing is normalised.
///
/// # Errors
/// [`CimdError::Url`].
pub fn client_id_url(id: &str) -> Result<(), CimdError> {
    let rest = id.strip_prefix("https://").ok_or(CimdError::Url)?;
    if id.len() > 2048 || id.contains(['#', '?', '\\']) || !id.bytes().all(|c| c.is_ascii_graphic())
    {
        return Err(CimdError::Url);
    }
    let slash = rest.find('/').ok_or(CimdError::Url)?;
    let (authority, path) = rest.split_at(slash);
    if authority.contains('@') || authority.is_empty() || path == "/" {
        return Err(CimdError::Url);
    }
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => h,
        Some(_) => return Err(CimdError::Url),
        None => authority,
    };
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    let literal = host.starts_with('[')
        || name.parse::<std::net::Ipv4Addr>().is_ok()
        || name.bytes().all(|c| c.is_ascii_digit() || c == b'.');
    if literal
        || name == "localhost"
        || name.ends_with(".localhost")
        || !name.contains('.')
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
    {
        return Err(CimdError::Url);
    }
    if path
        .split('/')
        .any(|seg| matches!(seg, "." | "..") || seg.eq_ignore_ascii_case("%2e") || seg.eq_ignore_ascii_case("%2e%2e"))
    {
        return Err(CimdError::Url);
    }
    Ok(())
}

/// The host of a Client Identifier URL, lowercase, for the domain trust policy (AS-A2).
#[must_use]
pub fn host(id: &str) -> Option<String> {
    let rest = id.strip_prefix("https://")?;
    let authority = rest.split('/').next()?;
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

/// Whether the realm's domain policy admits `host` (AS-A2, `idp.client.cimd_policy`): one of
/// `domains` exactly, or a subdomain of one written `*.example.com`. An empty list admits none.
#[must_use]
pub fn domain_admitted(domains: &[String], host: &str) -> bool {
    domains.iter().any(|d| match d.strip_prefix("*.") {
        Some(base) => host
            .strip_suffix(base)
            .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.')),
        None => d.eq_ignore_ascii_case(host),
    })
}

/// How the client authenticates at the token endpoint, as its document says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocumentAuth {
    /// A public client.
    None,
    /// `private_key_jwt` against `jwks_uri`.
    JwksUri(String),
    /// `private_key_jwt` against the inline `jwks`.
    Jwks(String),
}

/// `application_type` (OIDC DCR §2), read from the document too (§11.3.9, §11.4.5 #8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationType {
    /// A remote, browser-based client; the OIDC default.
    Web,
    /// A local or CLI client.
    Native,
}

/// A checked document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// The Client Identifier URL.
    pub client_id: String,
    /// The client's claimed name; authority-opaque.
    pub client_name: String,
    /// Its redirect URIs, exact strings.
    pub redirect_uris: Vec<String>,
    /// Token endpoint authentication.
    pub auth: DocumentAuth,
    /// Whether it opted in to RS256 client assertions (§11.4.5 (a), OP-154 m.3 (l)).
    pub rs256: bool,
    /// `application_type`.
    pub application_type: ApplicationType,
    /// Its `logo_uri`; authority-opaque.
    pub logo_uri: Option<String>,
    /// Every URL member Access could fetch.
    pub fetched: Vec<String>,
    /// Digest of the authority members (AG-5).
    pub authority_hash: [u8; 32],
    /// Digest of the visual members (AG-5).
    pub visual_hash: [u8; 32],
}

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(UniqueVisitor).map(Unique)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JSON without repeated members")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(String::from(v)))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Unique(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some(k) = map.next_key::<String>()? {
            let Unique(v) = map.next_value()?;
            if out.insert(k, v).is_some() {
                return Err(de::Error::custom("repeated member"));
            }
        }
        Ok(Value::Object(out))
    }
}

/// Writes `v` as JSON with sorted object members, for a digest that does not depend on member
/// order.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                if let Some(x) = m.get(k) {
                    canonical(x, out);
                }
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        other => {
            let _ = write!(out, "{other}");
        }
    }
}

/// The digest of the members `names` of `doc`, absent ones included as absent.
fn digest_of(doc: &serde_json::Map<String, Value>, context: &str, names: &[&str]) -> [u8; 32] {
    let mut text = String::from(context);
    for n in names {
        text.push('\n');
        text.push_str(n);
        text.push('=');
        match doc.get(*n) {
            Some(v) => canonical(v, &mut text),
            None => text.push('-'),
        }
    }
    suiss_crypto::digest::sha256(text.as_bytes())
}

fn https_member(v: &Value) -> Result<Option<String>, CimdError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) if s.starts_with("https://") && s.len() <= 2048 && !s.contains('#') => {
            Ok(Some(s.clone()))
        }
        _ => Err(CimdError::Embedded),
    }
}

/// Whether `uri` is a loopback redirect URI (RFC 8252 §7.3, AG-6).
#[must_use]
pub fn is_loopback(uri: &str) -> bool {
    crate::domain::client::loopback(uri).is_some()
}

fn redirect_ok(uri: &str, kind: ApplicationType) -> bool {
    if uri.len() > 2048 || uri.contains(['#', '*']) || !uri.bytes().all(|c| c.is_ascii_graphic())
    {
        return false;
    }
    if is_loopback(uri) {
        return kind == ApplicationType::Native;
    }
    uri.strip_prefix("https://")
        .and_then(|r| r.split(['/', '?']).next())
        .is_some_and(|h| !h.is_empty() && !h.contains('@'))
}

/// AS-M11, AS-M13, §11.3.3, §11.3.1, §11.3.9: checks a fetched document against the URL it was
/// fetched from. Members Access does not know are kept and ignored (§11.8.3).
///
/// # Errors
/// [`CimdError`].
pub fn parse(bytes: &[u8], fetched_url: &str) -> Result<Document, CimdError> {
    if bytes.len() > MAX_DOCUMENT {
        return Err(CimdError::Json);
    }
    let Ok(Unique(Value::Object(doc))) = serde_json::from_slice::<Unique>(bytes) else {
        return Err(CimdError::Json);
    };
    if doc.get("client_id").and_then(Value::as_str) != Some(fetched_url) {
        return Err(CimdError::ClientId);
    }
    if doc.contains_key("client_secret") || doc.contains_key("client_secret_expires_at") {
        return Err(CimdError::Secret);
    }
    let client_name = doc
        .get("client_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.chars().count() <= MAX_NAME && !n.chars().any(char::is_control))
        .ok_or(CimdError::Missing)?;
    let declared = doc.get("application_type");
    let loopbacks = matches!(doc.get("redirect_uris"), Some(Value::Array(u))
        if u.iter().filter_map(Value::as_str).any(is_loopback));
    let application_type = match declared {
        None | Some(Value::Null) if loopbacks => ApplicationType::Native,
        None | Some(Value::Null) => ApplicationType::Web,
        Some(Value::String(s)) if s == "web" => ApplicationType::Web,
        Some(Value::String(s)) if s == "native" => ApplicationType::Native,
        Some(_) => return Err(CimdError::ApplicationType),
    };
    let Some(Value::Array(uris)) = doc.get("redirect_uris") else {
        return Err(CimdError::Missing);
    };
    if uris.is_empty() || uris.len() > MAX_REDIRECTS {
        return Err(CimdError::Missing);
    }
    let mut redirect_uris = Vec::with_capacity(uris.len());
    for u in uris {
        let u = u.as_str().ok_or(CimdError::Redirect)?;
        if !redirect_ok(u, application_type) {
            return Err(CimdError::Redirect);
        }
        redirect_uris.push(String::from(u));
    }
    let mut fetched = Vec::new();
    for name in FETCHED_FIELDS {
        if let Some(v) = doc.get(name)
            && let Some(u) = https_member(v)?
        {
            fetched.push(u);
        }
    }
    let method = match doc.get("token_endpoint_auth_method") {
        None | Some(Value::Null) => "none",
        Some(Value::String(m)) => m.as_str(),
        Some(_) => return Err(CimdError::Auth),
    };
    if SYMMETRIC_METHODS.contains(&method) {
        return Err(CimdError::Secret);
    }
    let jwks_uri = doc.get("jwks_uri").map(https_member).transpose()?.flatten();
    let jwks = match doc.get("jwks") {
        None | Some(Value::Null) => None,
        Some(v @ Value::Object(_)) => {
            let text = v.to_string();
            // §11.3.1
            parse_jwks(text.as_bytes()).map_err(|_| CimdError::Secret)?;
            Some(text)
        }
        Some(_) => return Err(CimdError::Auth),
    };
    let auth = match (method, jwks_uri, jwks) {
        ("none", None, None) => DocumentAuth::None,
        ("private_key_jwt", Some(u), None) => DocumentAuth::JwksUri(u),
        ("private_key_jwt", None, Some(j)) => DocumentAuth::Jwks(j),
        _ => return Err(CimdError::Auth),
    };
    let rs256 = match doc.get("token_endpoint_auth_signing_alg") {
        None | Some(Value::Null) => false,
        Some(Value::String(a)) if a == "ES256" => false,
        Some(Value::String(a)) if a == "RS256" => true,
        Some(_) => return Err(CimdError::Auth),
    };
    let logo_uri = doc.get("logo_uri").map(https_member).transpose()?.flatten();
    Ok(Document {
        client_id: String::from(fetched_url),
        client_name: String::from(client_name),
        redirect_uris,
        auth,
        rs256,
        application_type,
        logo_uri,
        fetched,
        authority_hash: digest_of(&doc, "access/cimd-authority/v1", &AUTHORITY_FIELDS),
        visual_hash: digest_of(&doc, "access/cimd-visual/v1", &VISUAL_FIELDS),
    })
}

/// What changed between the snapshot a consent was given against and the document now (AG-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Nothing that matters.
    None,
    /// Only `client_name` or `logo_uri`: shown as a warning, nothing ends.
    Visual,
    /// An authority member: the client's consent records end and consent is asked again with
    /// an AAS; no Grant is revoked.
    Authority,
}

/// AG-5: the change from `(authority, visual)` digests before to after.
#[must_use]
pub fn change(before: ([u8; 32], [u8; 32]), after: ([u8; 32], [u8; 32])) -> Change {
    if before.0 != after.0 {
        Change::Authority
    } else if before.1 != after.1 {
        Change::Visual
    } else {
        Change::None
    }
}

/// How long a fetched document is kept, seconds: its `max-age` clamped to
/// [[`CACHE_MIN_S`], [`CACHE_MAX_S`]], the shortest without one (§11.3.5, OP-154 m.3 (i)).
#[must_use]
pub fn keep_s(max_age_s: Option<u64>) -> u64 {
    max_age_s.unwrap_or(0).clamp(CACHE_MIN_S, CACHE_MAX_S)
}

/// Whether the client is new on the consent screen: first seen less than seven days ago.
#[must_use]
pub const fn new_app(first_seen_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(first_seen_ms) < NEW_APP_MS
}

/// Whether every redirect URI is a loopback one (AG-6): such a client gets the extra warning.
#[must_use]
pub fn loopback_only(redirect_uris: &[String]) -> bool {
    !redirect_uris.is_empty() && redirect_uris.iter().all(|u| is_loopback(u))
}

/// The hosts of `redirect_uris`, sorted, shown on the consent screen (AS-M14).
#[must_use]
pub fn redirect_hosts(redirect_uris: &[String]) -> Vec<String> {
    let hosts: BTreeSet<String> = redirect_uris
        .iter()
        .filter_map(|u| {
            let rest = u.split_once("://")?.1;
            let authority = rest.split(['/', '?']).next()?;
            let host = match authority.strip_prefix('[') {
                Some(v6) => format!("[{}]", v6.split(']').next()?),
                None => String::from(authority.split(':').next()?),
            };
            Some(host.to_ascii_lowercase())
        })
        .collect();
    hosts.into_iter().collect()
}

/// Whether `content_type` names a logo media type Access keeps (OP-154 m.3 (i)).
#[must_use]
pub fn logo_type(content_type: &str) -> Option<&'static str> {
    let base = content_type.split(';').next().unwrap_or_default().trim();
    LOGO_TYPES
        .into_iter()
        .find(|t| t.eq_ignore_ascii_case(base))
}

/// Whether `bytes` start as the raster image `kind` says; an SVG or anything else is refused.
#[must_use]
pub fn logo_bytes(kind: &str, bytes: &[u8]) -> bool {
    match kind {
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "image/webp" => bytes.get(..4) == Some(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
