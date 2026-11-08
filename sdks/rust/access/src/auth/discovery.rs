//! Authorization server metadata (OIDC Discovery 1.0, RFC 8414): read from the document the
//! caller fetched at [`well_known`] and held against the issuer the caller configured. The
//! `issuer` must be that exact string (RFC 8414 §3.3, mix-up defence); every endpoint is an
//! absolute `https` URL; `S256` must be offered, or PKCE could not be used and the RP refuses
//! the server (RFC 9700 §2.1.1).

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::json::{self, Json};

use super::pkce;
use crate::transport::Answer;

/// Largest metadata document read (§14.6).
pub const MAX_METADATA: usize = 64 * 1024;

/// The metadata URL of `issuer` (OIDC Discovery §4: the path is appended).
#[must_use]
pub fn well_known(issuer: &str) -> String {
    let mut out = String::from(issuer.trim_end_matches('/'));
    out.push_str("/.well-known/openid-configuration");
    out
}

/// Why the metadata is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// No answer, or a status other than 200.
    #[error("discovery-unavailable")]
    Unavailable,
    /// Not a JSON object.
    #[error("discovery-malformed")]
    Malformed,
    /// `issuer` is not the configured one.
    #[error("discovery-issuer")]
    Issuer,
    /// A required endpoint is missing or not an absolute `https` URL.
    #[error("discovery-endpoint: {0}")]
    Endpoint(&'static str),
    /// `S256` is not offered.
    #[error("discovery-pkce")]
    Pkce,
    /// `code` is not among the response types.
    #[error("discovery-response-type")]
    ResponseType,
}

/// What the RP uses of the metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// The issuer, as configured.
    pub issuer: String,
    /// `authorization_endpoint`.
    pub authorization_endpoint: String,
    /// `token_endpoint`.
    pub token_endpoint: String,
    /// `jwks_uri`.
    pub jwks_uri: String,
    /// `pushed_authorization_request_endpoint`, when offered.
    pub par_endpoint: Option<String>,
    /// `end_session_endpoint`, when offered.
    pub end_session_endpoint: Option<String>,
    /// `revocation_endpoint`, when offered.
    pub revocation_endpoint: Option<String>,
    /// `dpop_signing_alg_values_supported`.
    pub dpop_algs: Vec<String>,
    /// `authorization_response_iss_parameter_supported` (RFC 9207).
    pub iss_parameter: bool,
    /// `require_pushed_authorization_requests` (RFC 9126).
    pub require_par: bool,
}

/// Whether `url` is an absolute `https` URL without user information or fragment.
#[must_use]
pub fn is_https(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        let authority = rest.split(['/', '?']).next().unwrap_or("");
        !authority.is_empty() && !authority.contains('@') && !url.contains('#')
    })
}

fn endpoint(doc: &Json, name: &'static str) -> Result<String, DiscoveryError> {
    doc.get(name)
        .and_then(Json::as_str)
        .filter(|u| is_https(u))
        .map(String::from)
        .ok_or(DiscoveryError::Endpoint(name))
}

fn optional(doc: &Json, name: &'static str) -> Result<Option<String>, DiscoveryError> {
    match doc.get(name) {
        None => Ok(None),
        Some(_) => endpoint(doc, name).map(Some),
    }
}

fn strings(doc: &Json, name: &str) -> Option<Vec<String>> {
    match doc.get(name)? {
        Json::Array(items) => Some(
            items
                .iter()
                .filter_map(Json::as_str)
                .map(String::from)
                .collect(),
        ),
        _ => None,
    }
}

/// Reads the metadata the port fetched, for the configured `issuer`.
///
/// # Errors
/// [`DiscoveryError`].
pub fn parse(answer: &Answer, issuer: &str) -> Result<Metadata, DiscoveryError> {
    let Answer::Response(r) = answer else {
        return Err(DiscoveryError::Unavailable);
    };
    if r.status != 200 {
        return Err(DiscoveryError::Unavailable);
    }
    parse_document(&r.body, issuer)
}

/// [`parse`] on the document bytes.
///
/// # Errors
/// [`DiscoveryError`].
pub fn parse_document(body: &[u8], issuer: &str) -> Result<Metadata, DiscoveryError> {
    let doc = json::parse(body, MAX_METADATA).map_err(|_| DiscoveryError::Malformed)?;
    if !matches!(doc, Json::Object(_)) {
        return Err(DiscoveryError::Malformed);
    }
    // RFC 8414 §3.3
    if doc.get("issuer").and_then(Json::as_str) != Some(issuer) || !is_https(issuer) {
        return Err(DiscoveryError::Issuer);
    }
    // RFC 9700 §2.1.1
    if !strings(&doc, "code_challenge_methods_supported")
        .is_some_and(|m| m.iter().any(|x| x == pkce::METHOD))
    {
        return Err(DiscoveryError::Pkce);
    }
    if strings(&doc, "response_types_supported").is_some_and(|t| !t.iter().any(|x| x == "code")) {
        return Err(DiscoveryError::ResponseType);
    }
    Ok(Metadata {
        issuer: String::from(issuer),
        authorization_endpoint: endpoint(&doc, "authorization_endpoint")?,
        token_endpoint: endpoint(&doc, "token_endpoint")?,
        jwks_uri: endpoint(&doc, "jwks_uri")?,
        par_endpoint: optional(&doc, "pushed_authorization_request_endpoint")?,
        end_session_endpoint: optional(&doc, "end_session_endpoint")?,
        revocation_endpoint: optional(&doc, "revocation_endpoint")?,
        dpop_algs: strings(&doc, "dpop_signing_alg_values_supported").unwrap_or_default(),
        iss_parameter: matches!(
            doc.get("authorization_response_iss_parameter_supported"),
            Some(Json::Bool(true))
        ),
        require_par: matches!(
            doc.get("require_pushed_authorization_requests"),
            Some(Json::Bool(true))
        ),
    })
}
