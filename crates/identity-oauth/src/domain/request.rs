//! The authorization request (RFC 6749 §4.1.1, RFC 7636, RFC 9126, OIDC Core §3.1.2.1) as a
//! validated value. Validation runs in two stages: the client and redirect URI first, whose
//! failure is never redirected (RFC 6749 §4.1.2.1, TN-104); then everything else, whose failure
//! goes back to the client with `iss` (RFC 9207).

use access_kernel::json::b64url_decode;
use serde::{Deserialize, Serialize};

use crate::domain::client::Client;
use crate::domain::dpop::{Jkt, authorization_request_jkt};
use crate::domain::issuer::{Issuer, form_encode, with_iss};
use crate::domain::scope;

/// `openid`: an ID token is issued (OIDC Core §3.1.2.1).
pub const OPENID: &str = "openid";

/// The protocol scopes served (OP-146 m.5 (c)): `openid`, and `email` and `profile`, which
/// release only what the account holds honestly (§10.4.6, OP-153 m.3 (l)).
pub const SCOPES: [&str; 3] = [OPENID, "email", "profile"];

/// Longest `state` kept (PD).
pub const MAX_STATE: usize = 1024;

/// Longest `nonce` kept (PD).
pub const MAX_NONCE: usize = 255;

/// Most parameters read from one request.
pub const MAX_PARAMS: usize = 64;

/// The `request_uri` prefix of a pushed request (RFC 9126 §2.2).
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// What the user must do at the hosted login before a code can be issued (OIDC `prompt`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    /// Interact only when needed.
    #[default]
    Default,
    /// Never interact: answer `login_required` instead (OIDC Core §3.1.2.6).
    None,
    /// Authenticate again even with a live session.
    Login,
    /// Offer account creation (OIDC `prompt=create`).
    Create,
}

/// A validated authorization request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    /// The client.
    pub client_id: String,
    /// The redirect URI as presented; it matched a registered one (IDP-7).
    pub redirect_uri: String,
    /// Requested protocol scopes.
    pub scope: Vec<String>,
    /// `state`, returned as sent.
    pub state: Option<String>,
    /// OIDC `nonce`, echoed in the ID token.
    pub nonce: Option<String>,
    /// The S256 code challenge (RFC 7636).
    pub code_challenge: [u8; 32],
    /// `prompt`.
    pub prompt: Prompt,
    /// `max_age`, seconds.
    pub max_age_s: Option<u64>,
    /// `acr_values`, in order.
    pub acr_values: Vec<String>,
    /// `dpop_jkt` (RFC 9449 §10).
    pub dpop_jkt: Option<[u8; 32]>,
    /// The authority asked for (RFC 9396, RFC 8707): the token endpoint decides it later as a
    /// `projection.issue` (§9.9).
    #[serde(default)]
    pub authority: Option<AuthorityAsk>,
    /// The RFC 8707 resource of the protocol-scope access token: the `client_id` of a
    /// registered platform product client (OP-149 m.26 (a)); the realm itself when absent.
    #[serde(default)]
    pub resource: Option<String>,
    /// The OIDC `claims` request (OIDC Core §5.5, §10.4.6).
    #[serde(default)]
    pub claims: Option<crate::domain::claims_request::ClaimsAsk>,
}

/// The authority an authorization request asks for: the one resource server and the RFC 9396
/// details as sent; the token request may ask for these or fewer (RFC 9396 §6.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityAsk {
    /// The RFC 8707 resource.
    pub resource: String,
    /// `authorization_details` as sent.
    pub details: String,
}

impl AuthRequest {
    /// Whether an ID token is issued.
    #[must_use]
    pub fn openid(&self) -> bool {
        self.scope.iter().any(|s| s == OPENID)
    }

    /// The bound key, if any.
    #[must_use]
    pub fn jkt(&self) -> Option<Jkt> {
        self.dpop_jkt.map(Jkt)
    }

    /// The scope as one space-separated string.
    #[must_use]
    pub fn scope_text(&self) -> String {
        self.scope.join(" ")
    }
}

/// A request that cannot be returned to the client: the user sees a page, the browser is not
/// redirected (RFC 6749 §4.1.2.1, TN-104, X41).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unredirectable {
    /// `client_id` is missing, unknown or retired.
    #[error("invalid client")]
    Client,
    /// `redirect_uri` is missing or not registered for the client.
    #[error("invalid redirect_uri")]
    RedirectUri,
    /// A parameter is repeated or the request is malformed before the client is known.
    #[error("malformed request")]
    Malformed,
    /// A `request_uri` is unknown, expired, used, or another client's.
    #[error("invalid request_uri")]
    RequestUri,
}

impl Unredirectable {
    /// Stable reason code for the RFC 9457 problem.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Client => "invalid-client",
            Self::RedirectUri => "invalid-redirect-uri",
            Self::Malformed => "invalid-request",
            Self::RequestUri => "invalid-request-uri",
        }
    }
}

/// An authorization error that goes back to the client (RFC 6749 §4.1.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthError {
    /// The error code.
    pub error: &'static str,
    /// A short description for the developer.
    pub description: &'static str,
}

impl AuthError {
    const fn new(error: &'static str, description: &'static str) -> Self {
        Self { error, description }
    }

    /// `invalid_request`.
    #[must_use]
    pub const fn invalid_request(description: &'static str) -> Self {
        Self::new("invalid_request", description)
    }

    /// `invalid_request` for a client registered to require pushed authorization requests
    /// that sent its request to `/authorize` directly (RFC 9126 §6).
    pub const PAR_REQUIRED: Self = Self::new(
        "invalid_request",
        "this client must push its authorization requests to the pushed authorization request endpoint",
    );

    /// `login_required`: the same answer whether or not any account exists (CR-40).
    pub const LOGIN_REQUIRED: Self = Self::new("login_required", "the user is not signed in");

    /// `consent_required`: a third party asks for claims the person has not shared (OIDC Core
    /// §3.1.2.6, OP-153 m.3 (z)).
    pub const CONSENT_REQUIRED: Self = Self::new(
        "consent_required",
        "the person has not shared these claims with this app",
    );

    /// `access_denied`.
    pub const ACCESS_DENIED: Self = Self::new("access_denied", "the request was denied");

    /// `temporarily_unavailable` (RFC 6749 §4.1.2.1).
    pub const UNAVAILABLE: Self = Self::new(
        "temporarily_unavailable",
        "the service is temporarily unavailable",
    );
}

/// Request parameters as decoded pairs. A parameter sent twice is refused (RFC 6749 §3.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Params(Vec<(String, String)>);

impl Params {
    /// From decoded pairs.
    ///
    /// # Errors
    /// [`Unredirectable::Malformed`] for a repeated or empty-named parameter, or too many.
    pub fn new(pairs: Vec<(String, String)>) -> Result<Self, Unredirectable> {
        if pairs.len() > MAX_PARAMS {
            return Err(Unredirectable::Malformed);
        }
        for (i, (k, _)) in pairs.iter().enumerate() {
            if k.is_empty() || pairs.iter().skip(i.saturating_add(1)).any(|(o, _)| o == k) {
                return Err(Unredirectable::Malformed);
            }
        }
        Ok(Self(pairs))
    }

    /// Parses an `application/x-www-form-urlencoded` body or query.
    ///
    /// # Errors
    /// [`Unredirectable::Malformed`].
    pub fn parse(text: &str) -> Result<Self, Unredirectable> {
        let mut pairs = Vec::new();
        for part in text.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            let k = crate::domain::client::form_decode(k).ok_or(Unredirectable::Malformed)?;
            let v = crate::domain::client::form_decode(v).ok_or(Unredirectable::Malformed)?;
            pairs.push((k, v));
        }
        Self::new(pairs)
    }

    /// The value of `name`; an empty value counts as absent (RFC 6749 §3.1).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
}

fn challenge(text: &str) -> Option<[u8; 32]> {
    if text.len() != 43 {
        return None;
    }
    b64url_decode(text).ok()?.try_into().ok()
}

/// Stage one: the client and its redirect URI (IDP-7). Nothing is redirected before this
/// passes.
///
/// # Errors
/// [`Unredirectable`].
pub fn stage_one<'a>(
    params: &'a Params,
    client: Option<&Client>,
) -> Result<&'a str, Unredirectable> {
    let client = client.ok_or(Unredirectable::Client)?;
    let redirect = params
        .get("redirect_uri")
        .ok_or(Unredirectable::RedirectUri)?;
    if !client.redirect_allowed(redirect) {
        return Err(Unredirectable::RedirectUri);
    }
    Ok(redirect)
}

/// The requested scopes: protocol scopes this realm serves. A resource scope is refused first
/// (§2.2.2 #2, L24, S-1): resource access is asked for as `authorization_details`.
fn scopes(params: &Params) -> Result<Vec<String>, AuthError> {
    let scope: Vec<String> = params
        .get("scope")
        .unwrap_or_default()
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if scope
        .iter()
        .any(|s| scope::classify(s) == scope::ScopeClass::Resource)
    {
        return Err(AuthError::new("invalid_scope", scope::RESOURCE_SCOPE));
    }
    if scope.iter().any(|s| !SCOPES.contains(&s.as_str())) {
        return Err(AuthError::new("invalid_scope", "unknown scope"));
    }
    Ok(scope)
}

/// Stage two: everything after the redirect URI is known good (RFC 6749 §4.1.1, RFC 7636,
/// RFC 8707, RFC 9449 §10, OIDC Core §3.1.2.1). A protocol-scope token names `issuer` or, as
/// `resource`, a registered platform product client: `product` is that client's `client_id`
/// when the request's `resource` names one (OP-146 m.5 (c), OP-149 m.26 (a)).
///
/// # Errors
/// [`AuthError`].
pub fn stage_two(
    params: &Params,
    client: &Client,
    redirect_uri: &str,
    issuer: &Issuer,
    product: Option<&str>,
) -> Result<AuthRequest, AuthError> {
    // IDP-7, TN-34
    match params.get("response_type") {
        Some("code") => {}
        Some(_) => {
            return Err(AuthError::new(
                "unsupported_response_type",
                "only response_type=code is supported",
            ));
        }
        None => return Err(AuthError::invalid_request("response_type is required")),
    }
    if params.get("response_mode").is_some_and(|m| m != "query") {
        return Err(AuthError::invalid_request(
            "only response_mode=query is supported",
        ));
    }
    if params.get("request").is_some() {
        return Err(AuthError::new(
            "request_not_supported",
            "request objects are not supported",
        ));
    }
    if params.get("request_uri").is_some() {
        return Err(AuthError::new(
            "request_uri_not_supported",
            "only request_uri values from the pushed authorization endpoint are accepted",
        ));
    }
    // IDP-7, §10.4.1
    if params.get("code_challenge_method") != Some("S256") {
        return Err(AuthError::invalid_request(
            "code_challenge_method=S256 is required",
        ));
    }
    let code_challenge = params
        .get("code_challenge")
        .and_then(challenge)
        .ok_or(AuthError::invalid_request("code_challenge is required"))?;
    let scope = scopes(params)?;
    let mut prompts = params
        .get("prompt")
        .unwrap_or_default()
        .split(' ')
        .filter(|p| !p.is_empty());
    let prompt = match (prompts.next(), prompts.next()) {
        (None, _) => Prompt::Default,
        (Some("none"), None) => Prompt::None,
        (Some("login"), None) => Prompt::Login,
        (Some("create"), None) => Prompt::Create,
        _ => return Err(AuthError::invalid_request("unsupported prompt")),
    };
    let max_age_s = params
        .get("max_age")
        .map(|m| {
            m.parse::<u64>()
                .map_err(|_| AuthError::invalid_request("max_age is not a number"))
        })
        .transpose()?;
    let acr_values = params
        .get("acr_values")
        .unwrap_or_default()
        .split(' ')
        .filter(|a| !a.is_empty())
        .take(8)
        .map(String::from)
        .collect();
    let dpop_jkt = authorization_request_jkt(params.get("dpop_jkt"))
        .map_err(|_| AuthError::invalid_request("dpop_jkt is malformed"))?
        .map(|j| j.0);
    let (authority, resource) = authority_ask(params, issuer, product)?;
    // §10.4.6, OP-148
    let claims = params
        .get("claims")
        .map(|raw| {
            crate::domain::claims_request::parse(raw)
                .map(|r| crate::domain::claims_request::ClaimsAsk::from(&r))
                .map_err(|_| AuthError::invalid_request("claims is malformed"))
        })
        .transpose()?;
    let state = params.get("state").map(String::from);
    let nonce = params.get("nonce").map(String::from);
    if state.as_ref().is_some_and(|s| s.len() > MAX_STATE)
        || nonce.as_ref().is_some_and(|n| n.len() > MAX_NONCE)
    {
        return Err(AuthError::invalid_request("state or nonce too long"));
    }
    Ok(AuthRequest {
        client_id: client.id.clone(),
        redirect_uri: String::from(redirect_uri),
        scope,
        state,
        nonce,
        code_challenge,
        prompt,
        max_age_s,
        acr_values,
        dpop_jkt,
        authority,
        resource,
        claims,
    })
}

/// The authority an authorization request asks for (RFC 9396, §9.9, AG-8): one resource server,
/// never a default one, and valid details. Without details the resource is the realm, or a
/// registered platform product client (`product`) the protocol-scope token is then addressed
/// to (RFC 8707, OP-149 m.26 (a)); anything else is `invalid_target`.
fn authority_ask(
    params: &Params,
    issuer: &Issuer,
    product: Option<&str>,
) -> Result<(Option<AuthorityAsk>, Option<String>), AuthError> {
    let resource = params.get("resource");
    let Some(details) = params.get(crate::domain::authority::DETAILS_PARAM) else {
        // RFC 8707, AG-8
        return match resource {
            None => Ok((None, None)),
            Some(r) if r == issuer.as_str() => Ok((None, None)),
            Some(r) if product == Some(r) => Ok((None, Some(String::from(r)))),
            Some(_) => Err(AuthError::new("invalid_target", "unknown resource")),
        };
    };
    let Some(resource) = resource.filter(|r| *r != issuer.as_str()) else {
        return Err(AuthError::new(
            "invalid_target",
            "one resource server is required",
        ));
    };
    if crate::domain::authority::parse_details(details, resource).is_err() {
        return Err(AuthError::new(
            "invalid_authorization_details",
            "the authorization details are not valid",
        ));
    }
    Ok((
        Some(AuthorityAsk {
            resource: String::from(resource),
            details: String::from(details),
        }),
        None,
    ))
}

/// The authorization error response: `redirect_uri` with `error`, `error_description`,
/// `state` and `iss` (RFC 6749 §4.1.2.1, RFC 9207, TN-11).
#[must_use]
pub fn error_redirect(
    redirect_uri: &str,
    error: AuthError,
    state: Option<&str>,
    issuer: &Issuer,
) -> String {
    let mut q = format!("error={}&error_description=", error.error);
    form_encode(error.description, &mut q);
    if let Some(s) = state {
        q.push_str("&state=");
        form_encode(s, &mut q);
    }
    with_iss(&append(redirect_uri, &q), issuer)
}

/// The success response: `redirect_uri` with `code`, `state` and `iss` (RFC 9207).
#[must_use]
pub fn code_redirect(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
    issuer: &Issuer,
) -> String {
    let mut q = String::from("code=");
    form_encode(code, &mut q);
    if let Some(s) = state {
        q.push_str("&state=");
        form_encode(s, &mut q);
    }
    with_iss(&append(redirect_uri, &q), issuer)
}

fn append(uri: &str, query: &str) -> String {
    let sep = if uri.contains('?') { '&' } else { '?' };
    format!("{uri}{sep}{query}")
}

#[cfg(test)]
mod tests;
