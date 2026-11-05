//! What the authorization server issues (OP-146 m.5 (c), §10.4 (ii)): identity assertions
//! only. The ID token (≤ 5 minutes, MD-7), the protocol-scope access token (RFC 9068,
//! `at+jwt`, one audience, `cnf.jkt` always: there is no bearer token, TN-27), the logout token
//! (OIDC Back-Channel Logout §2.4), and the lifetimes and session rules behind them.

use access_identity_session::domain::assurance::Aal;
use serde_json::{Map, Value, json};

use crate::domain::issuer::Issuer;
use crate::domain::request::{AuthRequest, Prompt};

/// Authorization code lifetime (PD; RFC 6749 §4.1.2: at most 10 minutes).
pub const CODE_TTL_MS: u64 = 60_000;

/// Pushed request lifetime (RFC 9126 §2.2, PD).
pub const PAR_TTL_MS: u64 = 60_000;

/// How long a request waits while the user signs in (the flow lifetime, PD).
pub const INTERACTIVE_TTL_MS: u64 = 30 * 60 * 1000;

/// Access token lifetime: the 10-minute default of the 5–15 minute range (MD-7, PD).
pub const ACCESS_TTL_MS: u64 = 10 * 60 * 1000;

/// ID token lifetime (§10.4.5: ≤ 5 minutes, PD).
pub const ID_TTL_MS: u64 = 5 * 60 * 1000;

/// Logout token lifetime (PD).
pub const LOGOUT_TTL_MS: u64 = 2 * 60 * 1000;

/// `typ` of the ID token.
pub const ID_TYP: &str = "JWT";

/// `typ` of the access token (RFC 9068 §2.1).
pub const ACCESS_TYP: &str = "at+jwt";

/// `typ` of the logout token (OIDC Back-Channel Logout §2.4).
pub const LOGOUT_TYP: &str = "logout+jwt";

/// The identity outbox kind of a `projection-invalidated` event: a refresh family of authority
/// tokens ended on reuse (§9.9.3 rule 6, §9.16).
pub const INVALIDATED_OUTBOX: &str = "event.projection_invalidated";

/// The back-channel logout event (OIDC Back-Channel Logout §2.4).
pub const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The outbox kind of a logout notice: the grants whose clients' back-channel endpoints get a
/// logout token.
pub const LOGOUT_OUTBOX: &str = access_store::backchannel::LOGOUT_KIND;

/// The `acr` of an AAL (NIST SP 800-63-4 identifiers).
#[must_use]
pub const fn acr(aal: Aal) -> &'static str {
    match aal {
        Aal::Aal1 => "http://idmanagement.gov/ns/assurance/aal/1",
        Aal::Aal2 => "http://idmanagement.gov/ns/assurance/aal/2",
        Aal::Aal3 => "http://idmanagement.gov/ns/assurance/aal/3",
    }
}

/// The AAL an `acr` value asks for; unknown values ask for nothing (`acr_values` is
/// voluntary, OIDC Core §3.1.2.1).
#[must_use]
pub fn aal_of(acr_value: &str) -> Option<Aal> {
    [Aal::Aal1, Aal::Aal2, Aal::Aal3]
        .into_iter()
        .find(|a| acr(*a) == acr_value)
}

/// What the hosted login is asked to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginReason {
    /// No live session.
    SignIn,
    /// Authenticate again: `prompt=login` or `max_age` (OIDC Core §3.1.2.1).
    Reauthenticate,
    /// Offer account creation (`prompt=create`).
    Create,
    /// Reach at least this AAL (`acr_values`, RFC 9470).
    StepUp(Aal),
}

/// The live session facts the request is held against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signed {
    /// Authentication time, Unix milliseconds.
    pub auth_time_ms: u64,
    /// Its AAL.
    pub aal: Aal,
}

/// Whether the hosted login must run before a code is issued. A session authenticated after
/// the request was stored has answered it (`prompt=login`, `max_age`, `acr_values` are
/// satisfied by that fresh sign-in), so a returning browser never loops.
#[must_use]
pub fn needs_login(
    req: &AuthRequest,
    session: Option<Signed>,
    request_created_ms: u64,
    now_ms: u64,
) -> Option<LoginReason> {
    let Some(s) = session else {
        return Some(match req.prompt {
            Prompt::Create => LoginReason::Create,
            _ => LoginReason::SignIn,
        });
    };
    if s.auth_time_ms >= request_created_ms {
        return None;
    }
    match req.prompt {
        Prompt::Login => return Some(LoginReason::Reauthenticate),
        Prompt::Create => return Some(LoginReason::Create),
        Prompt::Default | Prompt::None => {}
    }
    if let Some(max) = req.max_age_s {
        let age = now_ms.saturating_sub(s.auth_time_ms);
        if age > max.saturating_mul(1000) {
            return Some(LoginReason::Reauthenticate);
        }
    }
    let wanted = req.acr_values.iter().filter_map(|a| aal_of(a)).min();
    match wanted {
        Some(w) if w > s.aal => Some(LoginReason::StepUp(w)),
        _ => None,
    }
}

/// The facts behind every token of one grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenFacts<'a> {
    /// The realm issuer.
    pub issuer: &'a Issuer,
    /// The client.
    pub client_id: &'a str,
    /// The pairwise subject (MD-10).
    pub sub: &'a str,
    /// The grant's `sid`, base64url.
    pub sid: &'a str,
    /// Authentication time, Unix milliseconds.
    pub auth_time_ms: u64,
    /// The AAL of that authentication.
    pub aal: Aal,
    /// Issue time, Unix milliseconds.
    pub now_ms: u64,
}

fn secs(ms: u64) -> u64 {
    ms / 1000
}

/// The ID token claims (OIDC Core §2): one audience, `typ` JWT, ≤ 5 minutes.
#[must_use]
pub fn id_token_claims(f: &TokenFacts<'_>, nonce: Option<&str>) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("iss".into(), f.issuer.as_str().into());
    m.insert("sub".into(), f.sub.into());
    m.insert("aud".into(), f.client_id.into());
    m.insert("iat".into(), secs(f.now_ms).into());
    m.insert(
        "exp".into(),
        secs(f.now_ms.saturating_add(ID_TTL_MS)).into(),
    );
    m.insert("auth_time".into(), secs(f.auth_time_ms).into());
    m.insert("acr".into(), acr(f.aal).into());
    m.insert("sid".into(), f.sid.into());
    if let Some(n) = nonce {
        m.insert("nonce".into(), n.into());
    }
    Value::Object(m).to_string().into_bytes()
}

/// The protocol-scope access token claims (RFC 9068 §2.2): audience the realm itself, the
/// only resource Stage 5 serves; always bound by `cnf.jkt` (TN-27, PI-11).
#[must_use]
pub fn access_token_claims(f: &TokenFacts<'_>, scope: &str, jti: &str, jkt: &str) -> Vec<u8> {
    json!({
        "iss": f.issuer.as_str(),
        "sub": f.sub,
        "aud": f.issuer.as_str(),
        "client_id": f.client_id,
        "iat": secs(f.now_ms),
        "exp": secs(f.now_ms.saturating_add(ACCESS_TTL_MS)),
        "jti": jti,
        "scope": scope,
        "sid": f.sid,
        "auth_time": secs(f.auth_time_ms),
        "acr": acr(f.aal),
        "cnf": { "jkt": jkt },
    })
    .to_string()
    .into_bytes()
}

/// The logout token claims (OIDC Back-Channel Logout §2.4): `events`, `sid` and `sub`, never a
/// `nonce`.
#[must_use]
pub fn logout_token_claims(
    issuer: &Issuer,
    client_id: &str,
    sub: &str,
    sid: &str,
    jti: &str,
    now_ms: u64,
) -> Vec<u8> {
    json!({
        "iss": issuer.as_str(),
        "aud": client_id,
        "sub": sub,
        "sid": sid,
        "iat": secs(now_ms),
        "exp": secs(now_ms.saturating_add(LOGOUT_TTL_MS)),
        "jti": jti,
        "events": { LOGOUT_EVENT: {} },
    })
    .to_string()
    .into_bytes()
}

/// What a grant carries for its later tokens.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantDetails {
    /// Granted scope.
    pub scope: String,
    /// Authentication time, Unix milliseconds.
    pub auth_time_ms: u64,
    /// AAL of that authentication.
    pub aal: Aal,
    /// Whether an ID token is issued.
    pub openid: bool,
    /// The authority the grant was asked for; its tokens are `projection.issue` decisions.
    #[serde(default)]
    pub authority: Option<crate::domain::request::AuthorityAsk>,
    /// The refresh family of its authority tokens, once the first one is issued (P50).
    #[serde(default)]
    pub family: Option<[u8; 16]>,
    /// The `ExerciseID` of the family's first token.
    #[serde(default)]
    pub projection: Option<[u8; 32]>,
}

/// What a code carries to the token endpoint.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CodeDetails {
    /// The redirect URI of the request, checked again at the exchange (IDP-7).
    pub redirect_uri: String,
    /// The S256 challenge.
    pub code_challenge: [u8; 32],
    /// `dpop_jkt` of the request.
    pub dpop_jkt: Option<[u8; 32]>,
    /// OIDC `nonce`.
    pub nonce: Option<String>,
    /// What the grant will carry.
    pub grant: GrantDetails,
}

#[cfg(test)]
mod tests;
