//! The authorization request and its callback (OIDC Core §3.1.2, RFC 7636, RFC 9207,
//! RFC 9700 §2.1, §4.7): a fresh `state`, `nonce` and PKCE verifier per request, kept in a
//! [`Pending`] the caller stores until the browser returns. The callback is accepted only with
//! the same `state`, from the same issuer, and with a code; an error answer is a refusal.

use alloc::string::String;
use alloc::vec::Vec;

use super::discovery::Metadata;
use super::pkce::{self, Verifier};
use super::{OAuthClass, Random, RandomUnavailable, form, form_decode, random_text};

/// The relying party.
#[derive(Clone, Copy, Debug)]
pub struct Client<'a> {
    /// `client_id`.
    pub client_id: &'a str,
    /// The registered redirect URI, compared by the server as an exact string.
    pub redirect_uri: &'a str,
    /// Space-separated scopes; `openid` is added when missing.
    pub scope: &'a str,
}

/// What the RP keeps between the request and the callback. `Debug` hides the secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct Pending {
    /// The issuer the request went to.
    pub issuer: String,
    /// `client_id`.
    pub client_id: String,
    /// `redirect_uri`.
    pub redirect_uri: String,
    /// Whether the issuer sends `iss` on the callback (RFC 9207).
    pub iss_parameter: bool,
    state: String,
    nonce: String,
    verifier: Verifier,
}

impl core::fmt::Debug for Pending {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pending")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

/// A request to send the browser to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// The authorization endpoint with the query.
    pub url: String,
    /// What to keep for the callback.
    pub pending: Pending,
}

/// Builds the authorization request: `response_type=code`, `S256`, fresh `state` and `nonce`
/// of 32 random bytes each, and `dpop_jkt` when the tokens are to be DPoP-bound (RFC 9449 §10).
///
/// # Errors
/// [`RandomUnavailable`].
pub fn authorize(
    metadata: &Metadata,
    client: &Client<'_>,
    dpop_jkt: Option<&str>,
    rng: &impl Random,
) -> Result<AuthorizationRequest, RandomUnavailable> {
    let state = random_text::<32>(rng)?;
    let nonce = random_text::<32>(rng)?;
    let verifier = Verifier::generate(rng)?;
    let challenge = verifier.challenge();
    let mut scope = String::from(client.scope.trim());
    if !scope.split(' ').any(|s| s == "openid") {
        if !scope.is_empty() {
            scope.insert(0, ' ');
        }
        scope.insert_str(0, "openid");
    }
    let mut pairs: Vec<(&str, &str)> = alloc::vec![
        ("response_type", "code"),
        ("client_id", client.client_id),
        ("redirect_uri", client.redirect_uri),
        ("scope", scope.as_str()),
        ("state", state.as_str()),
        ("nonce", nonce.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", pkce::METHOD),
    ];
    if let Some(jkt) = dpop_jkt {
        pairs.push(("dpop_jkt", jkt));
    }
    let mut url = metadata.authorization_endpoint.clone();
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str(&form(&pairs));
    Ok(AuthorizationRequest {
        url,
        pending: Pending {
            issuer: metadata.issuer.clone(),
            client_id: String::from(client.client_id),
            redirect_uri: String::from(client.redirect_uri),
            iss_parameter: metadata.iss_parameter,
            state,
            nonce,
            verifier,
        },
    })
}

/// Why the callback is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CallbackError {
    /// The query is not form-encoded, or a member is repeated.
    #[error("callback-malformed")]
    Malformed,
    /// `state` is missing or not this request's (CSRF, RFC 9700 §4.7).
    #[error("callback-state")]
    State,
    /// `iss` is missing where the issuer sends it, or names another issuer (RFC 9207).
    #[error("callback-issuer")]
    Issuer,
    /// The server answered with an error (P15: unknown codes are [`OAuthClass::Refused`]).
    #[error("callback-refused")]
    Refused(OAuthClass),
    /// No `code`.
    #[error("callback-code")]
    NoCode,
}

/// The authorization code, for one token request. `Debug` hides it.
#[derive(Clone, PartialEq, Eq)]
pub struct Code(String);

impl core::fmt::Debug for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Code(..)")
    }
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

impl Pending {
    /// The `nonce` the ID token must carry.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Checks the callback query (the part after `?`, or the form body of `form_post`).
    ///
    /// # Errors
    /// [`CallbackError`].
    pub fn callback(&self, query: &str) -> Result<Code, CallbackError> {
        let mut params: Vec<(String, String)> = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = form_decode(k).ok_or(CallbackError::Malformed)?;
            let v = form_decode(v).ok_or(CallbackError::Malformed)?;
            if params.iter().any(|(n, _)| *n == k) {
                return Err(CallbackError::Malformed);
            }
            params.push((k, v));
        }
        let get = |name: &str| {
            params
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        if !get("state").is_some_and(|s| same(s, &self.state)) {
            return Err(CallbackError::State);
        }
        match get("iss") {
            Some(iss) if iss != self.issuer => return Err(CallbackError::Issuer),
            None if self.iss_parameter => return Err(CallbackError::Issuer),
            _ => {}
        }
        if let Some(code) = get("error") {
            return Err(CallbackError::Refused(OAuthClass::of(code)));
        }
        get("code")
            .filter(|c| !c.is_empty())
            .map(|c| Code(String::from(c)))
            .ok_or(CallbackError::NoCode)
    }

    /// The token request body for `code` (RFC 6749 §4.1.3, RFC 7636 §4.5); client
    /// authentication is the caller's (`private_key_jwt` or none for a public client).
    #[must_use]
    pub fn token_request(&self, code: &Code) -> String {
        form(&[
            ("grant_type", "authorization_code"),
            ("code", code.0.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("code_verifier", self.verifier.expose()),
        ])
    }
}

/// The refresh request body (RFC 6749 §6).
#[must_use]
pub fn refresh_request(client_id: &str, refresh_token: &str) -> String {
    form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ])
}
