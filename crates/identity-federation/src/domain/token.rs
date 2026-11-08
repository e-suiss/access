//! The relying party's checks, sans I/O (OP-63): the authorization request, the token answer
//! and the ID token, all decided in the back end (§10.2.6, OP-153 m.3 (l)). An ID token is
//! accepted only with a signature by a provider key under an algorithm the preset names, the
//! expected `iss`, our client in `aud`, an unexpired `exp` and the flow's `nonce`.

use access_crypto::oauth::{ClientAlg, verify_client_signature};
use access_identity_oauth::domain::issuer::form_encode;
use access_identity_oauth::domain::jwt::{Jwk, SKEW_MS};
use access_kernel::json::{b64url_decode, b64url_encode};
use serde_json::Value;

use super::preset::{EmailAssurance, Preset, Protocol, ResponseMode};

/// Largest ID token read.
pub const MAX_ID_TOKEN: usize = 16 * 1024;

/// Largest token, user-info or address list answer read.
pub const MAX_ANSWER: usize = 64 * 1024;

/// Why a provider answer is refused; every refusal ends the attempt with nothing linked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Not a compact JWS or not JSON.
    #[error("format")]
    Format,
    /// The header's algorithm is not one the preset names (MD-3).
    #[error("algorithm")]
    Algorithm,
    /// No provider key verifies the signature.
    #[error("signature")]
    Signature,
    /// `iss` is not the provider's.
    #[error("issuer")]
    Issuer,
    /// Our client is not the audience.
    #[error("audience")]
    Audience,
    /// Expired or issued in the future.
    #[error("time")]
    Time,
    /// `nonce` is not the flow's.
    #[error("nonce")]
    Nonce,
    /// The subject claims are missing.
    #[error("subject")]
    Subject,
    /// The token endpoint refused the code or answered something else.
    #[error("token answer")]
    Answer,
}

/// What an ID token must say.
#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    /// Our client id at the provider.
    pub client_id: &'a str,
    /// The flow's nonce.
    pub nonce: &'a str,
    /// Trusted now.
    pub now_ms: u64,
}

/// RFC 7636 `S256` of `verifier`.
#[must_use]
pub fn pkce_challenge(verifier: &str) -> String {
    b64url_encode(&suiss_crypto::digest::sha256(verifier.as_bytes()))
}

/// The authorization request's secrets: `state`, `nonce` and the PKCE verifier, each 256
/// random bits as base64url, from the caller's RNG (OP-63).
#[derive(Clone, PartialEq, Eq)]
pub struct Secrets {
    /// `state`.
    pub state: String,
    /// `nonce`.
    pub nonce: String,
    /// The PKCE verifier.
    pub verifier: String,
}

impl core::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secrets(<redacted>)")
    }
}

impl Secrets {
    /// From 96 random bytes.
    #[must_use]
    pub fn from_random(r: &[u8; 96]) -> Self {
        let (a, rest) = r.split_at(32);
        let (b, c) = rest.split_at(32);
        Self {
            state: b64url_encode(a),
            nonce: b64url_encode(b),
            verifier: b64url_encode(c),
        }
    }
}

fn push(out: &mut String, name: &str, value: &str) {
    out.push(if out.contains('?') { '&' } else { '?' });
    out.push_str(name);
    out.push('=');
    form_encode(value, out);
}

/// The authorization request URL: code flow with PKCE `S256`, `state`, and `nonce` for OIDC.
#[must_use]
pub fn authorization_url(p: &Preset, client_id: &str, redirect_uri: &str, s: &Secrets) -> String {
    let mut out = p.authorization_endpoint.clone();
    push(&mut out, "response_type", "code");
    push(&mut out, "client_id", client_id);
    push(&mut out, "redirect_uri", redirect_uri);
    push(&mut out, "scope", &p.scopes.join(" "));
    push(&mut out, "state", &s.state);
    push(&mut out, "code_challenge", &pkce_challenge(&s.verifier));
    push(&mut out, "code_challenge_method", "S256");
    if p.protocol == Protocol::Oidc {
        push(&mut out, "nonce", &s.nonce);
    }
    if p.response_mode == ResponseMode::FormPost {
        push(&mut out, "response_mode", "form_post");
    }
    out
}

/// The token request's form body; the client authenticates with `client_secret_post`.
#[must_use]
pub fn token_form(
    client_id: &str,
    secret: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> String {
    let mut out = String::new();
    for (n, v) in [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", secret),
        ("code_verifier", verifier),
    ] {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(n);
        out.push('=');
        form_encode(v, &mut out);
    }
    out
}

/// What a token answer carries.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenAnswer {
    /// The access token, for user-info.
    pub access_token: String,
    /// The ID token, for OIDC.
    pub id_token: Option<String>,
}

impl core::fmt::Debug for TokenAnswer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TokenAnswer(<redacted>)")
    }
}

/// Reads a `200` token answer.
///
/// # Errors
/// [`TokenError::Answer`].
pub fn token_answer(status: u16, body: &[u8]) -> Result<TokenAnswer, TokenError> {
    if status != 200 || body.len() > MAX_ANSWER {
        return Err(TokenError::Answer);
    }
    let v: Value = serde_json::from_slice(body).map_err(|_| TokenError::Answer)?;
    let access_token = v
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or(TokenError::Answer)?;
    Ok(TokenAnswer {
        access_token: access_token.into(),
        id_token: v.get("id_token").and_then(Value::as_str).map(String::from),
    })
}

fn eq_ct(a: &str, b: &str) -> bool {
    let (a, b) = (
        suiss_crypto::digest::sha256(a.as_bytes()),
        suiss_crypto::digest::sha256(b.as_bytes()),
    );
    access_crypto::Secret::new(a).ct_eq_bytes(&b)
}

/// Checks an ID token of `p` against `keys` and `e`; returns its claims.
///
/// # Errors
/// [`TokenError`].
pub fn check_id_token(
    token: &str,
    preset: &Preset,
    keys: &[Jwk],
    expect: &Expect<'_>,
) -> Result<Value, TokenError> {
    if token.len() > MAX_ID_TOKEN {
        return Err(TokenError::Format);
    }
    let mut parts = token.split('.');
    let (Some(head), Some(body), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenError::Format);
    };
    let header: Value = b64url_decode(head)
        .ok()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .ok_or(TokenError::Format)?;
    let alg_name = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(TokenError::Algorithm)?;
    // MD-3
    if !preset.algorithms.iter().any(|a| a == alg_name) {
        return Err(TokenError::Algorithm);
    }
    let alg = ClientAlg::from_name(alg_name)
        .filter(|a| matches!(a, ClientAlg::Rs256 | ClientAlg::Es256))
        .ok_or(TokenError::Algorithm)?;
    let kid = header.get("kid").and_then(Value::as_str);
    let signature = b64url_decode(sig).map_err(|_| TokenError::Format)?;
    let input = token
        .get(..head.len().saturating_add(1).saturating_add(body.len()))
        .ok_or(TokenError::Format)?;
    let verified = keys
        .iter()
        .filter(|k| kid.is_none_or(|id| k.kid.as_deref() == Some(id)))
        .any(|k| verify_client_signature(alg, &k.key, input.as_bytes(), &signature).is_ok());
    if !verified {
        return Err(TokenError::Signature);
    }
    let claims: Value = b64url_decode(body)
        .ok()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .filter(Value::is_object)
        .ok_or(TokenError::Format)?;
    let iss = claims.get("iss").and_then(Value::as_str);
    if iss.is_none() || iss != preset.issuer_for(&claims).as_deref() {
        return Err(TokenError::Issuer);
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == expect.client_id,
        Some(Value::Array(list)) => {
            list.iter().any(|a| a.as_str() == Some(expect.client_id))
                && (list.len() == 1
                    || claims.get("azp").and_then(Value::as_str) == Some(expect.client_id))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(TokenError::Audience);
    }
    let secs = |name: &str| claims.get(name).and_then(Value::as_u64);
    let exp_ms = secs("exp")
        .and_then(|s| s.checked_mul(1000))
        .ok_or(TokenError::Time)?;
    if exp_ms.saturating_add(SKEW_MS) <= expect.now_ms {
        return Err(TokenError::Time);
    }
    if let Some(iat) = secs("iat").and_then(|s| s.checked_mul(1000))
        && iat > expect.now_ms.saturating_add(SKEW_MS)
    {
        return Err(TokenError::Time);
    }
    let nonce = claims.get("nonce").and_then(Value::as_str);
    if !nonce.is_some_and(|n| eq_ct(n, expect.nonce)) {
        return Err(TokenError::Nonce);
    }
    Ok(claims)
}

/// The provider's subject from `claims` (TN-66): the preset's subject claims, in order, joined
/// by `:`; a number is taken in its decimal form.
///
/// # Errors
/// [`TokenError::Subject`].
pub fn subject_of(p: &Preset, claims: &Value) -> Result<String, TokenError> {
    let mut parts = Vec::with_capacity(p.subject.len());
    for name in &p.subject {
        let v = match claims.get(name) {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(Value::Number(n)) if n.is_u64() => n.to_string(),
            _ => return Err(TokenError::Subject),
        };
        if v.len() > 255 || v.chars().any(char::is_control) {
            return Err(TokenError::Subject);
        }
        parts.push(v);
    }
    Ok(parts.join(":"))
}

/// An address the provider gave, with what it is worth.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderEmail {
    /// The address as given.
    pub address: String,
    /// Whether the provider vouches for it under its preset (IDP-31 (3)); an unvouched address
    /// is kept `unconfirmed` and proven by our own code before any use.
    pub vouched: bool,
}

impl core::fmt::Debug for ProviderEmail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderEmail")
            .field("address", &"<redacted>")
            .field("vouched", &self.vouched)
            .finish()
    }
}

fn domain(address: &str) -> Option<String> {
    address
        .rsplit_once('@')
        .map(|(_, d)| d.to_ascii_lowercase())
        .filter(|d| !d.is_empty())
}

/// The address of `claims` and what `p`'s preset says it is worth. `emails` is the provider's
/// address list for [`EmailAssurance::VerifiedPrimary`].
#[must_use]
pub fn email_of(p: &Preset, claims: &Value, emails: Option<&Value>) -> Option<ProviderEmail> {
    let truthy = |v: Option<&Value>| match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    };
    if let EmailAssurance::VerifiedPrimary = p.email {
        let list = emails?.as_array()?;
        let primary = list
            .iter()
            .find(|e| truthy(e.get("primary")))
            .or_else(|| list.first())?;
        return Some(ProviderEmail {
            address: primary.get("email")?.as_str()?.into(),
            vouched: truthy(primary.get("verified")) && truthy(primary.get("primary")),
        });
    }
    let address = claims.get("email")?.as_str()?;
    if address.len() > 320 || !address.contains('@') {
        return None;
    }
    let vouched = match &p.email {
        EmailAssurance::VerifiedClaim => truthy(claims.get("email_verified")),
        EmailAssurance::AuthoritativeDomains {
            domains,
            hosted_domain_claim,
        } => {
            let d = domain(address);
            let consumer = d.as_ref().is_some_and(|d| domains.iter().any(|x| x == d));
            let hosted = hosted_domain_claim
                .as_deref()
                .and_then(|c| claims.get(c))
                .and_then(Value::as_str)
                .is_some_and(|hd| d.as_deref() == Some(&hd.to_ascii_lowercase()));
            (consumer || hosted) && truthy(claims.get("email_verified"))
        }
        EmailAssurance::Claim { claim } => truthy(claims.get(claim)),
        EmailAssurance::VerifiedPrimary | EmailAssurance::None => false,
    };
    Some(ProviderEmail {
        address: address.into(),
        vouched,
    })
}

#[cfg(test)]
mod tests;
