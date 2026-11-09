//! A connection's `TokenSet` and the upstream's OAuth 2.0 messages (RFC 6749 §4.1, §6, RFC 7009,
//! RFC 7636): what Access sends, what it reads back, and the lifetime and revocation facts it
//! learns from `expires_in`, the upstream's `revocation_endpoint` and the catalog (AG-40 (5)).
//! A `TokenSet` is possession, never authority (AGI-2); its tokens are never printed.

use access_crypto::Secret;
use access_identity_oauth::domain::issuer::form_encode;
use serde_json::{Value as Json, json};

use crate::domain::catalog::{Refresh, Upstream};

/// Largest upstream answer read.
pub const MAX_ANSWER: usize = 64 * 1024;

/// Longest token kept.
pub const MAX_TOKEN: usize = 8 * 1024;

/// Longest `expires_in` believed: one year.
pub const MAX_EXPIRES_IN_S: u64 = 31_536_000;

/// The tokens of one connection.
#[derive(Clone)]
pub struct TokenSet {
    /// The upstream access token.
    pub access_token: Secret<String>,
    /// The refresh token, when the upstream gave one.
    pub refresh_token: Option<Secret<String>>,
    /// `token_type`, as the upstream named it.
    pub token_type: String,
    /// The scopes the upstream granted, when it said.
    pub scope: Option<String>,
    /// When the access token expires, Unix milliseconds, when known.
    pub expires_at: Option<u64>,
}

impl core::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenSet")
            .field("token_type", &self.token_type)
            .field("refreshable", &self.refresh_token.is_some())
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// An upstream answer Access does not accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The upstream refused the grant (`invalid_grant` and the like): the person must connect
    /// again.
    #[error("refused")]
    Refused,
    /// Not a token answer.
    #[error("malformed")]
    Malformed,
}

fn token(v: &Json, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Json::as_str)
        .filter(|t| (1..=MAX_TOKEN).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_graphic()))
        .map(String::from)
}

impl TokenSet {
    /// Reads a token answer at `now_ms` (RFC 6749 §5.1). The lifetime comes from `expires_in`,
    /// else from the catalog's documented lifetime, else it is unknown. A refresh answer
    /// without a refresh token keeps `previous` only when the upstream reuses refresh tokens.
    ///
    /// # Errors
    /// [`TokenError`].
    pub fn from_answer(
        (status, body): (u16, &[u8]),
        upstream: &Upstream,
        previous: Option<&Secret<String>>,
        now_ms: u64,
    ) -> Result<Self, TokenError> {
        if body.len() > MAX_ANSWER {
            return Err(TokenError::Malformed);
        }
        let v: Json = serde_json::from_slice(body).map_err(|_| TokenError::Malformed)?;
        if (400..500).contains(&status) || v.get("error").is_some() {
            return Err(TokenError::Refused);
        }
        if status != 200 {
            return Err(TokenError::Malformed);
        }
        let access_token = token(&v, "access_token").ok_or(TokenError::Malformed)?;
        let refresh_token = match (token(&v, "refresh_token"), upstream.refresh) {
            (_, Refresh::None) | (None, Refresh::Rotating) => None,
            (Some(r), _) => Some(Secret::new(r)),
            (None, Refresh::Reusable) => previous.cloned(),
        };
        let lifetime_s = match v.get("expires_in") {
            None | Some(Json::Null) => upstream.lifetime_s,
            Some(Json::Number(n)) => Some(
                n.as_u64()
                    .filter(|s| (1..=MAX_EXPIRES_IN_S).contains(s))
                    .ok_or(TokenError::Malformed)?,
            ),
            Some(Json::String(s)) => Some(
                s.parse::<u64>()
                    .ok()
                    .filter(|s| (1..=MAX_EXPIRES_IN_S).contains(s))
                    .ok_or(TokenError::Malformed)?,
            ),
            Some(_) => return Err(TokenError::Malformed),
        };
        let expires_at = lifetime_s
            .map(|s| s.checked_mul(1000).and_then(|ms| now_ms.checked_add(ms)))
            .map(|e| e.ok_or(TokenError::Malformed))
            .transpose()?;
        Ok(Self {
            access_token: Secret::new(access_token),
            refresh_token,
            token_type: v
                .get("token_type")
                .and_then(Json::as_str)
                .filter(|t| {
                    (1..=32).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_alphanumeric())
                })
                .unwrap_or("Bearer")
                .to_owned(),
            scope: v
                .get("scope")
                .and_then(Json::as_str)
                .filter(|s| s.len() <= 4096)
                .map(String::from),
            expires_at,
        })
    }

    /// The plaintext sealed under the person's key.
    #[must_use]
    pub fn to_sealed_text(&self) -> String {
        json!({
            "access_token": self.access_token.expose(),
            "refresh_token": self.refresh_token.as_ref().map(|r| r.expose().clone()),
            "token_type": self.token_type,
            "scope": self.scope,
            "expires_at": self.expires_at,
        })
        .to_string()
    }

    /// Reads the sealed plaintext.
    ///
    /// # Errors
    /// [`TokenError::Malformed`].
    pub fn from_sealed_text(text: &str) -> Result<Self, TokenError> {
        let v: Json = serde_json::from_str(text).map_err(|_| TokenError::Malformed)?;
        Ok(Self {
            access_token: Secret::new(token(&v, "access_token").ok_or(TokenError::Malformed)?),
            refresh_token: token(&v, "refresh_token").map(Secret::new),
            token_type: v
                .get("token_type")
                .and_then(Json::as_str)
                .ok_or(TokenError::Malformed)?
                .to_owned(),
            scope: v.get("scope").and_then(Json::as_str).map(String::from),
            expires_at: v.get("expires_at").and_then(Json::as_u64),
        })
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (n, v) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(n);
        out.push('=');
        form_encode(v, &mut out);
    }
    out
}

/// The authorization request (RFC 6749 §4.1.1): code flow, `state`, PKCE `S256` when the
/// upstream takes it, the catalog's extra parameters.
#[must_use]
pub fn authorization_url(
    u: &Upstream,
    (client_id, redirect_uri): (&str, &str),
    scopes: &[String],
    (state, challenge): (&str, &str),
) -> String {
    let mut out = u.authorization_endpoint.clone();
    let mut push = |n: &str, v: &str| {
        out.push(if out.contains('?') { '&' } else { '?' });
        out.push_str(n);
        out.push('=');
        form_encode(v, &mut out);
    };
    push("response_type", "code");
    push("client_id", client_id);
    push("redirect_uri", redirect_uri);
    if !scopes.is_empty() {
        push("scope", &scopes.join(&u.scope_separator));
    }
    push("state", state);
    if u.pkce {
        push("code_challenge", challenge);
        push("code_challenge_method", "S256");
    }
    for (k, v) in &u.authorize_params {
        push(k, v);
    }
    out
}

/// The code exchange (RFC 6749 §4.1.3), `client_secret_post`.
#[must_use]
pub fn code_form(
    u: &Upstream,
    (client_id, secret): (&str, &str),
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> String {
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", secret),
    ];
    if u.pkce {
        pairs.push(("code_verifier", verifier));
    }
    form(&pairs)
}

/// The refresh (RFC 6749 §6), `client_secret_post`.
#[must_use]
pub fn refresh_form((client_id, secret): (&str, &str), refresh_token: &str) -> String {
    form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("client_secret", secret),
    ])
}

/// The revocation (RFC 7009 §2.1) of the refresh token, or else the access token.
#[must_use]
pub fn revoke_form((client_id, secret): (&str, &str), set: &TokenSet) -> String {
    let (t, hint) = set.refresh_token.as_ref().map_or_else(
        || (set.access_token.expose().as_str(), "access_token"),
        |r| (r.expose().as_str(), "refresh_token"),
    );
    form(&[
        ("token", t),
        ("token_type_hint", hint),
        ("client_id", client_id),
        ("client_secret", secret),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::catalog::Catalog;

    fn github() -> Upstream {
        Catalog::shipped().unwrap().get("github").unwrap().clone()
    }

    fn google() -> Upstream {
        Catalog::shipped().unwrap().get("google").unwrap().clone()
    }

    // AG-40 (5), Ek B 4412
    #[test]
    fn the_lifetime_is_learnt_from_expires_in_then_the_catalog() {
        let now = 1_000_000;
        let a =
            br#"{"access_token":"at","expires_in":120,"refresh_token":"rt","token_type":"Bearer"}"#;
        let s = TokenSet::from_answer((200, a), &google(), None, now).unwrap();
        assert_eq!(s.expires_at, Some(now + 120_000));
        assert!(s.refresh_token.is_some());

        let b = br#"{"access_token":"at2"}"#;
        let s = TokenSet::from_answer((200, b), &google(), None, now).unwrap();
        assert_eq!(s.expires_at, Some(now + 3_600_000));
        let s = TokenSet::from_answer((200, b), &github(), None, now).unwrap();
        assert_eq!(s.expires_at, None);
        assert!(google().revocation_endpoint.is_some());
        assert!(github().revocation_endpoint.is_none());
    }

    #[test]
    fn a_refresh_keeps_a_reusable_refresh_token_only() {
        let previous = Secret::new(String::from("old"));
        let a = br#"{"access_token":"new","expires_in":"60"}"#;
        let s = TokenSet::from_answer((200, a), &google(), Some(&previous), 0).unwrap();
        assert_eq!(s.refresh_token.unwrap().expose(), "old");
        let ms = Catalog::shipped()
            .unwrap()
            .get("microsoft-graph")
            .unwrap()
            .clone();
        let s = TokenSet::from_answer((200, a), &ms, Some(&previous), 0).unwrap();
        assert!(s.refresh_token.is_none());
    }

    #[test]
    fn a_refused_or_malformed_answer_is_not_a_token_set() {
        let g = google();
        assert_eq!(
            TokenSet::from_answer((400, br#"{"error":"invalid_grant"}"#), &g, None, 0).unwrap_err(),
            TokenError::Refused
        );
        for bad in [
            &br#"{"token_type":"Bearer"}"#[..],
            br#"{"access_token":"a","expires_in":-1}"#,
            br#"{"access_token":"a b"}"#,
            b"not json",
        ] {
            assert_eq!(
                TokenSet::from_answer((200, bad), &g, None, 0).unwrap_err(),
                TokenError::Malformed
            );
        }
    }

    // AGI-3, AG-40 (7), Ek B 4415: a TokenSet never prints its tokens
    #[test]
    fn a_token_set_never_prints_its_tokens() {
        let a = br#"{"access_token":"top-secret-at","refresh_token":"top-secret-rt"}"#;
        let s = TokenSet::from_answer((200, a), &google(), None, 0).unwrap();
        let shown = format!("{s:?}");
        assert!(!shown.contains("top-secret"));
        let back = TokenSet::from_sealed_text(&s.to_sealed_text()).unwrap();
        assert_eq!(back.access_token.expose(), "top-secret-at");
    }

    #[test]
    fn the_authorization_request_carries_pkce_and_the_catalog_parameters() {
        let u = authorization_url(
            &google(),
            ("cid", "https://acme.example/cb"),
            &[String::from("a"), String::from("b")],
            ("st", "ch"),
        );
        assert!(u.starts_with("https://accounts.google.com/o/oauth2/v2/auth?response_type=code"));
        for part in [
            "scope=a+b",
            "state=st",
            "code_challenge=ch",
            "access_type=offline",
        ] {
            assert!(u.contains(part), "{u}");
        }
        let slack = Catalog::shipped().unwrap().get("slack").unwrap().clone();
        let u = authorization_url(
            &slack,
            ("c", "https://x/cb"),
            &[String::from("a"), String::from("b")],
            ("s", "c"),
        );
        assert!(
            u.contains("scope=a%2Cb") && !u.contains("code_challenge"),
            "{u}"
        );
    }
}
