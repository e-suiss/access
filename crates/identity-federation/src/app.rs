//! The relying party over its ports (OP-63): resolves which client a realm signs in with,
//! builds the authorization request and turns the provider's redirect into one checked
//! external identity. Sessions, accounts and links are the caller's (identity-ui).

use std::collections::BTreeMap;

use access_crypto::Secret;
use access_identity_oauth::domain::jwt::parse_jwks;
use serde_json::Value;

use crate::domain::apple::AppleKey;
use crate::domain::key::identity_key;
use crate::domain::preset::{ClientAuth, EmailAssurance, Preset, Presets, Protocol, ResponseMode};
use crate::domain::rules::{ClientRefusal, client_allowed};
use crate::domain::token::{
    Expect, MAX_ANSWER, ProviderEmail, Secrets, TokenError, check_id_token, email_of, token_answer,
    token_form,
};
use crate::ports::{ProviderHttp, SocialSecrets, Unreachable};

/// A shared development client the operator configured for one preset (`social.dev_clients`,
/// OP-153 m.3 (l)); accepted only in a sandbox realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevClient {
    /// The client id.
    pub client_id: String,
    /// The secret's reference.
    pub secret_ref: String,
}

/// A provider as a realm enabled it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enabled {
    /// The preset, or the upstream's discovered profile.
    pub preset: Preset,
    /// The client id the realm holds; `None` names the shared development client.
    pub client_id: Option<String>,
    /// Its secret's reference.
    pub secret_ref: Option<String>,
}

/// Why a social attempt ends without an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FederationError {
    /// The provider, its keys or the secret store did not answer (MD-8).
    #[error("unavailable")]
    Unavailable,
    /// The client may not be used in this realm (IDP-31 (4)).
    #[error("client refused: {0:?}")]
    Client(ClientRefusal),
    /// An answer of the provider was refused.
    #[error("refused: {0}")]
    Refused(TokenError),
}

impl From<Unreachable> for FederationError {
    fn from(_: Unreachable) -> Self {
        Self::Unavailable
    }
}

impl From<TokenError> for FederationError {
    fn from(e: TokenError) -> Self {
        Self::Refused(e)
    }
}

/// One checked external identity (P-ID-9).
#[derive(Clone, PartialEq, Eq)]
pub struct External {
    /// The provider name in routes.
    pub provider: String,
    /// `identity_key(provider issuer, subject)`.
    pub key: [u8; 32],
    /// The address the provider gave, with what it is worth.
    pub email: Option<ProviderEmail>,
    /// The display name the provider gave, attacker-controlled text.
    pub name: Option<String>,
}

impl core::fmt::Debug for External {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("External")
            .field("provider", &self.provider)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// The client a sign-in uses, resolved.
pub struct Client {
    /// The client id.
    pub id: String,
    /// The secret.
    pub secret: Secret<String>,
}

/// The relying party.
pub struct Federation<'a, H, S> {
    /// HTTPS to providers.
    pub http: &'a H,
    /// The secret store.
    pub secrets: &'a S,
    /// Shared development clients by preset id.
    pub dev: &'a BTreeMap<String, DevClient>,
}

fn name_of(claims: &Value) -> Option<String> {
    claims
        .get("name")
        .or_else(|| claims.get("login"))
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty() && n.chars().count() <= 128 && !n.chars().any(char::is_control))
        .map(String::from)
}

impl<H: ProviderHttp, S: SocialSecrets> Federation<'_, H, S> {
    /// The client of `e` in a realm that is (`sandbox`) or is not a sandbox: the realm's own,
    /// or the shared development client only in a sandbox (OP-153 m.3 (l)); checked at
    /// `enable` and again here, at every sign-in.
    ///
    /// # Errors
    /// [`FederationError`].
    pub async fn client(&self, e: &Enabled, sandbox: bool) -> Result<Client, FederationError> {
        let dev = self.dev.get(&e.preset.id);
        client_allowed(e.client_id.is_none(), sandbox, dev.is_some())
            .map_err(FederationError::Client)?;
        let (id, reference) = match (&e.client_id, &e.secret_ref, dev) {
            (Some(id), Some(r), _) => (id.clone(), r.clone()),
            (None, _, Some(d)) => (d.client_id.clone(), d.secret_ref.clone()),
            _ => return Err(FederationError::Unavailable),
        };
        let secret = self.secrets.secret(&reference).await?;
        Ok(Client { id, secret })
    }

    /// Exchanges the redirect's `code` and checks the answer in the back end (§10.2.6).
    ///
    /// # Errors
    /// [`FederationError`].
    pub async fn finish(
        &self,
        p: &Preset,
        client: &Client,
        redirect_uri: &str,
        code: &str,
        s: &Secrets,
        now_ms: u64,
    ) -> Result<External, FederationError> {
        let secret = match p.client_auth {
            ClientAuth::SecretPost => Secret::new(client.secret.expose().clone()),
            ClientAuth::AppleJwt => Secret::new(
                AppleKey::parse(&client.secret)
                    .and_then(|k| k.client_secret(&client.id, now_ms / 1000))
                    .map_err(|_| FederationError::Unavailable)?,
            ),
        };
        let form = token_form(&client.id, secret.expose(), redirect_uri, code, &s.verifier);
        let (status, body) = self.http.post_form(&p.token_endpoint, &form).await?;
        let answer = token_answer(status, &body)?;
        let (claims, emails) = match p.protocol {
            Protocol::Oidc => {
                let token = answer.id_token.as_deref().ok_or(TokenError::Answer)?;
                let jwks = p.jwks_uri.as_deref().ok_or(TokenError::Answer)?;
                let (st, doc) = self.http.get_json(jwks, None).await?;
                if st != 200 {
                    return Err(FederationError::Unavailable);
                }
                let keys = parse_jwks(&doc).map_err(|_| FederationError::Unavailable)?;
                let expect = Expect {
                    client_id: &client.id,
                    nonce: &s.nonce,
                    now_ms,
                };
                (check_id_token(token, p, &keys, &expect)?, None)
            }
            Protocol::Oauth2 => {
                let url = p.userinfo_endpoint.as_deref().ok_or(TokenError::Answer)?;
                let claims = self.json(url, &answer.access_token).await?;
                let emails = match (&p.email, &p.emails_endpoint) {
                    (EmailAssurance::VerifiedPrimary, Some(u)) => {
                        Some(self.json(u, &answer.access_token).await?)
                    }
                    _ => None,
                };
                (claims, emails)
            }
        };
        let subject = crate::domain::token::subject_of(p, &claims)?;
        Ok(External {
            provider: p.id.clone(),
            key: identity_key(&p.issuer, &subject),
            email: email_of(p, &claims, emails.as_ref()),
            name: name_of(&claims),
        })
    }

    async fn json(&self, url: &str, bearer: &str) -> Result<Value, FederationError> {
        let (status, body) = self.http.get_json(url, Some(bearer)).await?;
        if status != 200 || body.len() > MAX_ANSWER {
            return Err(FederationError::Refused(TokenError::Answer));
        }
        serde_json::from_slice(&body).map_err(|_| FederationError::Refused(TokenError::Answer))
    }

    /// The profile of an upstream OIDC provider the realm registered (`idp.upstream.register`,
    /// TN-95): its discovery document must name the registered issuer; its JWKS is the
    /// registered one. Its addresses carry no assurance.
    ///
    /// # Errors
    /// [`FederationError`].
    pub async fn upstream(
        &self,
        name: &str,
        issuer: &str,
        jwks_uri: &str,
    ) -> Result<Preset, FederationError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let (status, body) = self.http.get_json(&url, None).await?;
        if status != 200 || body.len() > MAX_ANSWER {
            return Err(FederationError::Unavailable);
        }
        let doc: Value = serde_json::from_slice(&body).map_err(|_| FederationError::Unavailable)?;
        let text = |n: &str| doc.get(n).and_then(Value::as_str).map(String::from);
        if text("issuer").as_deref() != Some(issuer) {
            return Err(FederationError::Refused(TokenError::Issuer));
        }
        let (Some(authorization_endpoint), Some(token_endpoint)) =
            (text("authorization_endpoint"), text("token_endpoint"))
        else {
            return Err(FederationError::Unavailable);
        };
        let p = Preset {
            id: name.into(),
            display_name: name.into(),
            protocol: Protocol::Oidc,
            issuer: issuer.into(),
            authorization_endpoint,
            token_endpoint,
            jwks_uri: Some(jwks_uri.into()),
            userinfo_endpoint: None,
            emails_endpoint: None,
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            logo: "oidc".into(),
            subject: vec!["sub".into()],
            algorithms: vec!["RS256".into(), "ES256".into()],
            response_mode: ResponseMode::Query,
            client_auth: ClientAuth::SecretPost,
            email: EmailAssurance::None,
        };
        if [&p.authorization_endpoint, &p.token_endpoint]
            .iter()
            .all(|u| crate::domain::https(u))
        {
            Ok(p)
        } else {
            Err(FederationError::Unavailable)
        }
    }
}

/// The shipped presets, or the error that stops the process at start-up.
///
/// # Errors
/// [`crate::domain::preset::PresetError`].
pub fn presets() -> Result<Presets, crate::domain::preset::PresetError> {
    Presets::shipped()
}
