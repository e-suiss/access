//! The relying party of an enterprise upstream connection over its ports (OP-155 m.3 (h)): the
//! discovery that fixes its algorithms and client authentication, the authorization request,
//! and the redirect back turned into one checked upstream sign-in. Sessions, accounts, links and
//! Claims are the caller's.

use access_crypto::Secret;
use access_identity_oauth::domain::jwt::parse_jwks;

use super::{External, Federation, FederationError};
use crate::domain::connection::{
    ClientAuthMethod, ConnectionError, Declared, Discovered, Profile, UpstreamPreset,
    assertion_claims, assertion_form, basic_form, declared, discovered, evidence,
};
use crate::domain::key::identity_key;
use crate::domain::preset::Preset;
use crate::domain::token::{
    Expect, MAX_ANSWER, Secrets, TokenError, authorization_url, check_id_token, email_of,
    subject_of, token_answer, token_form,
};
use crate::ports::{ClientAssertion, ProviderHttp, SocialSecrets};

/// A connection as registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    /// Its name in routes.
    pub name: String,
    /// The registered issuer.
    pub issuer: String,
    /// Access's client id at the upstream.
    pub client_id: String,
    /// The client secret's reference, for a secret method.
    pub secret_ref: Option<String>,
    /// The registered `JWKS`.
    pub jwks_uri: String,
    /// Its profile.
    pub profile: Profile,
}

/// A connection with what its discovery document fixed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The connection.
    pub connection: Connection,
    /// Its discovery, cut down to its rules.
    pub discovered: Discovered,
    /// The relying party's view.
    pub preset: Preset,
}

/// One checked upstream sign-in.
pub struct UpstreamSignIn {
    /// The external identity, keyed by `(iss, sub)` or `(iss, tid:oid)`.
    pub external: External,
    /// The verified issuer (RFC 9207).
    pub issuer: String,
    /// What the upstream declared about the authentication.
    pub declared: Declared,
    /// The digest of the raw ID token.
    pub evidence: [u8; 32],
    /// The raw ID token, to be sealed; never logged, never in a Claim.
    pub raw: Secret<Vec<u8>>,
    /// The national identity number the preset names, to be sealed (IDP-34).
    pub national: Option<Secret<String>>,
}

impl core::fmt::Debug for UpstreamSignIn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UpstreamSignIn")
            .field("external", &self.external)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl From<ConnectionError> for FederationError {
    fn from(e: ConnectionError) -> Self {
        Self::Connection(e)
    }
}

impl<H: ProviderHttp, S: SocialSecrets> Federation<'_, H, S> {
    /// Reads the connection's discovery document (TN-95): its `issuer` must be the registered
    /// one; algorithms and client authentication are fixed by it and the profile.
    ///
    /// # Errors
    /// [`FederationError::Unavailable`] when the upstream does not answer;
    /// [`FederationError::Connection`] when the document does not fit.
    pub async fn resolve(&self, connection: Connection) -> Result<Resolved, FederationError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            connection.issuer.trim_end_matches('/')
        );
        let (status, body) = self.http.get_json(&url, None).await?;
        if status != 200 {
            return Err(FederationError::Unavailable);
        }
        let d = discovered(&body, &connection.issuer, connection.profile.client_auth)?;
        let preset = d.preset(&connection.name, &connection.profile, &connection.jwks_uri);
        Ok(Resolved {
            connection,
            discovered: d,
            preset,
        })
    }

    /// Exchanges the redirect's `code` with the connection's client authentication and checks
    /// the ID token in the back end (§10.2.6, OP-155 m.3 (h)).
    ///
    /// # Errors
    /// [`FederationError`].
    #[expect(
        clippy::too_many_arguments,
        reason = "the callback's inputs, each checked"
    )]
    pub async fn finish_connection(
        &self,
        r: &Resolved,
        assertions: &dyn ClientAssertion,
        realm: [u8; 16],
        redirect_uri: &str,
        code: &str,
        s: &Secrets,
        now_ms: u64,
    ) -> Result<UpstreamSignIn, FederationError> {
        let c = &r.connection;
        let endpoint = &r.discovered.token_endpoint;
        let (status, body) = match c.profile.client_auth {
            ClientAuthMethod::PrivateKeyJwt => {
                let alg = r
                    .discovered
                    .assertion_alg
                    .ok_or(FederationError::Unavailable)?;
                let jti = access_crypto::random::bytes::<32>()
                    .map_err(|_| FederationError::Unavailable)?;
                let claims = assertion_claims(
                    &c.client_id,
                    &c.issuer,
                    &access_kernel::json::b64url_encode(&jti),
                    now_ms / 1000,
                );
                let assertion = assertions.sign(realm, alg, claims, now_ms).await?;
                let form =
                    assertion_form(&c.client_id, &assertion, redirect_uri, code, &s.verifier);
                self.http.post_form(endpoint, &form).await?
            }
            ClientAuthMethod::ClientSecretPost => {
                let secret = self.secret_of(c).await?;
                let form = token_form(
                    &c.client_id,
                    secret.expose(),
                    redirect_uri,
                    code,
                    &s.verifier,
                );
                self.http.post_form(endpoint, &form).await?
            }
            ClientAuthMethod::ClientSecretBasic => {
                let secret = self.secret_of(c).await?;
                let (form, header) = basic_form(
                    &c.client_id,
                    secret.expose(),
                    redirect_uri,
                    code,
                    &s.verifier,
                );
                self.http
                    .post_form_authorized(endpoint, &form, &header)
                    .await?
            }
        };
        let answer = token_answer(status, &body)?;
        let token = answer.id_token.ok_or(TokenError::Answer)?;
        let (st, doc) = self.http.get_json(&c.jwks_uri, None).await?;
        if st != 200 || doc.len() > MAX_ANSWER {
            return Err(FederationError::Unavailable);
        }
        let keys = parse_jwks(&doc).map_err(|_| FederationError::Unavailable)?;
        let expect = Expect {
            client_id: &c.client_id,
            nonce: &s.nonce,
            now_ms,
        };
        let claims = check_id_token(&token, &r.preset, &keys, &expect)?;
        let subject = subject_of(&r.preset, &claims)?;
        let national = c
            .profile
            .preset
            .as_deref()
            .and_then(UpstreamPreset::get)
            .and_then(|p| p.national_id.as_deref())
            .map(|n| {
                claims
                    .get(n)
                    .and_then(serde_json::Value::as_str)
                    .filter(|v| {
                        (1..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit())
                    })
                    .map(|v| Secret::new(String::from(v)))
                    .ok_or(FederationError::Refused(TokenError::Subject))
            })
            .transpose()?;
        let name = claims
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|n| {
                !n.is_empty() && n.chars().count() <= 128 && !n.chars().any(char::is_control)
            })
            .map(String::from);
        Ok(UpstreamSignIn {
            external: External {
                provider: c.name.clone(),
                key: identity_key(&c.issuer, &subject),
                email: email_of(&r.preset, &claims, None),
                name,
                asserted: None,
            },
            issuer: c.issuer.clone(),
            declared: declared(&claims),
            evidence: evidence(token.as_bytes()),
            raw: Secret::new(token.into_bytes()),
            national,
        })
    }

    async fn secret_of(&self, c: &Connection) -> Result<Secret<String>, FederationError> {
        let reference = c
            .secret_ref
            .as_deref()
            .ok_or(FederationError::Unavailable)?;
        Ok(self.secrets.secret(reference).await?)
    }
}

impl Resolved {
    /// The authorization request URL, with the asked `ui_locales` the upstream supports
    /// (TN-108).
    #[must_use]
    pub fn authorization_url(
        &self,
        redirect_uri: &str,
        s: &Secrets,
        ui_locales: Option<&str>,
    ) -> String {
        let mut url = authorization_url(&self.preset, &self.connection.client_id, redirect_uri, s);
        if let Some(l) = self.discovered.ui_locales(ui_locales) {
            url.push_str("&ui_locales=");
            access_identity_oauth::domain::issuer::form_encode(&l, &mut url);
        }
        url
    }
}

/// Why a SAML upstream's assertion signs nobody in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SamlFailure {
    /// The parser worker could not be reached, or the connection names no identity provider (MD-8).
    #[error("unavailable")]
    Unavailable,
    /// The worker refused it, or it does not match the connection (§10.6.1).
    #[error("refused")]
    Refused,
}

/// The attributes an address may come in.
const MAIL: [&str; 3] = ["mail", "email", "urn:oid:0.9.2342.19200300.100.1.3"];

/// Reads `message` (a decoded `SAMLResponse` or assertion) of SAML connection `c` in the parser
/// worker against the identity provider's pinned certificates and checks it against `e` (OP-155 m.3 (h)).
///
/// # Errors
/// [`SamlFailure`].
pub async fn verify_saml(
    reader: &dyn crate::ports::AssertionReader,
    c: &Connection,
    message: &[u8],
    e: &crate::domain::saml::Expect<'_>,
) -> Result<(access_internal_api::saml::AssertionFacts, Declared), SamlFailure> {
    let Some(idp) = c.profile.saml.as_ref() else {
        return Err(SamlFailure::Unavailable);
    };
    let certs = idp
        .certificates
        .iter()
        .map(|b| access_identity_saml::sp::b64::decode(b).ok_or(SamlFailure::Unavailable))
        .collect::<Result<Vec<_>, _>>()?;
    let facts = match reader.read(certs, message.to_vec()).await {
        Ok(f) => f,
        Err(crate::ports::AssertionError::Unavailable) => return Err(SamlFailure::Unavailable),
        Err(crate::ports::AssertionError::Refused(_)) => return Err(SamlFailure::Refused),
    };
    let declared = crate::domain::saml::check(&facts, e).map_err(|_| SamlFailure::Refused)?;
    Ok((facts, declared))
}

/// The upstream sign-in of a verified SAML assertion of connection `c`: keyed by
/// (identity provider entity ID, `NameID`) (§10.1.2 SAML row); its address carries no assurance.
///
/// # Errors
/// [`SamlFailure::Refused`] when a preset's national identity number is missing.
pub fn saml_sign_in(
    c: &Connection,
    facts: &access_internal_api::saml::AssertionFacts,
    declared: Declared,
    raw: &[u8],
) -> Result<UpstreamSignIn, SamlFailure> {
    let attr = |n: &str| crate::domain::saml::attribute(facts, n);
    let national = c
        .profile
        .preset
        .as_deref()
        .and_then(UpstreamPreset::get)
        .and_then(|p| p.national_id.as_deref())
        .map(|n| {
            attr(n)
                .filter(|v| (1..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit()))
                .map(|v| Secret::new(String::from(v)))
                .ok_or(SamlFailure::Refused)
        })
        .transpose()?;
    let email = MAIL
        .iter()
        .find_map(|n| attr(n))
        .filter(|a| a.len() <= 320 && a.contains('@'))
        .map(|a| crate::domain::token::ProviderEmail {
            address: String::from(a),
            vouched: false,
        });
    Ok(UpstreamSignIn {
        external: External {
            provider: c.name.clone(),
            key: identity_key(&facts.issuer, &facts.name_id),
            email,
            name: attr("displayName")
                .filter(|n| n.chars().count() <= 128 && !n.chars().any(char::is_control))
                .map(String::from),
            asserted: None,
        },
        issuer: facts.issuer.clone(),
        declared,
        evidence: evidence(raw),
        raw: Secret::new(raw.to_vec()),
        national,
    })
}
