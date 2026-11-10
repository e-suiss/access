//! What social sign-in needs from the outside world (OP-63): HTTPS to the provider and the
//! secret store that holds the realm's client secrets. Both fail closed: no answer, no sign-in
//! (MD-8).

use std::future::Future;
use std::pin::Pin;

use access_crypto::Secret;

/// The provider or the secret store did not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unreachable")]
pub struct Unreachable;

/// An answer: status and body.
pub type Answer = (u16, Vec<u8>);

/// HTTPS to a provider, every request guarded against SSRF (§14.3).
pub trait ProviderHttp: Send + Sync {
    /// `GET url` accepting JSON, with a bearer token when given.
    fn get_json(
        &self,
        url: &str,
        bearer: Option<&str>,
    ) -> impl Future<Output = Result<Answer, Unreachable>> + Send;

    /// `POST url` with a form body, accepting JSON.
    fn post_form(
        &self,
        url: &str,
        form: &str,
    ) -> impl Future<Output = Result<Answer, Unreachable>> + Send;

    /// `POST url` with a form body and an `Authorization` value (`client_secret_basic`); a
    /// provider client that cannot send it answers [`Unreachable`] (MD-8).
    fn post_form_authorized(
        &self,
        url: &str,
        form: &str,
        authorization: &str,
    ) -> impl Future<Output = Result<Answer, Unreachable>> + Send {
        let _ = (url, form, authorization);
        std::future::ready(Err(Unreachable))
    }
}

/// A boxed future of [`ClientAssertion`].
pub type Signed<'a> = Pin<Box<dyn Future<Output = Result<String, Unreachable>> + Send + 'a>>;

/// Signs the RFC 7523 client assertions of `private_key_jwt` with a key of the realm, the one
/// its JWKS publishes (OP-155 m.3 (h)).
pub trait ClientAssertion: Send + Sync {
    /// The compact JWS of `claims` under `alg` (`ES256` or `RS256`) at `at_ms`.
    fn sign(&self, realm: [u8; 16], alg: &'static str, claims: Vec<u8>, at_ms: u64) -> Signed<'_>;
}

/// No signer: every `private_key_jwt` connection is unreachable (MD-8).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAssertion;

impl ClientAssertion for NoAssertion {
    fn sign(&self, _: [u8; 16], _: &'static str, _: Vec<u8>, _: u64) -> Signed<'_> {
        Box::pin(async { Err(Unreachable) })
    }
}

/// A boxed future of [`UpstreamTrust`].
pub type Trusted<'a> = Pin<Box<dyn Future<Output = Result<bool, Unreachable>> + Send + 'a>>;

/// Whether the governing domain trusts an upstream issuer (TN-95, INV-17, OP-155 m.3 (h)): a
/// live actor-binding Acceptance of the issuer's Party id
/// ([`crate::domain::connection::issuer_id`]) for `identity_binding_person`. A connection
/// without one signs nobody in and yields no Claim; cutting it off stops it prospectively
/// (SEC9).
pub trait UpstreamTrust: Send + Sync {
    /// Whether `domain` accepts the upstream issuer `issuer`.
    fn accepted(&self, domain: [u8; 32], issuer: [u8; 16]) -> Trusted<'_>;
}

/// No authority plane: no upstream is accepted (MD-8).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoUpstreamTrust;

impl UpstreamTrust for NoUpstreamTrust {
    fn accepted(&self, _: [u8; 32], _: [u8; 16]) -> Trusted<'_> {
        Box::pin(async { Ok(false) })
    }
}

/// Resolves a `secret://…` reference; the secret never touches the database.
pub trait SocialSecrets: Send + Sync {
    /// The secret `reference` names.
    fn secret(
        &self,
        reference: &str,
    ) -> impl Future<Output = Result<Secret<String>, Unreachable>> + Send;
}
