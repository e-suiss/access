//! What social sign-in needs from the outside world (OP-63): HTTPS to the provider and the
//! secret store that holds the realm's client secrets. Both fail closed: no answer, no sign-in
//! (MD-8).

use std::future::Future;

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
}

/// Resolves a `secret://…` reference; the secret never touches the database.
pub trait SocialSecrets: Send + Sync {
    /// The secret `reference` names.
    fn secret(
        &self,
        reference: &str,
    ) -> impl Future<Output = Result<Secret<String>, Unreachable>> + Send;
}
