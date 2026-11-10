//! `client_secret_jwt` (OIDC Core §9, RFC 7523 §2.2; CR-3, OP-148 m.16 (l), OP-155 m.3 (k)):
//! the HS256 assertion of a legacy client that opted in, verified with its secret, which the
//! realm KEK opens for this one check. The assertion's `jti` is used once. `client_secret_post`
//! is the registered secret in the form body and is checked with the client's other secret
//! methods ([`crate::domain::client::check_method`]).

use crate::app::oauth::{ClientRequest, Env, OAuth, Realm, day};
use crate::domain::client::{Client, ClientAuthError};
use crate::domain::jwt::{AssertionRules, verify_secret_assertion};
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthDb, OAuthTx};
use access_store::client_profiles::SealedJwtSecret;

impl<E: Env> OAuth<E> {
    /// The legacy client `client` once its `client_secret_jwt` `assertion` verifies with the
    /// secret `sealed` holds.
    #[expect(
        clippy::too_many_arguments,
        reason = "the facts of one client authentication"
    )]
    pub(crate) async fn secret_jwt_client(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        client: Client,
        sealed: &SealedJwtSecret,
        assertion: &str,
        req: &ClientRequest<'_>,
        now: u64,
    ) -> Result<Result<Client, ClientAuthError>, Unavailable> {
        let Some(secret) = self
            .env
            .jwt_secrets()
            .open(realm.realm, client.uuid, sealed)
            .await?
        else {
            tracing::warn!("client_secret_jwt secret does not open");
            return Ok(Err(ClientAuthError::Rejected));
        };
        let endpoint = realm.issuer.endpoint(req.endpoint);
        let rules = AssertionRules {
            client_id: &client.id,
            issuer: realm.issuer.as_str(),
            endpoint: &endpoint,
            now_ms: now,
            rs256: false,
        };
        let Ok(a) = verify_secret_assertion(assertion, &secret, &rules) else {
            return Ok(Err(ClientAuthError::Rejected));
        };
        if !tx.assertion_first_use(day(a.exp_ms), &a.replay_key).await? {
            return Ok(Err(ClientAuthError::Rejected));
        }
        Ok(Ok(client))
    }
}
