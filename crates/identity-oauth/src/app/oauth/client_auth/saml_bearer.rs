//! The SAML 2.0 bearer grant (RFC 7522) and SAML 2.0 subject tokens in token exchange (RFC 8693
//! §3; OP-154 m.3 (m), OP-155 m.3 (k)). Each is one client's opt-in naming an accepted SAML
//! upstream; the assertion is parsed in the parser worker and its signature verified against
//! the upstream's pinned keys (P1, P2), and it is used once. Like a JWT bearer assertion it is
//! Claim input, never a grant: authority comes only from the client's own `projection.issue`
//! (MD-18, L25, INV-17).

use serde_json::Value;
use suiss_crypto::digest::context_digest;

use crate::app::oauth::authority::{Asked, projected_body};
use crate::app::oauth::{Env, OAuth, Realm, Reply};
use crate::domain::authority::{DETAILS_PARAM, EXERCISE_PARAM};
use crate::domain::client::Client;
use crate::domain::dpop::Jkt;
use crate::domain::exchange::ACCESS_TOKEN;
use crate::domain::metadata::Endpoint;
use crate::domain::request::Params;
use crate::ports::Unavailable;
use crate::ports::dpop::ReplayCache as _;
use crate::ports::profile::SamlSubject;

const ID_CONTEXT: &str = "access/saml-assertion-id/v1";
const DAY_MS: u64 = 86_400_000;

fn invalid_grant(why: &str) -> Reply {
    Reply::oauth_error(400, "invalid_grant", why)
}

/// Why a SAML assertion was not taken.
pub(crate) enum SamlRefusal {
    /// The client did not opt in.
    NotAllowed,
    /// It did not verify, or was used before.
    Invalid,
}

impl<E: Env> OAuth<E> {
    /// The subject of a SAML 2.0 assertion `assertion` (base64url) for `client`: from the
    /// accepted upstream its profile names, verified in the parser worker, addressed to the
    /// token endpoint, used once.
    pub(crate) async fn saml_subject(
        &self,
        realm: &Realm,
        client: &Client,
        assertion: &str,
        now: u64,
    ) -> Result<Result<SamlSubject, SamlRefusal>, Unavailable> {
        let Some(upstream) = client.profile.saml_bearer.as_deref() else {
            return Ok(Err(SamlRefusal::NotAllowed));
        };
        let audience = realm.issuer.endpoint(Endpoint::Token.path());
        let subject = match self
            .env
            .saml_assertions()
            .verify(realm.realm, upstream, assertion, &audience, now)
            .await?
        {
            Ok(s) if s.not_on_or_after_ms > now => s,
            Ok(_) => return Ok(Err(SamlRefusal::Invalid)),
            Err(r) => {
                tracing::info!(reason = %r, "SAML assertion refused");
                return Ok(Err(SamlRefusal::Invalid));
            }
        };
        let mut input = subject.issuer.as_bytes().to_vec();
        input.push(0);
        input.extend_from_slice(subject.id.as_bytes());
        let key = context_digest(ID_CONTEXT, &input).0;
        let day = u32::try_from(subject.not_on_or_after_ms / DAY_MS).map_err(|_| Unavailable)?;
        match self
            .env
            .replay(realm.tenant, realm.realm)
            .first_use(day, key)
            .await
        {
            Ok(true) => Ok(Ok(subject)),
            Ok(false) => Ok(Err(SamlRefusal::Invalid)),
            Err(_) => Err(Unavailable),
        }
    }

    /// `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer` (RFC 7522 §2.1): the
    /// assertion is Claim input; the token is the client's own `projection.issue` decision
    /// (MD-18, EI-6), bound to `jkt`.
    pub(crate) async fn saml_bearer(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let Some(assertion) = params.get("assertion") else {
            return Ok(Reply::oauth_error(
                400,
                "invalid_request",
                "assertion is required",
            ));
        };
        match self.saml_subject(realm, client, assertion, now).await? {
            Ok(_) => {}
            Err(SamlRefusal::NotAllowed) => {
                return Ok(Reply::oauth_error(
                    400,
                    "unauthorized_client",
                    "this client may not use the SAML 2.0 bearer grant",
                ));
            }
            Err(SamlRefusal::Invalid) => return Ok(invalid_grant("the assertion is not valid")),
        }
        // EI-6, MD-18
        if params.get(EXERCISE_PARAM).is_none() || params.get(DETAILS_PARAM).is_none() {
            return Ok(invalid_grant("an assertion is not a grant"));
        }
        let asked = Asked {
            params,
            authorized: None,
            family: None,
        };
        Ok(match self.project(realm, client, &asked, jkt).await? {
            Ok(p) => {
                let mut body = projected_body(&p, now);
                if let Value::Object(m) = &mut body {
                    m.insert("issued_token_type".into(), ACCESS_TOKEN.into());
                }
                Reply::json(200, &body)
            }
            Err(r) => r,
        })
    }
}
