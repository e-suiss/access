//! Upstream SAML in access-server (OP-155 m.3 (c), (h), (k)): Responses of SAML upstream
//! connections and SAML 2.0 bearer assertions are read and their signatures verified in the
//! parser worker, never here; what comes back is checked against the connection and its
//! governing domain's Acceptance.

use std::sync::Arc;

use access_edge_core::ipc::{Op, Reply};
use access_edge_core::parser::ParserClient;
use access_edge_core::saml::{AssertionFacts, Context};
use access_identity_federation::app::connection::{Connection, verify_saml};
use access_identity_federation::domain::connection::{ConnectionProtocol, Profile, issuer_id};
use access_identity_federation::domain::key::identity_key;
use access_identity_federation::domain::saml::{Expect, bearer_end};
use access_identity_federation::ports::{AssertionError, AssertionReader, Read, UpstreamTrust};
use access_identity_oauth::ports::Unavailable;
use access_identity_oauth::ports::oauth::Held;
use access_identity_oauth::ports::profile::{SamlAssertions, SamlRefused, SamlSubject};
use access_store::Pool;
use access_store::identity::{RealmId, TenantTx};

/// The parser worker supervisor as the [`AssertionReader`]; no supervisor configured refuses
/// every read as unavailable (MD-8).
pub(crate) struct ParserReader(pub(crate) Option<ParserClient>);

impl AssertionReader for ParserReader {
    fn read(&self, certs: Vec<Vec<u8>>, message: Vec<u8>) -> Read<'_> {
        Box::pin(async move {
            let Some(client) = &self.0 else {
                return Err(AssertionError::Unavailable);
            };
            let input = Context {
                inflate: false,
                certs,
                require_signature: true,
            }
            .encode(&message)
            .map_err(|_| AssertionError::Refused(String::from("frame-malformed")))?;
            match client.parse(Op::SamlAssertion, input).await {
                Ok(Reply::Ok { output, .. }) => AssertionFacts::decode(&output)
                    .map_err(|_| AssertionError::Refused(String::from("saml-field"))),
                Ok(Reply::Refused(code)) => Err(AssertionError::Refused(code)),
                Ok(Reply::WorkerFailed) => {
                    Err(AssertionError::Refused(String::from("worker-failed")))
                }
                Err(_) => Err(AssertionError::Unavailable),
            }
        })
    }
}

/// SAML 2.0 bearer assertions (RFC 7522) of a realm's accepted SAML upstream connection (OP-155
/// m.3 (k)): verified in the parser worker, addressed to the token endpoint, from an IdP whose
/// issuer the governing domain accepts; the account is the one the identity is linked to.
pub(crate) struct UpstreamSamlAssertions {
    pub(crate) app: Pool,
    pub(crate) router: Pool,
    pub(crate) reader: Arc<dyn AssertionReader>,
    pub(crate) trust: Arc<dyn UpstreamTrust>,
}

impl UpstreamSamlAssertions {
    async fn connection(
        &self,
        realm: RealmId,
        upstream: &str,
    ) -> Result<Option<(Connection, [u8; 32], TenantTx)>, Unavailable> {
        let tenant = access_store::tenancy::realm_tenant(&self.router, realm)
            .await
            .map_err(|_| Unavailable)?
            .ok_or(Unavailable)?;
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(|_| Unavailable)?;
        let row = access_store::idp::realm::upstream(&mut t, upstream)
            .await
            .map_err(|_| Unavailable)?;
        let domain = access_store::idp::governance(&mut t)
            .await
            .map_err(|_| Unavailable)?
            .map(|g| *g.domain.as_bytes());
        let (Some(row), Some(domain)) = (row.filter(|r| r.active), domain) else {
            return Ok(None);
        };
        let Ok(profile) = Profile::stored(row.profile.as_deref(), row.client_secret_ref.is_some())
        else {
            return Ok(None);
        };
        if profile.protocol != ConnectionProtocol::Saml {
            return Ok(None);
        }
        Ok(Some((
            Connection {
                name: row.name,
                issuer: row.issuer,
                client_id: row.client_id,
                secret_ref: row.client_secret_ref,
                jwks_uri: row.jwks_uri,
                profile,
            },
            domain,
            t,
        )))
    }
}

impl SamlAssertions for UpstreamSamlAssertions {
    fn verify<'a>(
        &'a self,
        realm: RealmId,
        upstream: &'a str,
        assertion: &'a str,
        audience: &'a str,
        now_ms: u64,
    ) -> Held<'a, Result<SamlSubject, SamlRefused>> {
        Box::pin(async move {
            let Some((c, domain, mut t)) = self.connection(realm, upstream).await? else {
                return Ok(Err(SamlRefused::Issuer));
            };
            let Some(idp) = c.profile.saml.clone() else {
                return Ok(Err(SamlRefused::Issuer));
            };
            // TN-95, INV-17
            if !self
                .trust
                .accepted(domain, issuer_id(&idp.entity_id))
                .await
                .map_err(|_| Unavailable)?
            {
                return Ok(Err(SamlRefused::Issuer));
            }
            let Ok(message) = access_kernel::json::b64url_decode(assertion) else {
                return Ok(Err(SamlRefused::Malformed));
            };
            let expect = Expect {
                idp: &idp.entity_id,
                audience,
                recipient: None,
                in_response_to: None,
                allow_unsolicited: true,
                now_ms,
            };
            let facts = match verify_saml(&*self.reader, &c, &message, &expect).await {
                Ok((f, _)) => f,
                Err(access_identity_federation::app::connection::SamlFailure::Unavailable) => {
                    return Err(Unavailable);
                }
                Err(_) => return Ok(Err(SamlRefused::Conditions)),
            };
            if facts.recipient.as_deref().is_some_and(|r| r != audience) {
                return Ok(Err(SamlRefused::Conditions));
            }
            let Some(end) = bearer_end(&facts) else {
                return Ok(Err(SamlRefused::Conditions));
            };
            let linked = t
                .federated_by_key(&identity_key(&facts.issuer, &facts.name_id))
                .await
                .map_err(|_| Unavailable)?
                .map(|r| r.subject);
            t.commit().await.map_err(|_| Unavailable)?;
            Ok(Ok(SamlSubject {
                issuer: facts.issuer,
                name_id: facts.name_id,
                id: facts.id,
                not_on_or_after_ms: end,
                subject: linked,
            }))
        })
    }
}
