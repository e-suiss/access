//! SVID client authentication (`draft-ietf-oauth-spiffe-client-auth-02` §3.1, §3.2, AG-30,
//! OP-154 m.3 (r)): a JWT-SVID client assertion, or an X.509-SVID over mutual TLS whose URI SAN
//! the request's `client_id` repeats (`tls_client_auth`, RFC 8705 §2.1). Over A2A mutual TLS the
//! same SAN is the actor-binding input (§11.15).

use access_identity_attest::app::{Credential, verify};
use access_identity_attest::domain::svid::{JWT_SPIFFE, jwt_subject, x509_subject};
use access_identity_attest::domain::workload::{Selector, WorkloadId, trust_domain_issuer};
use access_identity_attest::ports::Scope;
use access_store::workloads::WorkloadClient as Registration;

use crate::app::oauth::{ClientRequest, Env, OAuth, Realm, day};
use crate::domain::client::{
    Client, ClientAuth, ClientAuthError, SPIFFE_JWT, SPIFFE_X509, VerifiedWorkload, WorkloadClient,
};
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthDb, OAuthTx};

/// The one registration of `clients` whose selector names `id` with method `method`; none when
/// no registration or more than one does (fail closed).
fn registration<'a>(
    clients: &'a [Registration],
    method: &str,
    id: &WorkloadId,
) -> Option<&'a Registration> {
    let mut found = clients.iter().filter(|c| {
        c.auth_method == method
            && Selector::parse(&c.workload.spiffe_id).is_ok_and(|s| s.matches(id))
    });
    let first = found.next();
    if found.next().is_some() {
        return None;
    }
    first
}

impl<E: Env> OAuth<E> {
    /// AG-30, OP-154 m.3 (r): the workload client a JWT-SVID or the connection's X.509-SVID
    /// authenticates; `None` when the request uses neither.
    pub(crate) async fn workload_client(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        req: &ClientRequest<'_>,
        now: u64,
    ) -> Result<Option<Result<Client, ClientAuthError>>, Unavailable> {
        let p = req.params;
        if p.get("client_assertion_type") == Some(JWT_SPIFFE) {
            let Some(token) = p
                .get("client_assertion")
                .filter(|_| req.authorization.is_none())
            else {
                return Ok(Some(Err(ClientAuthError::Malformed)));
            };
            return Ok(Some(
                self.svid_client(tx, realm, req, Credential::Jwt(token), now)
                    .await?,
            ));
        }
        // RFC 8705 §2.1
        let x509 = p
            .get("client_id")
            .is_some_and(|c| c.starts_with("spiffe://"))
            && !req.chain.is_empty()
            && req.authorization.is_none()
            && p.get("client_assertion").is_none();
        if !x509 {
            return Ok(None);
        }
        Ok(Some(
            self.svid_client(tx, realm, req, Credential::X509(req.chain), now)
                .await?,
        ))
    }

    async fn svid_client(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        req: &ClientRequest<'_>,
        credential: Credential<'_>,
        now: u64,
    ) -> Result<Result<Client, ClientAuthError>, Unavailable> {
        let (method, id) = match credential {
            Credential::Jwt(t) => (SPIFFE_JWT, jwt_subject(t)),
            Credential::X509(chain) => (
                SPIFFE_X509,
                chain.first().map_or(
                    Err(access_identity_attest::domain::svid::SvidError::Format),
                    |l| x509_subject(l),
                ),
            ),
        };
        let Ok(id) = id else {
            return Ok(Err(ClientAuthError::Rejected));
        };
        let clients = tx.workload_clients().await?;
        let Some(reg) = registration(&clients, method, &id) else {
            return Ok(Err(ClientAuthError::Unknown));
        };
        let named = req.params.get("client_id");
        let client_id_ok = match credential {
            Credential::Jwt(_) => named.is_none_or(|c| c == reg.client_id || c == id.as_str()),
            Credential::X509(_) => named == Some(id.as_str()),
        };
        if !client_id_ok {
            return Ok(Err(ClientAuthError::Unknown));
        }
        let Some(domain) = tx.governing().await? else {
            return Ok(Err(ClientAuthError::Rejected));
        };
        // OP-154 m.3 (r)
        let issuer = trust_domain_issuer(id.scheme(), id.trust_domain());
        if !self.env.workload_trust().accepted(domain, issuer).await? {
            return Ok(Err(ClientAuthError::Rejected));
        }
        let scope = Scope {
            tenant: *realm.tenant.as_bytes(),
            realm: *realm.realm.as_bytes(),
        };
        let verified = verify(
            self.env.bundles(),
            scope,
            &reg.workload.bundle_endpoint,
            (credential, realm.issuer.as_str()),
            now,
        )
        .await
        .map_err(|_| Unavailable)?;
        let Ok(v) = verified else {
            return Ok(Err(ClientAuthError::Rejected));
        };
        if let (Some(key), Some(exp)) = (v.replay_key, v.exp_ms)
            && !tx.assertion_first_use(day(exp), &key).await?
        {
            return Ok(Err(ClientAuthError::Rejected));
        }
        let Some(mut client) = tx.client(&reg.client_id).await?.and_then(Client::from_row) else {
            return Ok(Err(ClientAuthError::Unknown));
        };
        let ClientAuth::Workload(w) = &client.auth else {
            return Ok(Err(ClientAuthError::Method));
        };
        client.auth = ClientAuth::Workload(WorkloadClient {
            x509: w.x509,
            verified: Some(VerifiedWorkload {
                uri: String::from(v.id.as_str()),
                agent: reg.workload.agent,
                evidence: match credential {
                    Credential::Jwt(t) => suiss_crypto::digest::sha256(t.as_bytes()),
                    Credential::X509(chain) => {
                        suiss_crypto::digest::sha256(chain.first().map_or(&[][..], Vec::as_slice))
                    }
                },
            }),
        });
        Ok(Ok(client))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_store::workloads::ClientWorkload;

    use super::*;

    fn reg(id: &str, method: &str, selector: &str) -> Registration {
        Registration {
            client_id: String::from(id),
            auth_method: String::from(method),
            workload: ClientWorkload {
                client_uuid: [1; 16],
                spiffe_id: String::from(selector),
                bundle_endpoint: String::from("https://b.example/bundle"),
                agent: [2; 16],
            },
        }
    }

    // §11.12.1, MD-4, AG-30, Ek B 4136, 4258
    #[test]
    fn one_registration_names_a_workload_and_a_wildcard_names_none() {
        let a1 = WorkloadId::parse("spiffe://acme.example/agent/finance/a1").unwrap();
        let below = reg("cli_a", SPIFFE_JWT, "spiffe://acme.example/agent/finance/*");
        let mid = reg("cli_b", SPIFFE_JWT, "spiffe://acme.example/agent/*/a1");
        let x509 = reg(
            "cli_c",
            "spiffe_x509",
            "spiffe://acme.example/agent/finance/a1",
        );
        let list = vec![below.clone(), mid, x509];
        assert_eq!(
            registration(&list, SPIFFE_JWT, &a1).map(|r| r.client_id.as_str()),
            Some("cli_a")
        );
        let exact = reg(
            "cli_d",
            SPIFFE_JWT,
            "spiffe://acme.example/agent/finance/a1",
        );
        let ambiguous = vec![below, exact];
        assert!(registration(&ambiguous, SPIFFE_JWT, &a1).is_none());
        let only_mid = vec![reg("cli_b", SPIFFE_JWT, "spiffe://acme.example/agent/*/a1")];
        assert!(registration(&only_mid, SPIFFE_JWT, &a1).is_none());
    }
}
