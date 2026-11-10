//! A PEP's transport identity by OAuth (OP-155 m.3 (q), §9.5 `pep`, §9.5.1 #10, Ek B 5074): a
//! confidential client's `client_credentials` token for the deployment's ADP, bound to its DPoP
//! key (RFC 9449, TN-27). The token says which client calls; it carries no authority, and the
//! PEP it names is the key's RFC 7638 thumbprint, as a certificate's `x5t#S256` names a PEP
//! over mTLS. The PEP is never an actor (E17, PI-7).

use access_crypto::dpop::Role;
use access_kernel::json::b64url_encode;
use serde_json::json;

use super::{Env, OAuth, Realm, Reply};
use crate::app::dpop::DpopRequest;
use crate::domain::client::Client;
use crate::domain::dpop::{ClientType, Failure, Jkt};
use crate::domain::fapi::Binding;
use crate::domain::tokens::{ACCESS_TYP, SERVICE_TTL_MS, ServiceFacts, service_token_claims};
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthTx, TokenSigner as _};

/// What a PEP's presented token and proof come to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PepIdentity {
    /// The PEP: the DPoP key's thumbprint; and the nonce for its next proof.
    Pep {
        /// The base64url RFC 7638 thumbprint of the DPoP key.
        jkt: String,
        /// The next server nonce.
        nonce: Option<String>,
    },
    /// Not an authenticated PEP: the RFC 6750 / RFC 9449 error and the nonce to retry with.
    Refused {
        /// `invalid_token`, `invalid_dpop_proof` or `use_dpop_nonce`.
        error: &'static str,
        /// The server nonce, when the proof lacked a current one.
        nonce: Option<String>,
    },
}

fn refused(error: &'static str) -> PepIdentity {
    PepIdentity::Refused { error, nonce: None }
}

impl<E: Env> OAuth<E> {
    /// Whether a `client_credentials` request names the deployment's ADP as its resource with
    /// no `authorization_details`: a PEP token request.
    pub(crate) fn asks_pep_token(&self, params: &crate::domain::request::Params) -> bool {
        params
            .get(crate::domain::authority::DETAILS_PARAM)
            .is_none()
            && self
                .pep_audience()
                .is_some_and(|a| params.get("resource") == Some(a))
    }

    /// Issues a PEP token (RFC 6749 §4.4.3, RFC 9068): `iss` the client's realm, `aud` the ADP,
    /// `sub` and `client_id` the client, `access_tenant` its tenant, `cnf.jkt` its proof key;
    /// no scope, no details, no refresh token. Only a confidential client gets one.
    pub(crate) async fn pep_token(
        &self,
        realm: &Realm,
        client: &Client,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let Some(audience) = self.pep_audience() else {
            return Ok(Reply::oauth_error(400, "invalid_target", "no ADP resource"));
        };
        if client.client_type() != ClientType::Confidential {
            return Ok(Reply::oauth_error(
                400,
                "unauthorized_client",
                "a PEP token needs a confidential client",
            ));
        }
        let tenant = self.tenant_name(realm)?;
        let mut tx = self.begin(realm).await?;
        let alg = tx.jose_alg().await?;
        tx.commit().await?;
        let facts = ServiceFacts {
            issuer: &realm.issuer,
            audience,
            client_id: &client.id,
            sub: &client.id,
            tenant: &tenant,
            now_ms: now,
        };
        let jti = b64url_encode(&self.random::<16>()?);
        let token = self
            .env()
            .signer()
            .sign(
                realm.realm,
                alg,
                ACCESS_TYP,
                &service_token_claims(&facts, &jti, &jkt.text()),
                now,
            )
            .await?;
        Ok(Reply::json(
            200,
            &json!({
                "access_token": token,
                "token_type": "DPoP",
                "expires_in": SERVICE_TTL_MS / 1000,
            }),
        ))
    }

    /// The PEP an ADP request authenticates as by `authorization` (`DPoP <token>`) and its one
    /// DPoP proof for `method` on `uri` (OP-155 m.3 (q)): a live PEP token of `realm` for this
    /// deployment's ADP, its proof by the bound key with a current server nonce, used once, and
    /// a client that is still a confidential client of the realm's tenant. A bearer token, a
    /// certificate-bound or grant token, or any token for another audience is refused.
    ///
    /// # Errors
    /// [`Unavailable`] when the realm's keys, nonces, replay store or directory do not answer.
    pub async fn pep_identity(
        &self,
        realm: &Realm,
        method: &str,
        uri: &str,
        authorization: &str,
        dpop: &[&str],
    ) -> Result<PepIdentity, Unavailable> {
        let Some(audience) = self.pep_audience() else {
            return Ok(refused("invalid_token"));
        };
        let Some(("DPoP" | "dpop", token)) =
            authorization.split_once(' ').map(|(s, t)| (s, t.trim()))
        else {
            return Ok(refused("invalid_token"));
        };
        let now = self.now()?;
        let Some(at) = self
            .access_token(realm, token, now, true)
            .await?
            .filter(|at| at.aud == audience && at.sid.is_none())
        else {
            return Ok(refused("invalid_token"));
        };
        let Binding::Dpop(jkt) = at.binding else {
            return Ok(refused("invalid_token"));
        };
        let proof = self
            .dpop(
                realm,
                Role::ResourceServer,
                &DpopRequest {
                    proofs: dpop,
                    method,
                    uri,
                    access_token: Some(token),
                    bound: Some(jkt),
                },
            )
            .await;
        let next = match proof {
            Ok(p) => p.nonce,
            Err(Failure::Unavailable) => return Err(Unavailable),
            Err(f) => {
                return Ok(PepIdentity::Refused {
                    error: if f.nonce().is_some() {
                        "use_dpop_nonce"
                    } else {
                        "invalid_dpop_proof"
                    },
                    nonce: f.nonce().map(String::from),
                });
            }
        };
        if at.access_tenant.as_deref() != Some(self.tenant_name(realm)?.as_str()) {
            return Ok(refused("invalid_token"));
        }
        let mut tx = self.begin(realm).await?;
        let client = tx.client(&at.client_id).await?.and_then(Client::from_row);
        tx.commit().await?;
        if !client.is_some_and(|c| c.client_type() == ClientType::Confidential) {
            return Ok(refused("invalid_token"));
        }
        Ok(PepIdentity::Pep {
            jkt: jkt.text(),
            nonce: Some(next),
        })
    }
}
