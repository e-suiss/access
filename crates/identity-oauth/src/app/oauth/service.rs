//! The identity-assertion service token for a platform product (OP-149 m.31 (a), m.34 (b), §9
//! "two token classes" (ii), E39, MD-7): `client_credentials` with `resource=<the product's
//! client_id>` (RFC 8707) and no `authorization_details`, by another platform product or by a
//! confidential client of a tenant realm. It says who is calling and from which tenant, bound by
//! `cnf.jkt` (TN-27); it carries no authority (no details, no contract, no family, no status) and
//! the product it is for reads it as "who is calling" only. Authority is asked of Access
//! separately. A request with `authorization_details` is the holder's `projection.issue` as before
//! (OP-150 m.9).

use access_kernel::json::b64url_encode;
use serde_json::json;

use super::resource::AccessToken;
use super::{Env, OAuth, Realm, Reply};
use crate::domain::authority::DETAILS_PARAM;
use crate::domain::client::Client;
use crate::domain::dpop::{ClientType, Jkt};
use crate::domain::request::Params;
use crate::domain::tokens::{ACCESS_TYP, SERVICE_TTL_MS, ServiceFacts, service_token_claims};
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthDb, OAuthTx, TokenSigner as _};

/// Whom the product reads the caller as (MD-10, OP-149 m.34 (b)).
#[derive(Clone, Copy)]
pub(crate) enum Caller {
    /// A platform product: its service Party in this realm (OP-149 m.4).
    Party([u8; 16]),
    /// A tenant realm's API client, which has no Party: the client itself.
    Client([u8; 16]),
}

/// The product a service token is asked for, and whom it reads the caller as.
pub(crate) struct ServiceTarget {
    /// The `client_id` of the product: the token's `aud`.
    pub(crate) client_id: String,
    /// Its internal id: the pairwise sector the `sub` is for (MD-10).
    pub(crate) sector: [u8; 16],
    /// The caller as the product reads it.
    pub(crate) caller: Caller,
}

fn invalid_target(description: &str) -> Reply {
    Reply::oauth_error(400, "invalid_target", description)
}

fn active_false() -> Reply {
    Reply::json(200, &json!({ "active": false }))
}

impl<E: Env> OAuth<E> {
    /// Whom the product `sector` reads `client` as, by the stored pairwise value or a fresh one
    /// (MD-10): `None` when a platform product has no service Party in this realm yet.
    async fn caller(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        client: &Client,
    ) -> Result<Option<Caller>, Unavailable> {
        if client.platform_product.is_none() {
            return Ok(Some(Caller::Client(client.uuid)));
        }
        Ok(tx.platform_party(&client.id).await?.map(Caller::Party))
    }

    async fn caller_sub(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        caller: Caller,
        sector: [u8; 16],
    ) -> Result<Option<String>, Unavailable> {
        let candidate = b64url_encode(&self.random::<32>()?);
        match caller {
            Caller::Party(party) => tx.platform_party_pairwise(&party, sector, &candidate).await,
            Caller::Client(client) => tx.client_pairwise(client, sector, &candidate).await,
        }
    }

    /// Whether a `client_credentials` request is for a service token (OP-149 m.31 (a),
    /// m.34 (b)), and for which product. `None` is not one: no `resource`, the realm itself, or
    /// `authorization_details` present, which is the projection path unchanged. A registered
    /// platform product of the deployment is the only resource (RFC 8707 §2, OP-149 m.26 (a),
    /// AG-8); a product never names itself; a public client gets no service token.
    pub(crate) async fn service_target(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
    ) -> Result<Option<Result<ServiceTarget, Reply>>, Unavailable> {
        if params.get(DETAILS_PARAM).is_some() {
            return Ok(None);
        }
        let Some(resource) = params
            .get("resource")
            .filter(|r| *r != realm.issuer.as_str())
        else {
            return Ok(None);
        };
        if client.client_type() != ClientType::Confidential {
            return Ok(Some(Err(Reply::oauth_error(
                400,
                "unauthorized_client",
                "a service token needs a confidential client",
            ))));
        }
        let Some(target) = self.env().db().platform_product(resource).await? else {
            return Ok(Some(Err(invalid_target("not a registered resource"))));
        };
        if target.client_uuid == client.uuid {
            return Ok(Some(Err(invalid_target(
                "a product is not its own resource",
            ))));
        }
        let mut tx = self.begin(realm).await?;
        let caller = self.caller(&mut tx, client).await?;
        tx.commit().await?;
        let Some(caller) = caller else {
            return Ok(Some(Err(Reply::oauth_error(
                400,
                "unauthorized_client",
                "the client has no service Party in this realm",
            ))));
        };
        Ok(Some(Ok(ServiceTarget {
            client_id: String::from(resource),
            sector: target.client_uuid,
            caller,
        })))
    }

    /// Issues the service token of `client` for `target` (RFC 6749 §4.4.3, RFC 9068, OP-149
    /// m.31 (a), m.34 (b)): `iss` the caller's realm, `aud` the target, `sub` the pairwise value
    /// the target reads of the caller, `access_tenant` the caller's tenant, `cnf.jkt` the proof
    /// key; no refresh token, no scope.
    pub(crate) async fn service_token(
        &self,
        realm: &Realm,
        client: &Client,
        target: &ServiceTarget,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let tenant = self.tenant_name(realm)?;
        let mut tx = self.begin(realm).await?;
        let sub = self
            .caller_sub(&mut tx, target.caller, target.sector)
            .await?
            .ok_or(Unavailable)?;
        let alg = tx.jose_alg().await?;
        tx.commit().await?;
        let facts = ServiceFacts {
            issuer: &realm.issuer,
            audience: &target.client_id,
            client_id: &client.id,
            sub: &sub,
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

    /// RFC 7662 for a service token (OP-149 m.31 (a), m.34 (b), MD-8): active while it is
    /// unexpired, the product is still registered, the caller is still a confidential client of
    /// this realm (with its Party, for a product), the tenant is this realm's and the `sub` is
    /// still the one the product reads of the caller. The caller or the product may ask
    /// (RFC 7662 §2.1); anyone else, or anything unprovable, is `active: false`.
    pub(crate) async fn introspect_service(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        asking: &Client,
        at: &AccessToken,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let Some(tenant) = &at.access_tenant else {
            return Ok(active_false());
        };
        let expired = u64::try_from(at.exp).map_or(true, |e| e.saturating_mul(1000) <= now);
        if expired || (asking.id != at.client_id && asking.id != at.aud) {
            return Ok(active_false());
        }
        if *tenant != self.tenant_name(realm)? {
            return Ok(active_false());
        }
        let caller = tx
            .client(&at.client_id)
            .await?
            .and_then(Client::from_row)
            .filter(|c| c.client_type() == ClientType::Confidential);
        let (Some(caller), Some(target)) =
            (caller, self.env().db().platform_product(&at.aud).await?)
        else {
            return Ok(active_false());
        };
        let Some(caller) = self.caller(tx, &caller).await? else {
            return Ok(active_false());
        };
        let sub = self.caller_sub(tx, caller, target.client_uuid).await?;
        if sub.as_deref() != Some(at.sub.as_str()) {
            return Ok(active_false());
        }
        Ok(Reply::json(
            200,
            &json!({
                "active": true,
                "iss": realm.issuer.as_str(),
                "sub": at.sub,
                "aud": at.aud,
                "client_id": at.client_id,
                "access_tenant": tenant,
                "token_type": "DPoP",
                "exp": at.exp,
                "iat": at.iat,
                "cnf": { "jkt": at.jkt.text() },
            }),
        ))
    }
}
