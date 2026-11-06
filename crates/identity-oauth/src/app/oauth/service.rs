//! The service token of one platform product for another (OP-149 m.31 (a), §9 "two token
//! classes" (ii), E39, MD-7): `client_credentials` with `resource=<the other product's
//! client_id>` (RFC 8707) and no `authorization_details`. It says who is calling, for whom and
//! from which tenant, bound by `cnf.jkt` (TN-27); it carries no authority (no details, no
//! contract, no family, no status) and the product it is for reads it as "who is calling" only.
//! Authority is asked of Access separately. A request with `authorization_details` is the
//! holder's `projection.issue` as before (OP-150 m.9).

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
use crate::ports::oauth::{OAuthDb, OAuthTx, TenantIds as _, TokenSigner as _};

/// The product a service token is asked for, and the caller's Party it names.
pub(crate) struct ServiceTarget {
    /// The `client_id` of the product: the token's `aud`.
    pub(crate) client_id: String,
    /// Its internal id: the pairwise sector the `sub` is for (MD-10).
    pub(crate) sector: [u8; 16],
    /// The caller's service Party in this realm (OP-149 m.4).
    pub(crate) party: [u8; 16],
}

fn invalid_target(description: &str) -> Reply {
    Reply::oauth_error(400, "invalid_target", description)
}

fn active_false() -> Reply {
    Reply::json(200, &json!({ "active": false }))
}

/// The active platform product client with `client_id` in this realm, if it is one.
async fn product<Tx: OAuthTx>(tx: &mut Tx, client_id: &str) -> Result<Option<Client>, Unavailable> {
    Ok(tx
        .client(client_id)
        .await?
        .and_then(Client::from_row)
        .filter(|c| c.platform_product.is_some()))
}

impl<E: Env> OAuth<E> {
    /// Whether a `client_credentials` request is for a service token (OP-149 m.31 (a)), and for
    /// which product. `None` is not one: no `resource`, the realm itself, or
    /// `authorization_details` present, which is the projection path unchanged. Only a platform
    /// product calls a product, never itself; any other `resource` is `invalid_target`
    /// (RFC 8707 §2, OP-149 m.26 (a), AG-8).
    pub(crate) async fn service_target(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
    ) -> Result<Option<Result<ServiceTarget, Reply>>, Unavailable> {
        if params.get(DETAILS_PARAM).is_some() || client.client_type() != ClientType::Confidential {
            return Ok(None);
        }
        let Some(resource) = params
            .get("resource")
            .filter(|r| *r != realm.issuer.as_str())
        else {
            return Ok(None);
        };
        let mut tx = self.begin(realm).await?;
        let target = product(&mut tx, resource).await?;
        let party = tx.platform_party(&client.id).await?;
        tx.commit().await?;
        let Some(target) = target else {
            return Ok(Some(Err(invalid_target("not a registered resource"))));
        };
        if client.platform_product.is_none() {
            return Ok(Some(Err(invalid_target(
                "only a platform product calls a product",
            ))));
        }
        if target.id == client.id {
            return Ok(Some(Err(invalid_target(
                "a product is not its own resource",
            ))));
        }
        let Some(party) = party else {
            return Ok(Some(Err(Reply::oauth_error(
                400,
                "unauthorized_client",
                "the client has no service Party in this realm",
            ))));
        };
        Ok(Some(Ok(ServiceTarget {
            client_id: target.id,
            sector: target.uuid,
            party,
        })))
    }

    /// Issues the service token of `client` for `target` (RFC 6749 §4.4.3, RFC 9068, OP-149
    /// m.31 (a)): `aud` the target, `sub` the pairwise value the target reads of the caller's
    /// Party, `access_tenant` the caller's tenant, `cnf.jkt` the proof key; no refresh token,
    /// no scope.
    pub(crate) async fn service_token(
        &self,
        realm: &Realm,
        client: &Client,
        target: &ServiceTarget,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        // OP-149 m.19 (a): the tenant by its opaque id, or nothing (G50)
        let tenant = self
            .env()
            .tenant_ids()
            .external(realm.tenant.as_bytes())
            .ok_or(Unavailable)?;
        let mut tx = self.begin(realm).await?;
        let candidate = b64url_encode(&self.random::<32>()?);
        let sub = tx
            .platform_party_pairwise(&target.party, target.sector, &candidate)
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

    /// RFC 7662 for a service token (OP-149 m.31 (a), MD-8): active while it is unexpired, both
    /// products are still registered, the caller still holds its Party here and the `sub` is
    /// still the one the target reads of it. The caller or the target may ask (RFC 7662 §2.1);
    /// anyone else, or anything unprovable, is `active: false`.
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
        let (Some(_caller), Some(target), Some(party)) = (
            product(tx, &at.client_id).await?,
            product(tx, &at.aud).await?,
            tx.platform_party(&at.client_id).await?,
        ) else {
            return Ok(active_false());
        };
        let candidate = b64url_encode(&self.random::<32>()?);
        let sub = tx
            .platform_party_pairwise(&party, target.uuid, &candidate)
            .await?;
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
