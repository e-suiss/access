//! The gateway registry in PostgreSQL, read by the router role (OP-132 m.3), and its writes
//! under an `idp.gateway.*` decision (OP-155 m.3 (a), (c)).

use access_internal_api::edge::{GatewayKind, GatewayUri, valid_name};
use access_store::Pool;
use access_store::identity::TenantTx;
use access_store::idp::Bound;

use crate::EdgeError;
use crate::app::Registry;
use crate::domain::Gateway;

/// The registry over the router pool.
#[derive(Clone)]
pub struct PgRegistry(pub Pool);

impl Registry for PgRegistry {
    async fn gateway(
        &self,
        uri: &GatewayUri,
        cert: &[u8; 32],
    ) -> Result<Option<Gateway>, EdgeError> {
        let mut routes =
            access_store::edge::gateway_routes(&self.0, uri.kind.name(), &uri.name, cert).await?;
        if routes.len() != 1 {
            return Ok(None);
        }
        let Some(r) = routes.pop() else {
            return Ok(None);
        };
        Ok(Some(Gateway {
            tenant: r.tenant,
            realm: r.realm,
            slug: r.slug,
            uri: uri.clone(),
        }))
    }
}

/// Why a registration was refused.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// The name is not a gateway name.
    #[error("invalid gateway name")]
    Name,
    /// Storage failed.
    #[error(transparent)]
    Store(#[from] access_store::StoreError),
}

/// `idp.gateway.register`: the gateway `kind`/`name` of the transaction's realm, live with the
/// client certificate whose SHA-256 is `cert` (a re-registration replaces the certificate).
///
/// # Errors
/// [`RegisterError`].
pub async fn register(
    t: &mut TenantTx,
    bound: &Bound,
    kind: GatewayKind,
    name: &str,
    cert: &[u8; 32],
) -> Result<u64, RegisterError> {
    if !valid_name(name) {
        return Err(RegisterError::Name);
    }
    Ok(access_store::edge::put_gateway(t, bound, kind.name(), name, cert, true).await?)
}

/// `idp.gateway.retire`: the gateway stops being answered; `false` when it is not live.
///
/// # Errors
/// [`RegisterError`].
pub async fn retire(
    t: &mut TenantTx,
    bound: &Bound,
    kind: GatewayKind,
    name: &str,
) -> Result<bool, RegisterError> {
    let Some(cert) = access_store::edge::live_gateway(t, kind.name(), name).await? else {
        return Ok(false);
    };
    access_store::edge::put_gateway(t, bound, kind.name(), name, &cert, false).await?;
    Ok(true)
}
