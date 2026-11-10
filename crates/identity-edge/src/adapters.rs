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

/// Why a gateway setting was refused.
#[derive(Debug, thiserror::Error)]
pub enum SettingError {
    /// No live gateway of that kind and name.
    #[error("no such gateway")]
    NoGateway,
    /// The setting is outside its model.
    #[error("invalid gateway setting")]
    Invalid,
    /// Storage failed.
    #[error(transparent)]
    Store(#[from] access_store::StoreError),
}

async fn live(t: &mut TenantTx, kind: GatewayKind, name: &str) -> Result<(), SettingError> {
    access_store::edge::live_gateway(t, kind.name(), name)
        .await?
        .map(|_| ())
        .ok_or(SettingError::NoGateway)
}

/// `idp.gateway.radius_client_register` (OP-155 m.3 (f)): `RadSec` client `client` of the live
/// RADIUS gateway `gateway`, by the SHA-256 of its TLS certificate; registering a client again
/// replaces its certificate.
///
/// # Errors
/// [`SettingError`].
pub async fn radius_client_register(
    t: &mut TenantTx,
    bound: &Bound,
    gateway: &str,
    client: &str,
    cert: &[u8; 32],
) -> Result<u64, SettingError> {
    if !valid_name(client) {
        return Err(SettingError::Invalid);
    }
    live(t, GatewayKind::Radius, gateway).await?;
    Ok(access_store::edge::put_radius_client(t, bound, gateway, client, cert).await?)
}

/// `idp.gateway.keytab_policy` (OP-155 m.3 (o)): the live Kerberos gateway `gateway` accepts
/// tickets for `spn` only and rotates its keytab every `rotate_days`; the key version floor an
/// emergency set is kept.
///
/// # Errors
/// [`SettingError`].
pub async fn keytab_policy(
    t: &mut TenantTx,
    bound: &Bound,
    gateway: &str,
    spn: &str,
    rotate_days: u16,
) -> Result<u64, SettingError> {
    if !crate::domain::kerberos::valid_spn(spn)
        || !(1..=crate::domain::kerberos::MAX_ROTATE_DAYS).contains(&rotate_days)
    {
        return Err(SettingError::Invalid);
    }
    live(t, GatewayKind::Kerberos, gateway).await?;
    let floor = access_store::edge::keytab_policy(t, gateway)
        .await?
        .map_or(0, |p| p.kvno_floor);
    let p = access_store::edge::KeytabPolicy {
        spn: String::from(spn),
        rotate_days,
        kvno_floor: floor,
    };
    Ok(access_store::edge::put_keytab_policy(t, bound, gateway, &p).await?)
}

/// `idp.gateway.keytab_emergency` (OP-155 m.3 (o), reserved CT3): tickets under any key version
/// below `kvno`, the replacement keytab's, are refused at once. The floor never goes down.
///
/// # Errors
/// [`SettingError`]; [`SettingError::Invalid`] without a policy or for a lower floor.
pub async fn keytab_emergency(
    t: &mut TenantTx,
    bound: &Bound,
    gateway: &str,
    kvno: u32,
) -> Result<u64, SettingError> {
    live(t, GatewayKind::Kerberos, gateway).await?;
    let Some(mut p) = access_store::edge::keytab_policy(t, gateway).await? else {
        return Err(SettingError::Invalid);
    };
    if kvno <= p.kvno_floor {
        return Err(SettingError::Invalid);
    }
    p.kvno_floor = kvno;
    Ok(access_store::edge::put_keytab_policy(t, bound, gateway, &p).await?)
}
