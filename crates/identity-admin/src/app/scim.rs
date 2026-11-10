//! `idp.scim.*` against the realm's current state and its write in the decision's transaction
//! (OP-155 m.3 (a), (g), IDP-23, IDP-29): a client name is registered once; a rotation or a
//! retirement needs a live client; a target's secret is sealed under the realm KEK, and without
//! the vault no target is registered (MD-8).

use access_identity_hooks::ports::KeyVault;
use access_identity_scim::app::clients::{self, ClientError};
use access_store::identity::TenantTx;
use access_store::idp::Bound;

use super::ClientSecret;
use crate::AdminError;
use crate::domain::Invalid;
use crate::domain::scim::ScimChange;

fn refused(e: ClientError) -> AdminError {
    match e {
        ClientError::Store(s) => s.into(),
        ClientError::Taken => AdminError::Conflict,
        ClientError::NotLive => Invalid::NoScimClient.into(),
        ClientError::Random => AdminError::Encode,
        ClientError::Name | ClientError::Profile | ClientError::Url => Invalid::ScimClient.into(),
    }
}

/// Whether `s` fits the realm's current SCIM clients and targets.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, s: &ScimChange) -> Result<(), AdminError> {
    match s {
        ScimChange::ClientRegister { name, org, .. } => {
            clients::registrable(t, name).await.map_err(refused)?;
            // TN-95
            if let Some(o) = org {
                super::orgs::live_org(t, *o).await?;
            }
            Ok(())
        }
        ScimChange::TokenRotate(n) | ScimChange::ClientRetire(n) => {
            clients::live(t, n).await.map_err(refused)
        }
        ScimChange::OutboundRegister { name, .. } => {
            let taken = access_store::scim::targets(t)
                .await?
                .iter()
                .any(|x| x.name == *name);
            if taken {
                Err(AdminError::Conflict)
            } else {
                Ok(())
            }
        }
        ScimChange::OutboundRetire(n) => {
            let live = access_store::scim::targets(t)
                .await?
                .iter()
                .any(|x| x.name == *n && x.live);
            if live {
                Ok(())
            } else {
                Err(Invalid::NoScimClient.into())
            }
        }
    }
}

/// Writes `s` under `bound`; a registered or rotated client's bearer secret, shown once.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    s: &ScimChange,
    vault: Option<&dyn KeyVault>,
) -> Result<Option<ClientSecret>, AdminError> {
    match s {
        ScimChange::ClientRegister { name, profile, .. } => {
            let secret = clients::register(t, bound, name, profile.as_deref())
                .await
                .map_err(refused)?;
            Ok(Some(ClientSecret(String::from(secret.expose()))))
        }
        ScimChange::TokenRotate(n) => {
            let secret = clients::rotate(t, bound, n).await.map_err(refused)?;
            Ok(Some(ClientSecret(String::from(secret.expose()))))
        }
        ScimChange::ClientRetire(n) => {
            clients::retire(t, bound, n).await.map_err(refused)?;
            Ok(None)
        }
        ScimChange::OutboundRegister {
            name,
            base_url,
            secret,
        } => {
            // MD-8
            let vault = vault.ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
            let realm = t.realm().ok_or(AdminError::NoRealm)?;
            let sealed = vault
                .seal(
                    t.tenant(),
                    realm,
                    &clients::target_id(name),
                    secret.expose().as_bytes(),
                )
                .map_err(|_| AdminError::Unavailable(String::from("vault")))?;
            clients::register_target(t, bound, name, base_url, &sealed)
                .await
                .map_err(refused)?;
            Ok(None)
        }
        ScimChange::OutboundRetire(n) => {
            clients::retire_target(t, bound, n).await.map_err(refused)?;
            Ok(None)
        }
    }
}
