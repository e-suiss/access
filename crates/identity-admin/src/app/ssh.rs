//! `idp.ssh.*` changes written under their committed ALLOW (OP-156 m.3 (o)), and the server
//! groups as administrators read them. A CA change is recorded here; access-server brings the
//! identity signer's keys in line with it. A retired server group keeps its name forever (OP-73).

use access_identity_ssh::domain::change::SshChange;
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;

/// Whether the realm's CA is on: its newest change turned it on, rotated or replaced its key.
///
/// # Errors
/// [`AdminError`].
pub async fn ca_on(t: &mut TenantTx) -> Result<bool, AdminError> {
    Ok(t.ssh_ca_change()
        .await?
        .is_some_and(|c| c.change != "disable"))
}

/// What must hold now for `change`: the CA is off to be turned on and on for anything else; a
/// new server group's name was never used, a retired one is live.
///
/// # Errors
/// [`Invalid`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &SshChange) -> Result<(), AdminError> {
    match change {
        SshChange::CaEnable => {
            if ca_on(t).await? {
                return Err(AdminError::Conflict);
            }
        }
        SshChange::CaDisable | SshChange::CaRotate | SshChange::CaEmergency => {
            if !ca_on(t).await? {
                return Err(AdminError::Conflict);
            }
        }
        SshChange::HostGroupRegister { name, .. } => {
            if t.ssh_host_groups().await?.iter().any(|g| g.name == *name) {
                return Err(Invalid::SshHostGroupExists.into());
            }
        }
        SshChange::HostGroupRetire(name) => {
            if !t
                .ssh_host_groups()
                .await?
                .iter()
                .any(|g| g.name == *name && g.live)
            {
                return Err(Invalid::NoSshHostGroup.into());
            }
        }
    }
    Ok(())
}

/// Writes `change` under `bound`.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &SshChange,
) -> Result<bool, AdminError> {
    match change {
        SshChange::HostGroupRegister { name, description } => {
            t.put_ssh_host_group(bound, name, true, description).await?;
        }
        SshChange::HostGroupRetire(name) => {
            let row = t
                .ssh_host_groups()
                .await?
                .into_iter()
                .find(|g| g.name == *name)
                .ok_or(Invalid::NoSshHostGroup)?;
            t.put_ssh_host_group(bound, name, false, &row.description)
                .await?;
        }
        ca => {
            let name = ca.ca_name().ok_or(Invalid::SshCa)?;
            t.put_ssh_ca_change(bound, name).await?;
        }
    }
    Ok(true)
}

/// The server groups as administrators read them, each with its decision position.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    Ok(t.ssh_host_groups()
        .await?
        .into_iter()
        .filter(|g| key.is_none_or(|k| k == g.name))
        .map(|g| {
            (
                json!({
                    "name": g.name,
                    "description": g.description,
                    "status": if g.live { "live" } else { "retired" },
                    "version": g.version,
                }),
                g.position,
            )
        })
        .collect())
}
