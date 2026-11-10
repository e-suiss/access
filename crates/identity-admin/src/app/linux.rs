//! `idp.linux.*` changes written under their committed ALLOW (OP-156 m.3 (p)), and the hosts as
//! administrators read them. Each change is a new version of the host; a retired host keeps its
//! name forever (OP-73).

use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::linux::LinuxHostRow;
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;
use crate::domain::linux::{CONSOLE_MAX_S, LinuxChange, NSS_MAX_S};

async fn live(t: &mut TenantTx, host: &str) -> Result<LinuxHostRow, AdminError> {
    Ok(t.linux_hosts()
        .await?
        .into_iter()
        .find(|h| h.name == host && h.live)
        .ok_or(Invalid::NoLinuxHost)?)
}

/// What must hold now for `change`: a new host's name was never used, its server group is live
/// and no live host has its certificate; any other change names a live host.
///
/// # Errors
/// [`Invalid`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &LinuxChange) -> Result<(), AdminError> {
    match change {
        LinuxChange::Register(h) => {
            let hosts = t.linux_hosts().await?;
            if hosts
                .iter()
                .any(|r| r.name == h.name || (r.live && r.certificate == h.certificate))
            {
                return Err(Invalid::LinuxHostExists.into());
            }
            if !t
                .ssh_host_groups()
                .await?
                .iter()
                .any(|g| g.name == h.host_group && g.live)
            {
                return Err(Invalid::NoSshHostGroup.into());
            }
        }
        other => {
            live(t, other.host()).await?;
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
    change: &LinuxChange,
) -> Result<bool, AdminError> {
    let row = match change {
        LinuxChange::Register(h) => LinuxHostRow {
            name: h.name.clone(),
            live: true,
            host_group: h.host_group.clone(),
            certificate: h.certificate.clone(),
            nss_ttl_s: NSS_MAX_S,
            console_ttl_s: CONSOLE_MAX_S,
            sudo_ct: h.sudo_ct,
            shell: h.shell.clone(),
            break_glass: false,
            version: 0,
            position: 0,
        },
        LinuxChange::Retire(host) => LinuxHostRow {
            live: false,
            ..live(t, host).await?
        },
        LinuxChange::OfflinePolicy {
            host,
            nss_ttl_s,
            console_ttl_s,
        } => LinuxHostRow {
            nss_ttl_s: *nss_ttl_s,
            console_ttl_s: *console_ttl_s,
            ..live(t, host).await?
        },
        LinuxChange::BreakGlass { host, enabled } => LinuxHostRow {
            break_glass: *enabled,
            ..live(t, host).await?
        },
    };
    t.put_linux_host(bound, &row).await?;
    Ok(true)
}

/// The hosts as administrators read them, each with its decision position.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    Ok(t.linux_hosts()
        .await?
        .into_iter()
        .filter(|h| key.is_none_or(|k| k == h.name))
        .map(|h| {
            (
                json!({
                    "name": h.name,
                    "host_group": h.host_group,
                    "certificate": h.certificate,
                    "shell": h.shell,
                    "sudo_ct": h.sudo_ct,
                    "nss_ttl_s": h.nss_ttl_s,
                    "console_ttl_s": h.console_ttl_s,
                    "break_glass": h.break_glass,
                    "status": if h.live { "live" } else { "retired" },
                    "version": h.version,
                }),
                h.position,
            )
        })
        .collect())
}
