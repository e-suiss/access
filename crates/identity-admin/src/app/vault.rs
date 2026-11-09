//! `idp.vault.*` changes (OP-154 m.3 (a), (t), MD-13): a Resource's next version and the realm's
//! release mode, each written under its committed ALLOW; and the Resource read.

use access_identity_vault::domain::resource::{Resource, VaultChange};
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::vault::NewResource;
use serde_json::Value as Json;

use crate::AdminError;
use crate::domain::Invalid;

/// What must hold now for `change`: a disabled Resource exists and is enabled.
///
/// # Errors
/// [`Invalid::NoVaultResource`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &VaultChange) -> Result<(), AdminError> {
    if let VaultChange::Disable(name) = change {
        let live = t
            .vault_resource(name)
            .await?
            .is_some_and(|r| r.definition.is_some());
        if !live {
            return Err(Invalid::NoVaultResource.into());
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
    change: &VaultChange,
) -> Result<bool, AdminError> {
    match change {
        VaultChange::Enable(r) | VaultChange::Register(r) => {
            let bytes = r.to_bytes().map_err(|_| Invalid::VaultResource)?;
            t.put_vault_resource(
                bound,
                &NewResource {
                    name: &r.name,
                    upstream: &r.upstream.id,
                    origin: r.origin.name(),
                    definition: Some(&bytes),
                },
            )
            .await?;
        }
        VaultChange::Disable(name) => {
            let row = t
                .vault_resource(name)
                .await?
                .ok_or(Invalid::NoVaultResource)?;
            t.put_vault_resource(
                bound,
                &NewResource {
                    name,
                    upstream: &row.upstream,
                    origin: &row.origin,
                    definition: None,
                },
            )
            .await?;
        }
        VaultChange::ReleaseMode(open) => t.put_vault_release_mode(bound, *open).await?,
    }
    Ok(true)
}

/// The realm's Resources as administrators read them, each with its decision position; a
/// disabled one says so. Never a client secret, only its reference.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    let open = t.vault_release_open().await?;
    let rows = t.vault_resources().await?;
    Ok(rows
        .into_iter()
        .filter(|r| key.is_none_or(|k| k == r.name))
        .map(|r| {
            let mut v = match r.definition.as_deref().map(Resource::from_bytes) {
                Some(Ok(def)) => def.view(),
                _ => serde_json::json!({
                    "resource": r.name,
                    "origin": r.origin,
                    "upstream": r.upstream,
                }),
            };
            if let Some(o) = v.as_object_mut() {
                let status = if r.definition.is_some() {
                    "enabled"
                } else {
                    "disabled"
                };
                o.insert(String::from("status"), Json::from(status));
                o.insert(String::from("version"), Json::from(r.version));
                o.insert(
                    String::from("release_mode"),
                    Json::from(if open { "open" } else { "closed" }),
                );
            }
            (v, r.position)
        })
        .collect())
}
