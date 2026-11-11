//! `idp.support.case_system_*` changes written under their committed ALLOW (OP-157 m.3 (e)), and
//! the case systems as administrators read them. A case system only names an issuer: its
//! `support_case` Claims hold support Grants once the domain accepts them as `predicate-input`
//! with its own Acceptance. A retired name is never reused (OP-73).

use access_kernel::json::b64url_encode;
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::support::{CaseSystemRow, NewCaseSystem};
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;
use crate::domain::support::{CaseSystem, CaseSystemChange};

/// What must hold now for `change`: a new name was never used; a retired system is live.
///
/// # Errors
/// [`Invalid`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &CaseSystemChange) -> Result<(), AdminError> {
    let rows = t.case_systems().await?;
    match change {
        CaseSystemChange::Register(c) => {
            if rows.iter().any(|r| r.name == c.name) {
                return Err(AdminError::Conflict);
            }
        }
        CaseSystemChange::Retire(name) => {
            if !rows.iter().any(|r| r.name == *name && r.live) {
                return Err(Invalid::CaseSystemUnknown.into());
            }
        }
    }
    Ok(())
}

fn new(c: &CaseSystem) -> NewCaseSystem<'_> {
    NewCaseSystem {
        name: &c.name,
        live: true,
        provider: &c.provider,
        issuer: &c.issuer,
        format: &c.format,
    }
}

/// Writes `change` under `bound`.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &CaseSystemChange,
) -> Result<bool, AdminError> {
    match change {
        CaseSystemChange::Register(c) => t.put_case_system(bound, &new(c)).await?,
        CaseSystemChange::Retire(name) => {
            let row: CaseSystemRow = t
                .case_systems()
                .await?
                .into_iter()
                .find(|r| r.name == *name)
                .ok_or(Invalid::CaseSystemUnknown)?;
            t.put_case_system(
                bound,
                &NewCaseSystem {
                    name: &row.name,
                    live: false,
                    provider: &row.provider,
                    issuer: &row.issuer,
                    format: &row.format,
                },
            )
            .await?;
        }
    }
    Ok(true)
}

/// The case systems as administrators read them, each with its decision position.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    Ok(t.case_systems()
        .await?
        .into_iter()
        .filter(|r| key.is_none_or(|k| k == r.name))
        .map(|r| {
            (
                json!({
                    "name": r.name,
                    "issuer": b64url_encode(&r.issuer),
                    "provider": r.provider,
                    "format": r.format,
                    "status": if r.live { "live" } else { "retired" },
                    "version": r.version,
                }),
                r.position,
            )
        })
        .collect())
}
