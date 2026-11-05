//! The N:M realm-to-domain map (TN-4, §12.1.1, OP-150 m.2): a realm has one governing domain,
//! and any domain of the tenant may consume its identity Claims through an Acceptance. A binding
//! is retired once and never removed (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{RealmId, TenantTx};
use crate::scope::DomainId;

/// How a domain relates to a realm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// The realm's governing domain (MD-14).
    Governing,
    /// A domain that consumes the realm's Claims through an Acceptance.
    Consuming {
        /// The Acceptance.
        acceptance: [u8; 16],
    },
}

/// Binds `domain` to `realm` (tenant scope): `true` the first time.
///
/// # Errors
/// [`StoreError`]; a second live governing domain fails.
pub async fn bind(
    t: &mut TenantTx,
    realm: RealmId,
    domain: &DomainId,
    role: Role,
) -> Result<bool, StoreError> {
    let (word, acceptance) = match &role {
        Role::Governing => ("governing", None),
        Role::Consuming { acceptance } => ("consuming", Some(acceptance.as_slice())),
    };
    let done = sqlx::query!(
        "INSERT INTO access.realm_domain_binding (tenant_id, realm_id, domain_id, role, acceptance_id)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, realm_id, domain_id) DO NOTHING",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        domain.as_bytes().as_slice(),
        word,
        acceptance,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Retires the binding: `true` the first time.
///
/// # Errors
/// [`StoreError`].
pub async fn retire(
    t: &mut TenantTx,
    realm: RealmId,
    domain: &DomainId,
) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access.realm_domain_binding SET retired_at = now()
          WHERE tenant_id = $1 AND realm_id = $2 AND domain_id = $3 AND retired_at IS NULL",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        domain.as_bytes().as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The live domains of `realm` with their roles.
///
/// # Errors
/// [`StoreError`].
pub async fn domains(
    t: &mut TenantTx,
    realm: RealmId,
) -> Result<Vec<(DomainId, Role)>, StoreError> {
    let rows = sqlx::query!(
        "SELECT domain_id, role, acceptance_id FROM access.realm_domain_binding
          WHERE tenant_id = $1 AND realm_id = $2 AND retired_at IS NULL ORDER BY domain_id",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            let domain = DomainId::from_bytes(
                <[u8; 32]>::try_from(r.domain_id.as_slice()).map_err(|_| StoreError::Corrupt)?,
            );
            let role = match (r.role.as_str(), r.acceptance_id) {
                ("governing", _) => Role::Governing,
                ("consuming", Some(a)) => Role::Consuming {
                    acceptance: <[u8; 16]>::try_from(a.as_slice())
                        .map_err(|_| StoreError::Corrupt)?,
                },
                _ => return Err(StoreError::Corrupt),
            };
            Ok((domain, role))
        })
        .collect()
}
