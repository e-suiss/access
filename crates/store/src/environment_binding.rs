//! The N:M environment-to-domain map (TN-4, §12.1.1, OP-150 m.2): an environment has one governing domain,
//! and any domain of the tenant may consume its identity Claims through an Acceptance. A binding
//! is retired once and never removed (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{EnvironmentId, TenantTx};
use crate::scope::DomainId;

/// How a domain relates to an environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// The environment's governing domain (MD-14).
    Governing,
    /// A domain that consumes the environment's Claims through an Acceptance.
    Consuming {
        /// The Acceptance.
        acceptance: [u8; 16],
    },
}

/// Binds `domain` to `environment` (tenant scope): `true` the first time.
///
/// # Errors
/// [`StoreError`]; a second live governing domain fails.
pub async fn bind(
    t: &mut TenantTx,
    environment: EnvironmentId,
    domain: &DomainId,
    role: Role,
) -> Result<bool, StoreError> {
    let (word, acceptance) = match &role {
        Role::Governing => ("governing", None),
        Role::Consuming { acceptance } => ("consuming", Some(acceptance.as_slice())),
    };
    let done = sqlx::query!(
        "INSERT INTO access.environment_domain_binding (tenant_id, environment_id, domain_id, role, acceptance_id)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, environment_id, domain_id) DO NOTHING",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*environment.as_bytes()),
        domain.as_bytes().as_slice(),
        word,
        acceptance,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Binds `domain` as consuming `environment`'s Claims through `acceptance`, holding only once
/// `cooling_s` seconds have passed (TN-4, OP-159 m.48 (b)): `true` the first time.
///
/// # Errors
/// [`StoreError`].
pub async fn bind_cooling(
    t: &mut TenantTx,
    environment: EnvironmentId,
    domain: &DomainId,
    acceptance: &[u8; 16],
    cooling_s: i64,
) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "INSERT INTO access.environment_domain_binding (tenant_id, environment_id, domain_id, role, acceptance_id,
           effective_at)
         VALUES ($1, $2, $3, 'consuming', $4, clock_timestamp() + $5::bigint * interval '1 second')
         ON CONFLICT (tenant_id, environment_id, domain_id) DO NOTHING",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*environment.as_bytes()),
        domain.as_bytes().as_slice(),
        acceptance.as_slice(),
        cooling_s,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Whether `domain` has a live binding to `environment`, holding or still cooling (TN-4, OP-159
/// m.48 (b)).
///
/// # Errors
/// [`StoreError`].
pub async fn bound(
    t: &mut TenantTx,
    environment: EnvironmentId,
    domain: &DomainId,
) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM access.environment_domain_binding
                           WHERE tenant_id = $1 AND environment_id = $2 AND domain_id = $3
                             AND retired_at IS NULL) AS "bound!""#,
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*environment.as_bytes()),
        domain.as_bytes().as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?)
}

/// Retires the binding: `true` the first time.
///
/// # Errors
/// [`StoreError`].
pub async fn retire(
    t: &mut TenantTx,
    environment: EnvironmentId,
    domain: &DomainId,
) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access.environment_domain_binding SET retired_at = now()
          WHERE tenant_id = $1 AND environment_id = $2 AND domain_id = $3 AND retired_at IS NULL",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*environment.as_bytes()),
        domain.as_bytes().as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The live domains of `environment` with their roles; a consuming binding still cooling is not one
/// yet (OP-159 m.48 (b)).
///
/// # Errors
/// [`StoreError`].
pub async fn domains(
    t: &mut TenantTx,
    environment: EnvironmentId,
) -> Result<Vec<(DomainId, Role)>, StoreError> {
    let rows = sqlx::query!(
        "SELECT domain_id, role, acceptance_id FROM access.environment_domain_binding
          WHERE tenant_id = $1 AND environment_id = $2 AND retired_at IS NULL
            AND (effective_at IS NULL OR effective_at <= clock_timestamp())
          ORDER BY domain_id",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*environment.as_bytes()),
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

/// The environments of the transaction's tenant whose Claims `domain` consumes (TN-4, OP-159 m.47
/// (d)): for a tenant environment, its management environment.
///
/// # Errors
/// [`StoreError`].
pub async fn consumed_by(
    t: &mut TenantTx,
    domain: &DomainId,
) -> Result<Vec<EnvironmentId>, StoreError> {
    let rows = sqlx::query_scalar!(
        "SELECT environment_id FROM access.environment_domain_binding
          WHERE tenant_id = $1 AND domain_id = $2 AND role = 'consuming' AND retired_at IS NULL
            AND (effective_at IS NULL OR effective_at <= clock_timestamp())
          ORDER BY environment_id",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        domain.as_bytes().as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|u| EnvironmentId::from_bytes(*u.as_bytes()))
        .collect())
}
