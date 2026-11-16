//! The coordinator an environment names (`idp.environment.coordinator`, OP-156 m.3 (t), §8.17.6.5): the
//! public Needs Attention endpoint its hub links pending approvals to. Scoped to the
//! transaction's environment by row-level security; nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*environment.as_bytes()),
    ))
}

impl TenantTx {
    /// The environment's coordinator Needs Attention URL; `None` when it names none or never decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn coordinator(&mut self) -> Result<Option<String>, StoreError> {
        let (tenant, environment) = scope(self)?;
        let r = sqlx::query_scalar!(
            "SELECT attention_url FROM access.idp_coordinator_settings
              WHERE tenant_id = $1 AND environment_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            environment,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(r.flatten())
    }

    /// Writes the next coordinator setting under `bound` (`idp.environment.coordinator`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_coordinator(
        &mut self,
        bound: &Bound,
        attention_url: Option<&str>,
    ) -> Result<(), StoreError> {
        let (tenant, environment) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_coordinator_settings
               (tenant_id, environment_id, version, attention_url, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_coordinator_settings
                               WHERE tenant_id = $1 AND environment_id = $2), 0) + 1,
                    $3, $4, $5",
            tenant,
            environment,
            attention_url,
            bound.domain().as_bytes().as_slice(),
            i64::try_from(bound.position()).map_err(|_| StoreError::Range)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}
