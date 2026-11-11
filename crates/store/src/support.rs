//! The realm's support case systems (OP-157 m.3 (e)): each a Claim issuer of `support_case`
//! Claims, written under its `idp.support.*` decision. A retired name is never reused and nothing
//! is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// One version of a case system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseSystemRow {
    /// Its name: the `system` of every case ref it states.
    pub name: String,
    /// Whether it is live.
    pub live: bool,
    /// The vendor.
    pub provider: String,
    /// The issuer Party its Claims are signed as.
    pub issuer: [u8; 16],
    /// The Claim body format.
    pub format: String,
    /// Its version.
    pub version: u64,
    /// The position of the decision that wrote it.
    pub position: u64,
}

/// What a new version of a case system says.
#[derive(Clone, Copy, Debug)]
pub struct NewCaseSystem<'a> {
    /// Its name.
    pub name: &'a str,
    /// Whether it is live.
    pub live: bool,
    /// Its vendor.
    pub provider: &'a str,
    /// Its issuer Party.
    pub issuer: &'a [u8; 16],
    /// Its format.
    pub format: &'a str,
}

impl TenantTx {
    /// Writes the next version of case system `c.name` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_case_system(
        &mut self,
        bound: &Bound,
        c: &NewCaseSystem<'_>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.support_case_systems (tenant_id, realm_id, name, version, state,
                    provider, issuer, format, domain_id, decision_pos)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9
               FROM access.support_case_systems
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
            tenant,
            realm,
            c.name,
            if c.live { "live" } else { "retired" },
            c.provider,
            c.issuer.as_slice(),
            c.format,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest version of every case system, live and retired, by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn case_systems(&mut self) -> Result<Vec<CaseSystemRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (name) name, state, provider, issuer, format, version, decision_pos
               FROM access.support_case_systems
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY name, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(CaseSystemRow {
                    name: r.name,
                    live: r.state == "live",
                    provider: r.provider,
                    issuer: <[u8; 16]>::try_from(r.issuer.as_slice())
                        .map_err(|_| StoreError::Corrupt)?,
                    format: r.format,
                    version: unsigned(r.version)?,
                    position: unsigned(r.decision_pos)?,
                })
            })
            .collect()
    }
}
