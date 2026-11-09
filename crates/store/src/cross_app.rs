//! The realm's cross-app connections for ID-JAG (OP-154 m.3 (n), AG-28, §11.11.2): one version
//! per `idp.client.cross_app_connection` or `cross_app_connection_retire`, the newest rules.
//! Scoped to the transaction's realm by row-level security; nothing is deleted (OP-73).

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

/// One cross-app connection as its newest version says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossAppRow {
    /// Its name in the realm.
    pub name: String,
    /// Its version.
    pub version: u64,
    /// `live` or `retired`.
    pub state: String,
    /// The requesting client.
    pub client_id: String,
    /// The Resource authorization server's issuer, the ID-JAG's `aud`.
    pub audience: String,
    /// The resource at that server.
    pub resource: String,
    /// The scopes it may ask for: a hint, never authority.
    pub scopes: Vec<String>,
    /// How the subject is named: `pairwise`.
    pub subject_policy: String,
}

impl TenantTx {
    /// The newest version of the cross-app connection `name`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn cross_app_connection(
        &mut self,
        name: &str,
    ) -> Result<Option<CrossAppRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT name, version, state, client_id, audience, resource, scopes, subject_policy
               FROM access.idp_cross_app_connections
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3
              ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
            name,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(CrossAppRow {
                name: r.name,
                version: u64::try_from(r.version).map_err(|_| StoreError::Corrupt)?,
                state: r.state,
                client_id: r.client_id,
                audience: r.audience,
                resource: r.resource,
                scopes: r.scopes,
                subject_policy: r.subject_policy,
            })
        })
        .transpose()
    }

    /// Whether a live cross-app connection lets `client_id` ask for an ID-JAG for `audience`
    /// and `resource`, compared as exact strings.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn cross_app_connected(
        &mut self,
        client_id: &str,
        audience: &str,
        resource: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let found = sqlx::query_scalar!(
            r#"SELECT EXISTS (
                 SELECT 1 FROM access.idp_cross_app_connections c
                  WHERE c.tenant_id = $1 AND c.realm_id = $2 AND c.client_id = $3
                    AND c.audience = $4 AND c.resource = $5 AND c.state = 'live'
                    AND c.version = (SELECT max(n.version) FROM access.idp_cross_app_connections n
                                      WHERE n.tenant_id = c.tenant_id AND n.realm_id = c.realm_id
                                        AND n.name = c.name)
               ) AS "found!""#,
            tenant,
            realm,
            client_id,
            audience,
            resource,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(found)
    }

    /// Records `row` as the next version of its connection under `bound`.
    ///
    /// # Errors
    /// [`StoreError`]; a version already taken is an integrity error.
    pub async fn put_cross_app_connection(
        &mut self,
        bound: &Bound,
        row: &CrossAppRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_cross_app_connections
               (tenant_id, realm_id, name, version, state, client_id, audience, resource, scopes,
                subject_policy, domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            tenant,
            realm,
            row.name,
            i64::try_from(row.version).map_err(|_| StoreError::Range)?,
            row.state,
            row.client_id,
            row.audience,
            row.resource,
            &row.scopes,
            row.subject_policy,
            bound.domain().as_bytes().as_slice(),
            i64::try_from(bound.position()).map_err(|_| StoreError::Range)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}
