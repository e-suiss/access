//! A realm's post-quantum signing profile and hybrid key exchange share policy (CR-41, CR-12
//! m.3, OP-159 m.3 (a), (o), (t)): `idp.realm.signing_profile` opens an ML-DSA parameter set,
//! `signing_profile_close` takes it out, `idp.realm.kex_share` sets the share policy. Nothing is
//! deleted (OP-73): the decisions that wrote them stay in the realm's config log.

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

/// The realm's settings as they are now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmSigning {
    /// `ml-dsa-65`, `ml-dsa-44` or `ml-dsa-87` while the profile is open.
    pub profile: Option<String>,
    /// `optimistic` or `advertise-only`.
    pub kex_share: String,
}

impl Default for RealmSigning {
    fn default() -> Self {
        Self {
            profile: None,
            kex_share: String::from("optimistic"),
        }
    }
}

impl TenantTx {
    fn signing_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
        ))
    }

    /// The realm's signing profile and share policy.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn realm_signing(&mut self) -> Result<RealmSigning, StoreError> {
        let (tenant, realm) = self.signing_scope()?;
        let row = sqlx::query!(
            "SELECT signing_profile, kex_share FROM access.realms
              WHERE tenant_id = $1 AND realm_id = $2",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map_or_else(RealmSigning::default, |r| RealmSigning {
            profile: r.signing_profile,
            kex_share: r.kex_share,
        }))
    }

    /// Opens (`Some`) or closes (`None`) the realm's signing profile under the bound decision.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_signing_profile(
        &mut self,
        _bound: &Bound,
        profile: Option<&str>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.signing_scope()?;
        sqlx::query!(
            "UPDATE access.realms SET signing_profile = $3 WHERE tenant_id = $1 AND realm_id = $2",
            tenant,
            realm,
            profile,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Sets the realm's key exchange share policy under the bound decision.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_kex_share(&mut self, _bound: &Bound, mode: &str) -> Result<(), StoreError> {
        let (tenant, realm) = self.signing_scope()?;
        sqlx::query!(
            "UPDATE access.realms SET kex_share = $3 WHERE tenant_id = $1 AND realm_id = $2",
            tenant,
            realm,
            mode,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}
