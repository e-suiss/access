//! A realm's crypto and password hash profiles (OP-158 m.3 (a), (y), m.6 (b), CR-15, CR-36):
//! `idp.realm.crypto_profile` turns the FIPS profile on or off, `idp.realm.hash_profile`
//! raises the Argon2id profile. Each write is a new version carrying both.

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

/// The realm's settings as they are now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmCrypto {
    /// The FIPS profile is on.
    pub fips: bool,
    /// `canonical` or `high-memory`.
    pub hash_profile: String,
}

impl Default for RealmCrypto {
    fn default() -> Self {
        Self {
            fips: false,
            hash_profile: String::from("canonical"),
        }
    }
}

impl TenantTx {
    fn crypto_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
        ))
    }

    /// The realm's newest settings; the defaults when none was written.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn realm_crypto(&mut self) -> Result<RealmCrypto, StoreError> {
        let (tenant, realm) = self.crypto_scope()?;
        let row = sqlx::query!(
            "SELECT fips, hash_profile FROM access.realm_crypto
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map_or_else(RealmCrypto::default, |r| RealmCrypto {
            fips: r.fips,
            hash_profile: r.hash_profile,
        }))
    }

    /// Writes a new version under `bound`: `fips` and `hash_profile` where given, the rest
    /// copied from the newest one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_realm_crypto(
        &mut self,
        bound: &Bound,
        fips: Option<bool>,
        hash_profile: Option<&str>,
    ) -> Result<(), StoreError> {
        let now = self.realm_crypto().await?;
        let (tenant, realm) = self.crypto_scope()?;
        sqlx::query!(
            "INSERT INTO access.realm_crypto (tenant_id, realm_id, version, fips, hash_profile,
                    domain_id, decision_pos)
             SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6
               FROM access.realm_crypto WHERE tenant_id = $1 AND realm_id = $2",
            tenant,
            realm,
            fips.unwrap_or(now.fips),
            hash_profile.unwrap_or(&now.hash_profile),
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}
