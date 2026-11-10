//! First-contact token rows of a realm (OP-156 m.3 (z), E58): the issuer key of each 30-day
//! period, sealed, and one row per issued token for the per-identity daily limit. Nothing names
//! a blinded message or a token; the spent set is Relay's. Nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// One period's issuer key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstContactKey {
    /// The 30-day period it signs in.
    pub period: i64,
    /// `token_key_id`.
    pub token_key_id: [u8; 32],
    /// The RFC 9578 token key.
    pub token_key: Vec<u8>,
    /// The PKCS#8 key, sealed under the realm KEK.
    pub sealed_key: Vec<u8>,
}

impl TenantTx {
    /// The keys of `from` and later periods, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn first_contact_keys(
        &mut self,
        from: i64,
    ) -> Result<Vec<FirstContactKey>, StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "SELECT period, token_key_id, token_key, sealed_key FROM access.first_contact_keys
              WHERE tenant_id = $1 AND realm_id = $2 AND period >= $3 ORDER BY period",
            tenant,
            realm,
            from,
        )
        .fetch_all(&mut *self.tx)
        .await?
        .into_iter()
        .map(|r| {
            Ok(FirstContactKey {
                period: r.period,
                token_key_id: <[u8; 32]>::try_from(r.token_key_id)
                    .map_err(|_| StoreError::Corrupt)?,
                token_key: r.token_key,
                sealed_key: r.sealed_key,
            })
        })
        .collect()
    }

    /// Keeps `key` unless its period already has one; `false` when another writer won.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_first_contact_key(
        &mut self,
        key: &FirstContactKey,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.first_contact_keys
               (tenant_id, realm_id, period, token_key_id, token_key, sealed_key)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, realm_id, period) DO NOTHING",
            tenant,
            realm,
            key.period,
            key.token_key_id.as_slice(),
            key.token_key,
            key.sealed_key,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// How many tokens `subject` was issued on `day`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn first_contact_issued(
        &mut self,
        subject: [u8; 16],
        day: i32,
    ) -> Result<i64, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM access.first_contact_issued
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND day = $4"#,
            tenant,
            realm,
            Uuid::from_bytes(subject),
            day,
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// Counts one token issued to `subject` on `day` under the key of `period`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_first_contact_issued(
        &mut self,
        subject: [u8; 16],
        day: i32,
        period: i64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.first_contact_issued (tenant_id, realm_id, subject_id, day, period)
             VALUES ($1, $2, $3, $4, $5)",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            day,
            period,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}
