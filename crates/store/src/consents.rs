//! Claim release consents (OP-153 m.3 (z)): what a person shares with a third-party client, kept
//! per (person, client, claim set) and ended from "Connected apps". Scoped to the transaction's
//! realm by row-level security; a consent only ends (OP-73).

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

fn i64_of(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

/// A live consent with the client it is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRow {
    /// The client's internal id.
    pub client_uuid: [u8; 16],
    /// Its `client_id`.
    pub client_id: String,
    /// Its display name.
    pub display_name: String,
    /// The claims shared, sorted.
    pub claims: Vec<String>,
    /// When it was given.
    pub created_ms: i64,
}

impl TenantTx {
    /// The claims `subject` shares with `client`, sorted; `None` without a live consent.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn consent(
        &mut self,
        subject: [u8; 16],
        client: [u8; 16],
    ) -> Result<Option<Vec<String>>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT claims FROM access.identity_claim_consents
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND client_uuid = $4
                AND ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            Uuid::from_bytes(client),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// Records that `subject` shares `claims` (sorted, deduplicated) with `client`; a live
    /// consent it held before ends as replaced.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_consent(
        &mut self,
        subject: [u8; 16],
        client: [u8; 16],
        claims: &[String],
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let now = i64_of(now_ms)?;
        sqlx::query!(
            "UPDATE access.identity_claim_consents SET ended_ms = $5, end_reason = 'replaced'
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND client_uuid = $4
                AND ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            Uuid::from_bytes(client),
            now,
        )
        .execute(&mut *self.tx)
        .await?;
        let mut sorted = claims.to_vec();
        sorted.sort();
        sorted.dedup();
        sqlx::query!(
            "INSERT INTO access.identity_claim_consents (tenant_id, realm_id, subject_id,
                    client_uuid, claims, created_ms)
             VALUES ($1, $2, $3, $4, $5, $6)",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            Uuid::from_bytes(client),
            &sorted,
            now,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The live consents of `subject`, newest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn consents_of(&mut self, subject: [u8; 16]) -> Result<Vec<ConsentRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT k.client_uuid, c.client_id, c.display_name, k.claims, k.created_ms
               FROM access.identity_claim_consents k
               JOIN access.idp_clients c
                 ON c.tenant_id = k.tenant_id AND c.realm_id = k.realm_id
                AND c.client_uuid = k.client_uuid
              WHERE k.tenant_id = $1 AND k.realm_id = $2 AND k.subject_id = $3
                AND k.ended_ms IS NULL
              ORDER BY k.consent_id DESC",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ConsentRow {
                client_uuid: *r.client_uuid.as_bytes(),
                client_id: r.client_id,
                display_name: r.display_name,
                claims: r.claims,
                created_ms: r.created_ms,
            })
            .collect())
    }

    /// Ends `subject`'s live consent for the client `client_id`; false when there is none.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn stop_consent(
        &mut self,
        subject: [u8; 16],
        client_id: &str,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.identity_claim_consents k SET ended_ms = $5, end_reason = 'stopped'
               FROM access.idp_clients c
              WHERE k.tenant_id = $1 AND k.realm_id = $2 AND k.subject_id = $3
                AND c.tenant_id = k.tenant_id AND c.realm_id = k.realm_id
                AND c.client_uuid = k.client_uuid AND c.client_id = $4 AND k.ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            client_id,
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}
