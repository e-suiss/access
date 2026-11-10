//! One's cloud key permissions of a realm (OP-156 m.3 (w), E59): the content-free record of each
//! `one.cloud_key/grant` Exercise and the end of each one. No DEK, KEK or data is kept (OP-78).
//! Nothing is deleted (OP-73).

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

/// A permission to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCloudKey {
    /// The person.
    pub subject: [u8; 16],
    /// The person's Party in `domain`.
    pub party: [u8; 16],
    /// The governing domain.
    pub domain: [u8; 32],
    /// The allowed `one.cloud_key/grant` Exercise.
    pub exercise: [u8; 32],
    /// What the work is.
    pub purpose: String,
    /// The class names it may open.
    pub classes: Vec<String>,
    /// From, Unix ms.
    pub valid_from: i64,
    /// Until, Unix ms; at most 24 hours after `valid_from`.
    pub valid_until: i64,
    /// The digest of the TEE's measurement.
    pub tee_measurement: [u8; 32],
    /// The digest of the TEE's job key.
    pub job_key: [u8; 32],
    /// The Mandate it is bound to.
    pub mandate: [u8; 16],
}

/// A recorded permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudKey {
    /// Its id.
    pub id: [u8; 16],
    /// What was recorded.
    pub grant: NewCloudKey,
    /// How and when it ended, when it did by an end row.
    pub ended: Option<(String, i64)>,
}

fn bytes<const N: usize>(v: Vec<u8>) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

impl TenantTx {
    /// Records `p`; the id, or `None` when its Exercise was recorded already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_cloud_key(
        &mut self,
        p: &NewCloudKey,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.cloud_key_permissions
               (tenant_id, realm_id, subject_id, party, domain, exercise, purpose, classes,
                valid_from, valid_until, tee_measurement, job_key, mandate)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (tenant_id, realm_id, exercise) DO NOTHING
             RETURNING permission_id",
            tenant,
            realm,
            Uuid::from_bytes(p.subject),
            p.party.as_slice(),
            p.domain.as_slice(),
            p.exercise.as_slice(),
            p.purpose,
            &p.classes,
            p.valid_from,
            p.valid_until,
            p.tee_measurement.as_slice(),
            p.job_key.as_slice(),
            p.mandate.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(id.map(|u| *u.as_bytes()))
    }

    /// `subject`'s permissions whose window ends after `since`, newest first, at most `limit`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn cloud_keys(
        &mut self,
        subject: [u8; 16],
        since: i64,
        limit: i64,
    ) -> Result<Vec<CloudKey>, StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            r#"SELECT p.permission_id, p.subject_id, p.party, p.domain, p.exercise, p.purpose,
                      p.classes, p.valid_from, p.valid_until, p.tee_measurement, p.job_key,
                      p.mandate, e.how AS "how?", e.ended_at AS "ended_at?"
                 FROM access.cloud_key_permissions p
                 LEFT JOIN access.cloud_key_permission_ends e
                   ON e.tenant_id = p.tenant_id AND e.realm_id = p.realm_id
                  AND e.permission_id = p.permission_id
                WHERE p.tenant_id = $1 AND p.realm_id = $2 AND p.subject_id = $3
                  AND p.valid_until > $4
                ORDER BY p.permission_id DESC
                LIMIT $5"#,
            tenant,
            realm,
            Uuid::from_bytes(subject),
            since,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?
        .into_iter()
        .map(|r| {
            Ok(CloudKey {
                id: *r.permission_id.as_bytes(),
                grant: NewCloudKey {
                    subject: *r.subject_id.as_bytes(),
                    party: bytes(r.party)?,
                    domain: bytes(r.domain)?,
                    exercise: bytes(r.exercise)?,
                    purpose: r.purpose,
                    classes: r.classes,
                    valid_from: r.valid_from,
                    valid_until: r.valid_until,
                    tee_measurement: bytes(r.tee_measurement)?,
                    job_key: bytes(r.job_key)?,
                    mandate: bytes(r.mandate)?,
                },
                ended: r.how.zip(r.ended_at),
            })
        })
        .collect()
    }

    /// Ends `subject`'s permission `id` as revoked at `at`; `false` when it is not the
    /// subject's or ended already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_cloud_key(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
        exercise: Option<[u8; 32]>,
        at: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.cloud_key_permission_ends
               (tenant_id, realm_id, permission_id, how, exercise, ended_at)
             SELECT p.tenant_id, p.realm_id, p.permission_id, 'revoked', $5, $6
               FROM access.cloud_key_permissions p
              WHERE p.tenant_id = $1 AND p.realm_id = $2 AND p.permission_id = $3
                AND p.subject_id = $4
             ON CONFLICT (tenant_id, realm_id, permission_id) DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(id),
            Uuid::from_bytes(subject),
            exercise.as_ref().map(<[u8; 32]>::as_slice),
            at,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}
