//! Committed offboardings (OP-157 m.3 (v), §8.17.9.6, E6): one row per departure, with the
//! choice made for every channel. Nothing is deleted (OP-73).

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

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn id32(b: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

/// An offboarding to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewOffboarding<'a> {
    /// The departed Party.
    pub party: [u8; 16],
    /// The account bound to it, when one is.
    pub subject: Option<[u8; 16]>,
    /// The choice for every channel, as JSON.
    pub choices: &'a str,
    /// Whether the person may come back on this account: `allowed` or `blocked`.
    pub reentry: &'a str,
    /// The departure's `ExerciseID`.
    pub departure: [u8; 32],
    /// Its position in the domain's log.
    pub departure_pos: u64,
    /// The key that signed the offboarding's envelope.
    pub actor: [u8; 32],
}

/// The newest offboarding of a Party.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffboardingRow {
    /// Its version.
    pub version: u64,
    /// The account bound to the Party, when one was.
    pub subject: Option<[u8; 16]>,
    /// The choice for every channel, as JSON.
    pub choices: String,
    /// `allowed` or `blocked`.
    pub reentry: String,
    /// The departure's `ExerciseID`.
    pub departure: [u8; 32],
    /// Its position.
    pub departure_pos: u64,
    /// When it was recorded, Unix ms.
    pub committed_ms: u64,
}

impl TenantTx {
    /// Records `o` as the next version of its Party's offboarding.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_offboarding(&mut self, o: &NewOffboarding<'_>) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.offboarding_previews (tenant_id, realm_id, party, version,
                    subject_id, choices, reentry, departure, departure_pos, actor)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9
               FROM access.offboarding_previews
              WHERE tenant_id = $1 AND realm_id = $2 AND party = $3",
            tenant,
            realm,
            o.party.as_slice(),
            o.subject.map(Uuid::from_bytes),
            o.choices,
            o.reentry,
            o.departure.as_slice(),
            signed(o.departure_pos)?,
            o.actor.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest offboarding of `party`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn offboarding(
        &mut self,
        party: [u8; 16],
    ) -> Result<Option<OffboardingRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            r#"SELECT version, subject_id, choices, reentry, departure, departure_pos,
                      (extract(epoch FROM committed_at) * 1000)::bigint AS "committed_ms!"
                 FROM access.offboarding_previews
                WHERE tenant_id = $1 AND realm_id = $2 AND party = $3
                ORDER BY version DESC LIMIT 1"#,
            tenant,
            realm,
            party.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(OffboardingRow {
                version: unsigned(r.version)?,
                subject: r.subject_id.map(|s| *s.as_bytes()),
                choices: r.choices,
                reentry: r.reentry,
                departure: id32(&r.departure)?,
                departure_pos: unsigned(r.departure_pos)?,
                committed_ms: unsigned(r.committed_ms)?,
            })
        })
        .transpose()
    }

    /// Whether the newest offboarding that names account `subject` blocked its re-entry
    /// (OP-157 m.3 (v)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn reentry_blocked(&mut self, subject: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query_scalar!(
            "SELECT reentry FROM access.offboarding_previews
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
              ORDER BY committed_at DESC, version DESC LIMIT 1",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.as_deref() == Some("blocked"))
    }
}
