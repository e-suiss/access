//! The realm's access review campaigns (OP-157 m.3 (w), IDP-39 (3)): each names a period and a
//! scope, written under its `idp.review.*` decision. A campaign is a view and never a queue; a
//! closed name is never reused and nothing is deleted (OP-73).

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

/// The newest version of one campaign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewScheduleRow {
    /// Its name.
    pub name: String,
    /// Whether it is live.
    pub live: bool,
    /// How often it runs, in days.
    pub period_days: u32,
    /// What it reviews.
    pub scope: String,
    /// Its version.
    pub version: u64,
    /// The position of the decision that wrote it.
    pub position: u64,
    /// When it was first scheduled, Unix ms: the start of its first period.
    pub first_ms: u64,
}

/// What a new version of a campaign says.
#[derive(Clone, Copy, Debug)]
pub struct NewReviewSchedule<'a> {
    /// Its name.
    pub name: &'a str,
    /// Whether it is live.
    pub live: bool,
    /// Its period, in days.
    pub period_days: u32,
    /// Its scope.
    pub scope: &'a str,
}

impl TenantTx {
    /// Writes the next version of campaign `r.name` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_review_schedule(
        &mut self,
        bound: &Bound,
        r: &NewReviewSchedule<'_>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let period = i32::try_from(r.period_days).map_err(|_| StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.review_schedules (tenant_id, realm_id, name, version, state,
                    period_days, scope, domain_id, decision_pos)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8
               FROM access.review_schedules
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
            tenant,
            realm,
            r.name,
            if r.live { "live" } else { "closed" },
            period,
            r.scope,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest version of every campaign, live and closed, by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn review_schedules(&mut self) -> Result<Vec<ReviewScheduleRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            r#"SELECT DISTINCT ON (s.name) s.name, s.state, s.period_days, s.scope, s.version,
                      s.decision_pos,
                      (SELECT (EXTRACT(EPOCH FROM f.created_at) * 1000)::bigint
                         FROM access.review_schedules f
                        WHERE f.tenant_id = s.tenant_id AND f.realm_id = s.realm_id
                          AND f.name = s.name AND f.version = 1) AS "first_ms!"
                 FROM access.review_schedules s
                WHERE s.tenant_id = $1 AND s.realm_id = $2
                ORDER BY s.name, s.version DESC"#,
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(ReviewScheduleRow {
                    name: r.name,
                    live: r.state == "live",
                    period_days: u32::try_from(r.period_days).map_err(|_| StoreError::Corrupt)?,
                    scope: r.scope,
                    version: unsigned(r.version)?,
                    position: unsigned(r.decision_pos)?,
                    first_ms: unsigned(r.first_ms)?,
                })
            })
            .collect()
    }
}
