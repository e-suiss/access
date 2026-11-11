//! Break-glass uses and their reviews (OP-157 m.3 (h), §12.3.8 (4), (5), TN-93): one row version
//! per state of a use, pending, overdue or reviewed. A review grants nothing. Nothing is deleted
//! (OP-73).

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

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn fixed<const N: usize>(b: &[u8]) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

/// Where a use stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewState {
    /// Not reviewed yet, within its window.
    Pending,
    /// Not reviewed within its window.
    Overdue,
    /// Reviewed by another Party.
    Reviewed,
}

impl ReviewState {
    /// Its stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Overdue => "overdue",
            Self::Reviewed => "reviewed",
        }
    }

    fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "pending" => Ok(Self::Pending),
            "overdue" => Ok(Self::Overdue),
            "reviewed" => Ok(Self::Reviewed),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// One use of a break-glass Grant, as its authority event names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakglassUse {
    /// The Exercise.
    pub exercise: [u8; 32],
    /// Whether it was a drill.
    pub drill: bool,
    /// The Grant used.
    pub grant: [u8; 16],
    /// The acting Party.
    pub actor: [u8; 16],
    /// The Party whose resource it acted on, when one.
    pub subject: Option<[u8; 16]>,
    /// When it committed, Unix ms.
    pub used_at_ms: u64,
    /// When its review is due, Unix ms.
    pub due_at_ms: u64,
}

/// The newest version of one use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakglassReviewRow {
    /// The use.
    pub used: BreakglassUse,
    /// Where it stands.
    pub state: ReviewState,
    /// Its classification once reviewed: `drill`, `emergency` or `misuse`.
    pub classification: Option<String>,
    /// The reviewing Party.
    pub reviewer: Option<[u8; 16]>,
    /// The position of the review's decision.
    pub position: Option<u64>,
    /// Its version.
    pub version: u64,
}

/// What a review did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Review {
    /// Recorded.
    Done(BreakglassReviewRow),
    /// No such use.
    Unknown,
    /// Already reviewed.
    Already,
    /// The reviewer is the Party that used it.
    OwnUse,
}

impl TenantTx {
    /// Records `u` as pending; `false` when it is already recorded.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_breakglass_use(&mut self, u: &BreakglassUse) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "INSERT INTO access.breakglass_reviews (tenant_id, realm_id, exercise, version, state,
                    drill, grant_id, actor, subject, used_at_ms, due_at_ms)
             VALUES ($1, $2, $3, 1, 'pending', $4, $5, $6, $7, $8, $9)
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            u.exercise.as_slice(),
            u.drill,
            u.grant.as_slice(),
            u.actor.as_slice(),
            u.subject.as_ref().map(<[u8; 16]>::as_slice),
            signed(u.used_at_ms)?,
            signed(u.due_at_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The newest version of every use, newest use first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn breakglass_reviews(&mut self) -> Result<Vec<BreakglassReviewRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT * FROM (
                SELECT DISTINCT ON (exercise) exercise, version, state, drill, grant_id, actor,
                       subject, used_at_ms, due_at_ms, classification, reviewer, decision_pos
                  FROM access.breakglass_reviews
                 WHERE tenant_id = $1 AND realm_id = $2
                 ORDER BY exercise, version DESC) latest
              ORDER BY used_at_ms DESC, exercise",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(BreakglassReviewRow {
                    used: BreakglassUse {
                        exercise: fixed(&r.exercise)?,
                        drill: r.drill,
                        grant: fixed(&r.grant_id)?,
                        actor: fixed(&r.actor)?,
                        subject: r.subject.as_deref().map(fixed).transpose()?,
                        used_at_ms: unsigned(r.used_at_ms)?,
                        due_at_ms: unsigned(r.due_at_ms)?,
                    },
                    state: ReviewState::parse(&r.state)?,
                    classification: r.classification,
                    reviewer: r.reviewer.as_deref().map(fixed).transpose()?,
                    position: r.decision_pos.map(unsigned).transpose()?,
                    version: unsigned(r.version)?,
                })
            })
            .collect()
    }

    /// Marks every pending use due before `now_ms` overdue and returns them.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn mark_breakglass_overdue(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<BreakglassUse>, StoreError> {
        let due: Vec<BreakglassReviewRow> = self
            .breakglass_reviews()
            .await?
            .into_iter()
            .filter(|r| r.state == ReviewState::Pending && r.used.due_at_ms < now_ms)
            .collect();
        let (tenant, realm) = scope(self)?;
        let mut out = Vec::with_capacity(due.len());
        for r in due {
            sqlx::query!(
                "INSERT INTO access.breakglass_reviews (tenant_id, realm_id, exercise, version,
                        state, drill, grant_id, actor, subject, used_at_ms, due_at_ms)
                 VALUES ($1, $2, $3, $4, 'overdue', $5, $6, $7, $8, $9, $10)",
                tenant,
                realm,
                r.used.exercise.as_slice(),
                signed(r.version.saturating_add(1))?,
                r.used.drill,
                r.used.grant.as_slice(),
                r.used.actor.as_slice(),
                r.used.subject.as_ref().map(<[u8; 16]>::as_slice),
                signed(r.used.used_at_ms)?,
                signed(r.used.due_at_ms)?,
            )
            .execute(&mut *self.tx)
            .await?;
            out.push(r.used);
        }
        Ok(out)
    }

    /// Records `reviewer`'s review of the use `exercise` as `classification` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn review_breakglass(
        &mut self,
        bound: &Bound,
        exercise: &[u8; 32],
        classification: &str,
        reviewer: &[u8; 16],
    ) -> Result<Review, StoreError> {
        let Some(r) = self
            .breakglass_reviews()
            .await?
            .into_iter()
            .find(|r| r.used.exercise == *exercise)
        else {
            return Ok(Review::Unknown);
        };
        if r.state == ReviewState::Reviewed {
            return Ok(Review::Already);
        }
        if r.used.actor == *reviewer {
            return Ok(Review::OwnUse);
        }
        let (tenant, realm) = scope(self)?;
        let version = r.version.saturating_add(1);
        sqlx::query!(
            "INSERT INTO access.breakglass_reviews (tenant_id, realm_id, exercise, version, state,
                    drill, grant_id, actor, subject, used_at_ms, due_at_ms, classification,
                    reviewer, domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, 'reviewed', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            tenant,
            realm,
            exercise.as_slice(),
            signed(version)?,
            r.used.drill,
            r.used.grant.as_slice(),
            r.used.actor.as_slice(),
            r.used.subject.as_ref().map(<[u8; 16]>::as_slice),
            signed(r.used.used_at_ms)?,
            signed(r.used.due_at_ms)?,
            classification,
            reviewer.as_slice(),
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(Review::Done(BreakglassReviewRow {
            state: ReviewState::Reviewed,
            classification: Some(classification.to_owned()),
            reviewer: Some(*reviewer),
            position: Some(bound.position()),
            version,
            used: r.used,
        }))
    }

    /// When the realm's last drill committed, Unix ms.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn last_breakglass_drill(&mut self) -> Result<Option<u64>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let at = sqlx::query_scalar!(
            "SELECT MAX(used_at_ms) FROM access.breakglass_reviews
              WHERE tenant_id = $1 AND realm_id = $2 AND drill",
            tenant,
            realm,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        at.map(unsigned).transpose()
    }
}
