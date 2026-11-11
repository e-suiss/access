//! Access review campaigns (IDP-39 (3), LFP-18, OP-157 m.3 (w), m.6 (a), (f)): `idp.review.*`
//! changes written under their committed ALLOW, a campaign's items for its reviewer, and the
//! reviewer's keep.
//!
//! - A campaign names a period and a scope; it is a view, never a queue, and writes no
//!   authority. A closed name is never reused (OP-73).
//! - Its items are the live Grants in the reviewer's own lineage, read from the authority plane
//!   for the reader alone: a reviewer never sees another manager's team.
//! - "Keep" is the reviewer's signed write that records `review.kept` in the identity audit and
//!   writes no authority. "Remove" is the reviewer's own `grant.revoke` Exercise, one per item;
//!   there is no bulk removal (§8.17.9.8).

use access_identity_account::app::SUBJECT_PREFIX;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{Id, SubjectSelector};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::Bound;
use access_store::review::{NewReviewSchedule, ReviewScheduleRow};
use serde_json::{Value as Json, json};

use super::Admin;
use super::rest::{cbor_json, rfc3339};
use crate::AdminError;
use crate::domain::review::ReviewChange;
use crate::ports::{Decider, Governance, Instances, RealmKeys, TeamGrant};

const DAY_MS: u64 = 86_400_000;

/// What must hold now for `change`: a new name was never used; a closed campaign is live.
///
/// # Errors
/// [`AdminError::Conflict`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &ReviewChange) -> Result<(), AdminError> {
    let rows = t.review_schedules().await?;
    let ok = match change {
        ReviewChange::Schedule(s) => !rows.iter().any(|r| r.name == s.name),
        ReviewChange::Close(name) => rows.iter().any(|r| r.name == *name && r.live),
    };
    if ok {
        Ok(())
    } else {
        Err(AdminError::Conflict)
    }
}

/// Writes `change` under `bound`.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &ReviewChange,
) -> Result<bool, AdminError> {
    match change {
        ReviewChange::Schedule(s) => {
            t.put_review_schedule(
                bound,
                &NewReviewSchedule {
                    name: &s.name,
                    live: true,
                    period_days: s.period_days,
                    scope: &s.scope,
                },
            )
            .await?;
        }
        ReviewChange::Close(name) => {
            let row = t
                .review_schedules()
                .await?
                .into_iter()
                .find(|r| r.name == *name)
                .ok_or(AdminError::Conflict)?;
            t.put_review_schedule(
                bound,
                &NewReviewSchedule {
                    name: &row.name,
                    live: false,
                    period_days: row.period_days,
                    scope: &row.scope,
                },
            )
            .await?;
        }
    }
    Ok(true)
}

/// When the period running at `now` ends: the next run of a live campaign.
#[must_use]
pub fn next_run(first_ms: u64, period_days: u32, now: u64) -> u64 {
    let period = u64::from(period_days).saturating_mul(DAY_MS).max(1);
    let elapsed = now.saturating_sub(first_ms);
    first_ms.saturating_add(
        elapsed
            .checked_div(period)
            .unwrap_or(0)
            .saturating_add(1)
            .saturating_mul(period),
    )
}

fn schedule_view(r: &ReviewScheduleRow, now: u64) -> Json {
    json!({
        "name": r.name,
        "period_days": r.period_days,
        "scope": r.scope,
        "status": if r.live { "live" } else { "closed" },
        "started_at": rfc3339(r.first_ms),
        "next_run": r.live.then(|| rfc3339(next_run(r.first_ms, r.period_days, now))),
        "version": r.version,
    })
}

/// The campaigns as administrators read them, each with its decision position.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
    now: u64,
) -> Result<Vec<(Json, u64)>, AdminError> {
    Ok(t.review_schedules()
        .await?
        .iter()
        .filter(|r| key.is_none_or(|k| k == r.name))
        .map(|r| (schedule_view(r, now), r.position))
        .collect())
}

fn holder_view(h: &SubjectSelector) -> Json {
    match h {
        SubjectSelector::Party(p) => json!({ "party": b64url_encode(&p.0) }),
        SubjectSelector::Pred(c) => {
            json!({ "group": c.iter().map(|c| c.claim_class.clone()).collect::<Vec<_>>() })
        }
        SubjectSelector::Public => json!({ "public": true }),
        SubjectSelector::Foreign { .. } => json!({ "foreign": true }),
    }
}

fn basis_view(b: &ExerciseBasis) -> Json {
    match b {
        ExerciseBasis::Anchor(a) => json!({ "anchor": b64url_encode(&a.0) }),
        ExerciseBasis::Public(g) => json!({ "public": b64url_encode(&g.0) }),
        ExerciseBasis::Holding(h) => json!({ "holding": {
            "grant": b64url_encode(&h.grant.0),
            "holder": b64url_encode(&h.holder.0),
            "since": h.since,
        } }),
    }
}

/// One campaign item as its reviewer reads it.
#[must_use]
pub fn item_view(review: &str, g: &TeamGrant) -> Json {
    json!({
        "review": review,
        "grant": b64url_encode(&g.grant.0),
        "holder": holder_view(&g.holder),
        "actions": g.actions.iter().map(|a| json!({
            "namespace": a.namespace,
            "name": a.name,
            "major": a.major,
        })).collect::<Vec<_>>(),
        "resource": cbor_json(&g.resource.to_value()),
        "valid_until": (g.validity.until != u64::MAX).then(|| rfc3339(g.validity.until)),
        "since": g.since.to_string(),
        "issued_by": g.issued_by.map(|p| b64url_encode(&p.0)),
        "delegable": g.delegable,
        "derived": g.derived,
        "remove": { "operation": "revokeGrant", "basis": basis_view(&g.via) },
    })
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    async fn domain_of(t: &mut TenantTx) -> Result<Digest, AdminError> {
        let g = access_store::idp::governance(t)
            .await?
            .ok_or(AdminError::NoRealm)?;
        Ok(Digest(*g.domain.as_bytes()))
    }

    /// The live campaign `name`, when there is one.
    async fn live_review(t: &mut TenantTx, name: &str) -> Result<bool, AdminError> {
        Ok(t.review_schedules()
            .await?
            .iter()
            .any(|r| r.name == name && r.live))
    }

    /// The items of campaign `review` for the reviewer `reviewer`: the live Grants in its own
    /// lineage (IDP-39 (3)); none when the campaign is not live.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn review_items(
        &self,
        t: &mut TenantTx,
        review: &str,
        reviewer: Id,
    ) -> Result<Vec<TeamGrant>, AdminError> {
        if !Self::live_review(t, review).await? {
            return Ok(Vec::new());
        }
        let domain = Self::domain_of(t).await?;
        self.governance
            .review_items(domain, reviewer)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))
    }

    /// The items read `key` names, `review:account`: campaign `review` for the account whose
    /// read token reads it, as that account's Party may see them; `None` for an account bound to
    /// no Party.
    ///
    /// # Errors
    /// [`AdminError`].
    pub(crate) async fn review_items_view(
        &self,
        t: &mut TenantTx,
        key: &str,
    ) -> Result<Option<Vec<(Json, u64)>>, AdminError> {
        let Some((review, account)) = key.split_once(':') else {
            return Ok(None);
        };
        let Ok(subject) = self.ids.decode(SUBJECT_PREFIX, account) else {
            return Ok(None);
        };
        let Some(party) = access_store::idp::subject_party(t, &subject).await? else {
            return Ok(None);
        };
        let items = self.review_items(t, review, Id(party)).await?;
        Ok(Some(
            items
                .iter()
                .map(|g| (item_view(review, g), g.since))
                .collect(),
        ))
    }

    /// Records the reviewer's keep of `grant` in campaign `review`, signed by the Instance key
    /// `kid` (OP-157 m.3 (w), m.6 (a)): only a Grant in the signer's own lineage, as a
    /// `review.kept` identity audit record; it writes no authority. `false` when the campaign is
    /// not live, the key is not live, or the Grant is not one of the signer's items.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn keep_review(
        &self,
        place: (TenantId, RealmId),
        review: &str,
        grant: &str,
        kid: [u8; 32],
    ) -> Result<bool, AdminError> {
        let Some(grant) = b64url_decode(grant)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        else {
            return Ok(false);
        };
        let mut t = TenantTx::begin(self.app, place.0, place.1).await?;
        let domain = Self::domain_of(&mut t).await?;
        let Some(reviewer) = self
            .governance
            .key_party(domain, kid)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?
        else {
            t.rollback().await?;
            return Ok(false);
        };
        let items = self.review_items(&mut t, review, reviewer).await?;
        if !items.iter().any(|g| g.grant.0 == grant) {
            t.rollback().await?;
            return Ok(false);
        }
        // OP-157 m.3 (aa), LFP-18
        t.audit(&access_store::audit::AuditEvent {
            event_type: "review.kept",
            actor: &b64url_encode(&reviewer.0),
            target: &b64url_encode(&grant),
            correlation: review,
        })
        .await?;
        t.commit().await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    // OP-157 m.3 (w), m.6 (f)
    #[test]
    fn a_campaign_runs_once_per_period_from_its_start() {
        let start = 1_000;
        assert_eq!(next_run(start, 7, start), start + 7 * DAY_MS);
        assert_eq!(
            next_run(start, 7, start + 7 * DAY_MS - 1),
            start + 7 * DAY_MS
        );
        assert_eq!(next_run(start, 7, start + 7 * DAY_MS), start + 14 * DAY_MS);
    }
}
