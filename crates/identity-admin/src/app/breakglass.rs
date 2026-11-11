//! Break-glass accounts and reviews written under their committed ALLOW, and the break-glass
//! screen's reads (OP-157 m.3 (h), INV-28, §12.3.8). The mark carries no authority; a review
//! grants nothing. Nothing is deleted (OP-73).

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::SUBJECT_PREFIX;
use access_kernel::json::b64url_encode;
use access_store::audit::AuditEvent;
use access_store::breakglass::{Review, ReviewState};
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::breakglass::{BreakglassMark, BreakglassReview};

/// Longest gap between two drills, ms (PD, 90 days, §12.3.8 (5)).
pub(crate) const DRILL_EVERY_MS: u64 = 90 * 86_400_000;

/// What must hold now: a mark names a live membership of a live organization, and a clear names
/// a marked one; a review names a recorded use not reviewed yet.
///
/// # Errors
/// [`AdminError::Conflict`]; [`AdminError`].
pub(crate) async fn current_mark(t: &mut TenantTx, m: &BreakglassMark) -> Result<(), AdminError> {
    let Some(org) = t.org_by_party(m.org).await? else {
        return Err(AdminError::Conflict);
    };
    if org.ended
        || !t
            .memberships(org.id)
            .await?
            .iter()
            .any(|x| x.subject == m.member)
    {
        return Err(AdminError::Conflict);
    }
    let marked = t
        .breakglass_accounts()
        .await?
        .iter()
        .any(|a| a.subject == m.member && a.org == m.org);
    if marked == m.on {
        return Err(AdminError::Conflict);
    }
    Ok(())
}

/// See [`current_mark`].
///
/// # Errors
/// [`AdminError::Conflict`]; [`AdminError`].
pub(crate) async fn current_review(
    t: &mut TenantTx,
    r: &BreakglassReview,
) -> Result<(), AdminError> {
    match t
        .breakglass_reviews()
        .await?
        .into_iter()
        .find(|u| u.used.exercise == r.exercise)
    {
        Some(u) if u.state != ReviewState::Reviewed => Ok(()),
        _ => Err(AdminError::Conflict),
    }
}

/// Writes the mark under `bound`; a new mark is audited as critical.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write_mark(
    t: &mut TenantTx,
    bound: &Bound,
    m: &BreakglassMark,
    ids: &IdKey,
) -> Result<bool, AdminError> {
    if !t
        .set_breakglass_mark(bound, &m.org, &m.member, m.on)
        .await?
    {
        return Ok(false);
    }
    if m.on {
        let target = ids.encode(SUBJECT_PREFIX, m.member)?;
        t.audit(&AuditEvent {
            event_type: "breakglass.account_marked",
            actor: "breakglass",
            target: &target,
            correlation: "-",
        })
        .await?;
    }
    Ok(true)
}

/// Records `reviewer`'s review under `bound` (OP-157 m.3 (h)): only another Party than the one
/// that used the Grant reviews it.
///
/// # Errors
/// [`AdminError::Conflict`] for the user's own review or a use already reviewed; [`AdminError`].
pub(crate) async fn write_review(
    t: &mut TenantTx,
    bound: &Bound,
    r: &BreakglassReview,
    reviewer: Option<[u8; 16]>,
) -> Result<(), AdminError> {
    let reviewer = reviewer.ok_or(AdminError::Conflict)?;
    match t
        .review_breakglass(bound, &r.exercise, r.classification.name(), &reviewer)
        .await?
    {
        Review::Done(_) => {
            let target = b64url_encode(&r.exercise);
            t.audit(&AuditEvent {
                event_type: "breakglass.reviewed",
                actor: "breakglass",
                target: &target,
                correlation: "-",
            })
            .await?;
            Ok(())
        }
        Review::Unknown | Review::Already | Review::OwnUse => Err(AdminError::Conflict),
    }
}

/// The break-glass accounts as the console reads them.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn accounts(
    t: &mut TenantTx,
    ids: &IdKey,
) -> Result<Vec<(Json, u64)>, AdminError> {
    let mut out = Vec::new();
    for a in t.breakglass_accounts().await? {
        let id = ids.encode(SUBJECT_PREFIX, a.subject)?;
        out.push((
            json!({
                "account_id": id,
                "member": b64url_encode(&a.subject),
                "organization": b64url_encode(&a.org),
                "organization_name": a.org_name,
                "marked_at": a.marked_at_ms,
                "position": a.position.to_string(),
            }),
            a.position,
        ));
    }
    Ok(out)
}

fn use_view(r: &access_store::breakglass::BreakglassReviewRow) -> Json {
    json!({
        "exercise": b64url_encode(&r.used.exercise),
        "drill": r.used.drill,
        "grant": b64url_encode(&r.used.grant),
        "actor": b64url_encode(&r.used.actor),
        "used_at": r.used.used_at_ms,
        "due_at": r.used.due_at_ms,
        "state": r.state.name(),
        "classification": r.classification,
        "reviewer": r.reviewer.map(|p| b64url_encode(&p)),
    })
}

/// Every use and its review, newest first.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn reviews(t: &mut TenantTx) -> Result<Vec<(Json, u64)>, AdminError> {
    Ok(t.breakglass_reviews()
        .await?
        .iter()
        .map(|r| (use_view(r), r.version))
        .collect())
}

/// The drills, newest first, with when the next is due: 90 days after the last drill, or after
/// the oldest mark when none ran (§12.3.8 (5)).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn drills(t: &mut TenantTx) -> Result<Vec<(Json, u64)>, AdminError> {
    let since = t
        .breakglass_accounts()
        .await?
        .iter()
        .map(|a| a.marked_at_ms)
        .min();
    let last = t.last_breakglass_drill().await?;
    let due = last.or(since).map(|t0| t0.saturating_add(DRILL_EVERY_MS));
    Ok(t.breakglass_reviews()
        .await?
        .iter()
        .filter(|r| r.used.drill)
        .map(|r| {
            let mut v = use_view(r);
            if let Some(o) = v.as_object_mut() {
                o.insert(String::from("next_due_at"), json!(due));
            }
            (v, r.version)
        })
        .collect())
}
