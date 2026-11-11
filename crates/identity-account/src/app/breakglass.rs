//! What the identity plane does when a break-glass Grant is used (OP-157 m.3 (h), §12.3.8,
//! TN-71): the use is recorded for its review, audited as critical, the person whose account it
//! acted on gets the notice, and the realm's on-call Parties get the alarm. Delivery is not
//! guaranteed (N-2); the authority decision never waits on it (INV-24).

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_store::audit::AuditEvent;
use access_store::breakglass::BreakglassUse;
use access_store::identity::TenantTx;

use crate::app::SUBJECT_PREFIX;
use crate::notify::NotifyError;
use crate::notify::message::{Body, BreakglassAlarm};
use crate::notify::notices::queue_body;
use crate::ports::{Clock, Entropy};
use suiss_crypto::envelope::Kek;

/// The console page a break-glass alarm opens, under the realm issuer.
pub const CONSOLE_PATH: &str = "/console/breakglass";

/// Hours within which another Party reviews a use, unless the realm's `breakglass_review_h`
/// says less (PD, OP-157 m.3 (h), (n)).
pub const REVIEW_WITHIN_H: u64 = 72;

/// One use as its authority event names it, with the account it acted on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Used<'a> {
    /// The Exercise.
    pub exercise: [u8; 32],
    /// The Grant used.
    pub grant: [u8; 16],
    /// The acting Party.
    pub actor: [u8; 16],
    /// The subject Party.
    pub party: [u8; 16],
    /// The subject's account, when the Party has one in this realm.
    pub subject: Option<[u8; 16]>,
    /// How many approvals the Grant asks for.
    pub approvals: u64,
    /// When the use committed, Unix ms.
    pub at_ms: u64,
    /// When its intent ends, Unix ms.
    pub until_ms: u64,
    /// Whether it is a drill.
    pub drill: bool,
    /// The acting organization's name, attacker-controlled text.
    pub organization: &'a str,
}

/// The incident reference a notice names: the first bytes of the Exercise, hex.
#[must_use]
pub fn incident(exercise: &[u8; 32]) -> String {
    exercise
        .iter()
        .take(4)
        .fold(String::with_capacity(8), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// What one delivery did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Delivered {
    /// Whether the use was new.
    pub recorded: bool,
    /// Whether the subject's notice was queued.
    pub noticed: bool,
    /// Alarms queued.
    pub alarms: u32,
}

/// Records, audits and announces `u` in `tx`: once per use (OP-157 m.3 (h)).
///
/// # Errors
/// [`NotifyError`]; the caller rolls back and reads the event again.
pub async fn deliver(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    entropy: &(dyn Entropy + Sync),
    clock: &(dyn Clock + Sync),
    u: &Used<'_>,
    issuer: &str,
) -> Result<Delivered, NotifyError> {
    let mut out = Delivered::default();
    let recorded = tx
        .record_breakglass_use(&BreakglassUse {
            exercise: u.exercise,
            drill: u.drill,
            grant: u.grant,
            actor: u.actor,
            subject: Some(u.party),
            used_at_ms: u.at_ms,
            due_at_ms: u
                .at_ms
                .saturating_add(REVIEW_WITHIN_H.saturating_mul(3_600_000)),
        })
        .await?;
    if !recorded {
        return Ok(out);
    }
    out.recorded = true;
    let account = match u.subject {
        Some(s) => ids
            .encode(SUBJECT_PREFIX, s)
            .map_err(|_| NotifyError::NoSubject)?,
        None => String::from("-"),
    };
    tx.audit(&AuditEvent {
        event_type: "breakglass.used",
        actor: "authority",
        target: &account,
        correlation: "-",
    })
    .await?;
    if let Some(s) = u.subject {
        let body = Body::BreakglassUsed {
            organization: u.organization.chars().take(200).collect(),
            incident: incident(&u.exercise),
            approvals: u32::try_from(u.approvals).unwrap_or(u32::MAX),
            at_ms: u.at_ms,
            until_ms: u.until_ms,
        };
        out.noticed = queue_body(tx, (kek, ids), entropy, clock, s, body)
            .await?
            .is_some();
    }
    let link = format!("{}{CONSOLE_PATH}", issuer.trim_end_matches('/'));
    for to in tx.breakglass_on_call().await? {
        let body = Body::BreakglassAlarm {
            alarm: BreakglassAlarm::Used,
            account: account.clone(),
            link: Secret::new(link.clone()),
            at_ms: u.at_ms,
        };
        if queue_body(tx, (kek, ids), entropy, clock, to, body)
            .await?
            .is_some()
        {
            out.alarms = out.alarms.saturating_add(1);
        }
    }
    Ok(out)
}

/// Marks the realm's unreviewed uses past their window overdue, audits each as critical and
/// alarms the on-call Parties (OP-157 m.3 (h), §12.3.8 (4)); how many fell overdue.
///
/// # Errors
/// [`NotifyError`].
pub async fn sweep(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    entropy: &(dyn Entropy + Sync),
    clock: &(dyn Clock + Sync),
    issuer: &str,
    now_ms: u64,
) -> Result<u32, NotifyError> {
    let overdue = tx.mark_breakglass_overdue(now_ms).await?;
    let link = format!("{}{CONSOLE_PATH}", issuer.trim_end_matches('/'));
    let on_call = if overdue.is_empty() {
        Vec::new()
    } else {
        tx.breakglass_on_call().await?
    };
    for u in &overdue {
        let target = incident(&u.exercise);
        tx.audit(&AuditEvent {
            event_type: "breakglass.review_overdue",
            actor: "breakglass-review",
            target: &target,
            correlation: "-",
        })
        .await?;
        for to in &on_call {
            let body = Body::BreakglassAlarm {
                alarm: BreakglassAlarm::ReviewOverdue,
                account: target.clone(),
                link: Secret::new(link.clone()),
                at_ms: now_ms,
            };
            queue_body(tx, (kek, ids), entropy, clock, *to, body).await?;
        }
    }
    Ok(u32::try_from(overdue.len()).unwrap_or(u32::MAX))
}

/// Longest gap between two drills, ms (PD, 90 days, §12.3.8 (5)).
pub const DRILL_EVERY_MS: u64 = 90 * 86_400_000;

/// When a realm with break-glass accounts ran no drill in [`DRILL_EVERY_MS`], counted from its
/// last drill or else its oldest mark: the critical audit row and the on-call alarm, once a run
/// of the daily job (OP-157 m.3 (h), §12.3.8 (5)); whether it was overdue.
///
/// # Errors
/// [`NotifyError`].
pub async fn drill_check(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    entropy: &(dyn Entropy + Sync),
    clock: &(dyn Clock + Sync),
    issuer: &str,
    now_ms: u64,
) -> Result<bool, NotifyError> {
    let Some(since) = tx
        .breakglass_accounts()
        .await?
        .iter()
        .map(|a| a.marked_at_ms)
        .min()
    else {
        return Ok(false);
    };
    let from = tx
        .last_breakglass_drill()
        .await?
        .unwrap_or(since)
        .max(since);
    if now_ms.saturating_sub(from) <= DRILL_EVERY_MS {
        return Ok(false);
    }
    tx.audit(&AuditEvent {
        event_type: "breakglass.drill_overdue",
        actor: "breakglass-drill",
        target: "-",
        correlation: "-",
    })
    .await?;
    let link = format!("{}{CONSOLE_PATH}", issuer.trim_end_matches('/'));
    for to in tx.breakglass_on_call().await? {
        let body = Body::BreakglassAlarm {
            alarm: BreakglassAlarm::DrillOverdue,
            account: String::from("-"),
            link: Secret::new(link.clone()),
            at_ms: now_ms,
        };
        queue_body(tx, (kek, ids), entropy, clock, to, body).await?;
    }
    Ok(true)
}
