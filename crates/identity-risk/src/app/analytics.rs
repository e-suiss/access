//! Tenant analytics (IDP-36, OP-151 m.3 (n)): the daily aggregation of one realm, the
//! failed-login surge alert, the realm-scoped read the console shows, and the FP ratio. Counters
//! only; nothing here is read by a decision path (TI-18).

use access_store::analytics::{AnalyticsDay, SurgeAlert};
use access_store::identity::TenantTx;

use crate::RiskError;
use crate::domain::analytics::{ppm, surge};

/// What one aggregation produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aggregated {
    /// The day's row.
    pub day: AnalyticsDay,
    /// The surge alert it raised, when it raised one now.
    pub surge: Option<SurgeAlert>,
}

/// Recomputes the transaction realm's row of `day` and records a failed-login surge.
///
/// # Errors
/// [`RiskError`]; a transaction without a realm is refused.
pub async fn aggregate(tx: &mut TenantTx, day: u32) -> Result<Aggregated, RiskError> {
    let (row, previous) = tx.aggregate_day(day).await?;
    let mut raised = None;
    if surge(previous, row.failed_logins) {
        let alert = SurgeAlert {
            day,
            observed: row.failed_logins,
            baseline: previous,
        };
        if tx.record_surge(&alert).await? {
            tracing::warn!(
                event = "login.failed_surge",
                observed = alert.observed,
                baseline = alert.baseline,
                "failed sign-ins surged (IDP-36)"
            );
            raised = Some(alert);
        }
    }
    Ok(Aggregated {
        day: row,
        surge: raised,
    })
}

/// A realm's analytics of days `from..=to`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The days that have a row, oldest first.
    pub days: Vec<AnalyticsDay>,
    /// Surge alerts, oldest first.
    pub surges: Vec<SurgeAlert>,
}

impl Report {
    /// Passkey adoption per day, parts per million of active accounts.
    #[must_use]
    pub fn passkey_adoption_ppm(&self) -> Vec<(u32, Option<u64>)> {
        self.days
            .iter()
            .map(|d| (d.day, ppm(d.accounts_with_passkey, d.accounts_active)))
            .collect()
    }

    /// The FP ratio over the report: false positives per step-up request, actual or shadowed
    /// (each opens a review item), in parts per million.
    #[must_use]
    pub fn fp_ratio_ppm(&self) -> Option<u64> {
        let (fp, reviews) = self.days.iter().fold((0_u64, 0_u64), |(f, r), d| {
            (
                f.saturating_add(d.risk_false_positives),
                r.saturating_add(d.risk_reviews),
            )
        });
        ppm(fp, reviews)
    }
}

/// The realm's analytics as its viewer reads them: the transaction is scoped to the viewer's
/// realm, and the rows of no other realm are visible to it (viewer-rechecked; RLS).
///
/// # Errors
/// [`RiskError`]; a transaction without a realm is refused.
pub async fn read(tx: &mut TenantTx, from: u32, to: u32) -> Result<Report, RiskError> {
    Ok(Report {
        days: tx.analytics_days(from, to).await?,
        surges: tx.surge_alerts(from, to).await?,
    })
}
