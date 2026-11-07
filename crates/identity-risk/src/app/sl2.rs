//! SL2 at sign-in (§12.2.4, TN-46, IDP-39): reads the sign-in's sources, assesses, and queues the
//! effects in the business transaction: the `risk.level` and `risk_signal` Claims, a review item,
//! CAEP `risk-level-change` (OP-151 m.7 (h) port) and log lines. The step-up request goes back to
//! the sign-in flow, which adds it to its SL1 requirements; nothing here allows or locks.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use access_identity_account::app::claims::emit;
use access_identity_account::app::signal::{OutboxRiskLevels, RiskLevels};
use access_store::audit::AuditEvent;
use access_store::risk::{NewReview, RiskSubjectRow};

use crate::RiskError;
use crate::adapters::{NoBreachSource, NoGeoSource, NoPseudonyms};
use crate::app::address::prefix;
use crate::app::settings::mode;
use crate::domain::assess::{Assessment, Breach, Inputs, assess};
use crate::domain::claims;
use crate::domain::geo::{GeoAnswer, Place, Point};
use crate::domain::score::Level;
use crate::domain::signal::RiskSignal;
use crate::ports::{BreachProbe, GeoResolver, GeoStatus, IpPseudonyms, RiskTx};

/// The process-wide sources of SL2.
#[derive(Clone)]
pub struct Services {
    /// The GeoIP/ASN source.
    pub geo: Arc<dyn GeoResolver>,
    /// Address pseudonyms.
    pub ips: Arc<dyn IpPseudonyms>,
    /// The breach corpus at sign-in.
    pub breach: Arc<dyn BreachProbe>,
}

impl Services {
    /// No source configured: every geographic and breach input is unavailable, so the level is
    /// `unavailable` unless something else fires, and nothing is kept of addresses.
    #[must_use]
    pub fn without_sources() -> Self {
        Self {
            geo: Arc::new(NoGeoSource),
            ips: Arc::new(NoPseudonyms),
            breach: Arc::new(NoBreachSource),
        }
    }

    /// The `GeoIP` source's state for the management surface (`GeoIP source not configured`).
    #[must_use]
    pub fn geo_status(&self) -> GeoStatus {
        self.geo.status()
    }
}

/// SL2 for one request: the sources and the client's address.
#[derive(Clone, Copy)]
pub struct Sl2<'a> {
    /// The sources.
    pub services: &'a Services,
    /// The request's client address, when known.
    pub client: Option<IpAddr>,
}

/// The facts of one sign-in SL2 reads besides its sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignIn {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The realm.
    pub realm: [u8; 16],
    /// The account.
    pub subject: [u8; 16],
    /// Now.
    pub now_ms: u64,
    /// Whether the browser has a valid device marker; `None` when the realm has none.
    pub device_known: Option<bool>,
    /// Failed password attempts counted before this sign-in.
    pub prior_failures: Option<u32>,
    /// The breached-password check.
    pub breach: Breach,
}

fn last_place(r: &RiskSubjectRow) -> Place {
    Place {
        country: r.country.as_deref().and_then(crate::domain::geo::country),
        asn: r.asn,
        point: match (r.lat_cdeg, r.lon_cdeg) {
            (Some(la), Some(lo)) => Point::new(la, lo),
            _ => None,
        },
    }
}

fn reason(a: &Assessment) -> &'static str {
    if a.signals.contains(&RiskSignal::CanaryHit) {
        "canary_hit"
    } else if a.step_up {
        "step_up"
    } else if a.shadow_step_up {
        "shadow_step_up"
    } else {
        "high"
    }
}

fn observe(a: &Assessment) {
    access_telemetry::signals::RISK_ASSESSMENTS.incr([a.level.name(), a.mode.name()]);
    for s in &a.signals {
        access_telemetry::signals::RISK_SIGNALS.incr([s.name()]);
    }
    tracing::info!(
        event = "risk.assessed",
        level = a.level.name(),
        mode = a.mode.name(),
        step_up = a.step_up,
        shadow_step_up = a.shadow_step_up,
        signals = a.signals.len(),
        missing = a.missing.len(),
        "sign-in risk assessed (SL2)"
    );
    for p in &a.monitored {
        tracing::warn!(
            event = "risk.protection.monitored",
            protection = p.name(),
            "attack protection fired in monitor mode; logged only (TN-108)"
        );
    }
}

/// Assesses a sign-in whose first step just passed and queues its effects in `tx`. A canary
/// account's match is in the result's signals; the caller ends that flow with the generic
/// failure. Storage failures are errors and fail the step closed (`503`), never an allow.
///
/// # Errors
/// [`RiskError`].
pub async fn evaluate<T: RiskTx + Send>(
    tx: &mut T,
    sl2: &Sl2<'_>,
    s: &SignIn,
) -> Result<Assessment, RiskError> {
    let canary = tx.store().is_canary(s.subject).await?;
    let realm_mode = mode(tx.store()).await?;
    let created = tx.store().realm_created_ms().await?;
    let stage = realm_mode.effective_sl2(created, s.now_ms);
    let last = tx.store().risk_subject(s.subject).await?;
    let inputs = Inputs {
        client_place: sl2.client.map(|ip| sl2.services.geo.locate(ip)),
        last_place: last.as_ref().map(last_place),
        last_at_ms: last.as_ref().map(|r| r.last_at_ms),
        now_ms: s.now_ms,
        device_known: s.device_known,
        prior_failures: s.prior_failures,
        breach: s.breach,
        canary,
    };
    let a = assess(&inputs, &realm_mode, stage);
    emit(tx, &claims::level(s.subject, a.level, s.now_ms)).await?;
    for signal in a.signals.iter().filter(|x| **x != RiskSignal::NewDevice) {
        emit(tx, &claims::signal(s.subject, *signal, s.now_ms)).await?;
    }
    if a.review {
        let signals: Vec<String> = a.signals.iter().map(|x| x.name().to_owned()).collect();
        tx.store()
            .insert_review(&NewReview {
                subject: s.subject,
                level: a.level.name(),
                signals: &signals,
                mode: a.mode.name(),
                reason: reason(&a),
            })
            .await?;
        tracing::warn!(
            event = "risk.review.opened",
            level = a.level.name(),
            reason = reason(&a),
            "risk review item opened for a person (TN-46)"
        );
    }
    if canary {
        tx.store()
            .audit(&AuditEvent {
                event_type: "risk.canary_hit",
                actor: "anonymous",
                target: "canary",
                correlation: "sl2",
            })
            .await?;
        tracing::warn!(
            event = "risk.canary.hit",
            "a canary credential matched; the sign-in ends without a session (§4.4)"
        );
    }
    if a.caep
        && let Some(current) = a.level.caep()
    {
        let previous = last
            .as_ref()
            .and_then(|r| r.level.as_deref())
            .and_then(Level::parse)
            .and_then(Level::caep);
        OutboxRiskLevels
            .changed(tx.store(), s.subject, current, previous, s.now_ms)
            .await?;
    }
    observe(&a);
    Ok(a)
}

/// Records the completed sign-in as SL2's "last sign-in" of the account: when, the address's
/// pseudonym and prefix, its coarse place and the level it was assessed at. Called only when a
/// session is created, so a failed step-up never moves the last place.
///
/// # Errors
/// [`RiskError`].
pub async fn record_sign_in<T: RiskTx + Send>(
    tx: &mut T,
    sl2: &Sl2<'_>,
    s: &SignIn,
    level: Option<Level>,
) -> Result<(), RiskError> {
    let place = match sl2.client.map(|ip| sl2.services.geo.locate(ip)) {
        Some(GeoAnswer::Found(p)) => p,
        Some(GeoAnswer::Unavailable) | None => Place::default(),
    };
    let row = RiskSubjectRow {
        last_at_ms: s.now_ms.max(1),
        ip_pseudonym: sl2
            .client
            .and_then(|ip| sl2.services.ips.pseudonym(&s.tenant, &s.realm, ip)),
        ip_prefix: sl2.client.map(prefix),
        country: place.country_code(),
        asn: place.asn,
        lat_cdeg: place.point.map(|p| p.lat_cdeg),
        lon_cdeg: place.point.map(|p| p.lon_cdeg),
        level: level
            .filter(|l| *l != Level::Unavailable)
            .map(|l| l.name().to_owned()),
    };
    tx.store().put_risk_subject(s.subject, &row).await?;
    Ok(())
}

/// The fired signal names of an assessment.
#[must_use]
pub fn names(signals: &BTreeSet<RiskSignal>) -> Vec<String> {
    signals.iter().map(|s| s.name().to_owned()).collect()
}
