//! The one mapping the three ingress paths share (OP-156 m.3 (r)): a CAEP event from an SSF
//! transmitter (Okta's among them), a call point's answer (TN-135) and a source's own signed
//! Claim all become the same signal bodies. Every mapped signal is a Claim of the registered
//! source's issuer; what it does is the domain's Acceptance and policy, never this mapping.

use access_internal_api::signals::{RiskExternal, RiskLevel, is_ref};
use serde_json::Value as Json;

pub use access_internal_api::signals::{
    CAEP_DEVICE_COMPLIANCE, CAEP_RISK_LEVEL, UNSPECIFIED, caep, caep_level,
};

/// A call point's `risk` member outside its schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("risk member outside its schema")]
pub struct RiskSchema;

/// The `risk` member a call point's answer may carry: `{"level", "reason_class"}`. An answer
/// without it states nothing; one that does not read is a schema violation.
///
/// # Errors
/// [`RiskSchema`].
pub fn hook_risk(
    answer: &serde_json::Map<String, Json>,
) -> Result<Option<RiskExternal>, RiskSchema> {
    let Some(r) = answer.get("risk") else {
        return Ok(None);
    };
    let o = r.as_object().ok_or(RiskSchema)?;
    if o.keys().any(|k| k != "level" && k != "reason_class") {
        return Err(RiskSchema);
    }
    let level = o
        .get("level")
        .and_then(Json::as_str)
        .and_then(RiskLevel::parse)
        .ok_or(RiskSchema)?;
    let reason_class = o
        .get("reason_class")
        .and_then(Json::as_str)
        .filter(|s| is_ref(s))
        .ok_or(RiskSchema)?;
    Ok(Some(RiskExternal {
        level,
        reason_class: String::from(reason_class),
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    fn kernel(v: &Json) -> access_kernel::json::Json {
        access_kernel::json::parse(v.to_string().as_bytes(), 4096).unwrap()
    }

    // OP-156 m.3 (r): recorded Okta SSF event bodies, scrubbed
    #[test]
    fn caep_events_map_to_the_same_signal_bodies() {
        use access_internal_api::signals::Signal;
        let Some(Signal::Posture(p)) = caep(
            CAEP_DEVICE_COMPLIANCE,
            &kernel(
                &json!({"previous_status": "compliant", "current_status": "not-compliant",
                    "event_timestamp": 1_700_000_000}),
            ),
            "okta",
        ) else {
            panic!();
        };
        assert!(!p.compliant);
        let Some(Signal::Risk(r)) = caep(
            CAEP_RISK_LEVEL,
            &kernel(&json!({"current_level": "HIGH", "previous_level": "LOW",
                    "risk_reason": "Anomalous location"})),
            "okta",
        ) else {
            panic!();
        };
        assert_eq!(
            (r.level, r.reason_class.as_str()),
            (RiskLevel::High, "anomalous-location")
        );
        assert!(
            caep(
                CAEP_RISK_LEVEL,
                &kernel(&json!({"current_level": "none"})),
                "okta"
            )
            .is_none()
        );
        assert!(
            caep(
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
                &kernel(&json!({})),
                "okta"
            )
            .is_none()
        );
    }

    // TN-135, CI-2
    #[test]
    fn a_call_point_answer_states_risk_in_one_schema() {
        let m = |v: Json| v.as_object().unwrap().clone();
        assert_eq!(hook_risk(&m(json!({"decision": "allow"}))), Ok(None));
        let r = hook_risk(&m(
            json!({"risk": {"level": "critical", "reason_class": "bot"}}),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(r.level, RiskLevel::Critical);
        assert!(hook_risk(&m(json!({"risk": {"level": "allow", "reason_class": "x"}}))).is_err());
        assert!(
            hook_risk(&m(
                json!({"risk": {"level": "low", "reason_class": "x", "grant": "all"}})
            ))
            .is_err()
        );
    }
}
