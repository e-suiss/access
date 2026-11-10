//! The one mapping the three ingress paths share (OP-156 m.3 (r)): a CAEP event from an SSF
//! transmitter (Okta's among them), a call point's answer (TN-135) and a source's own signed
//! Claim all become the same signal bodies. Every mapped signal is a Claim of the registered
//! source's issuer; what it does is the domain's Acceptance and policy, never this mapping.

use access_internal_api::signals::{PostureMdm, RiskExternal, RiskLevel, Signal, is_ref};
use serde_json::Value as Json;

/// CAEP `device-compliance-change` (OpenID CAEP 1.0 §3.5).
pub const CAEP_DEVICE_COMPLIANCE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

/// CAEP `risk-level-change` (OpenID CAEP 1.0 §3.4).
pub const CAEP_RISK_LEVEL: &str =
    "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";

/// The reason class of a risk event that names none.
pub const UNSPECIFIED: &str = "unspecified";

fn reason(v: Option<&Json>) -> String {
    v.and_then(Json::as_str)
        .map(str::to_ascii_lowercase)
        .map(|s| {
            s.chars()
                .map(|c| if c == ' ' || c == '_' { '-' } else { c })
                .take(128)
                .collect::<String>()
        })
        .filter(|s| is_ref(s))
        .unwrap_or_else(|| String::from(UNSPECIFIED))
}

/// A CAEP risk level as Access reads it: `low`, `medium` and `high`; CAEP has no `critical`.
#[must_use]
pub fn caep_level(s: &str) -> Option<RiskLevel> {
    match s.to_ascii_lowercase().as_str() {
        "low" => Some(RiskLevel::Low),
        "medium" => Some(RiskLevel::Medium),
        "high" => Some(RiskLevel::High),
        _ => None,
    }
}

/// The signal of one CAEP event of type `uri` with members `body`, from the source whose
/// provider is `provider`; `None` for an event that states no signal.
///
/// - `device-compliance-change`: `posture_mdm`, compliant only for `current_status`
///   `compliant`; Okta's SSF transmitter sends these for devices it manages.
/// - `risk-level-change`: `risk_external` at `current_level`, its reason from
///   `risk_reason` (Okta) or `reason_admin`.
#[must_use]
pub fn caep(uri: &str, body: &Json, provider: &str) -> Option<Signal> {
    if !is_ref(provider) {
        return None;
    }
    match uri {
        CAEP_DEVICE_COMPLIANCE => {
            let status = body.get("current_status")?.as_str()?;
            let compliant = match status {
                "compliant" => true,
                "not-compliant" => false,
                _ => return None,
            };
            Some(Signal::Posture(PostureMdm {
                managed: true,
                compliant,
                provider: String::from(provider),
                statement: format!("Device {status} (CAEP)"),
            }))
        }
        CAEP_RISK_LEVEL => {
            let level = caep_level(body.get("current_level")?.as_str()?)?;
            let why = body
                .get("risk_reason")
                .or_else(|| body.get("reason_admin").and_then(|r| r.get("en")))
                .or_else(|| body.get("reason_admin"));
            Some(Signal::Risk(RiskExternal {
                level,
                reason_class: reason(why),
            }))
        }
        _ => None,
    }
}

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

    // OP-156 m.3 (r): recorded Okta SSF event bodies, scrubbed
    #[test]
    fn caep_events_map_to_the_same_signal_bodies() {
        let Some(Signal::Posture(p)) = caep(
            CAEP_DEVICE_COMPLIANCE,
            &json!({"previous_status": "compliant", "current_status": "not-compliant",
                    "event_timestamp": 1_700_000_000}),
            "okta",
        ) else {
            panic!();
        };
        assert!(!p.compliant);
        let Some(Signal::Risk(r)) = caep(
            CAEP_RISK_LEVEL,
            &json!({"current_level": "HIGH", "previous_level": "LOW",
                    "risk_reason": "Anomalous location"}),
            "okta",
        ) else {
            panic!();
        };
        assert_eq!(
            (r.level, r.reason_class.as_str()),
            (RiskLevel::High, "anomalous-location")
        );
        assert!(caep(CAEP_RISK_LEVEL, &json!({"current_level": "none"}), "okta").is_none());
        assert!(
            caep(
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
                &json!({}),
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
