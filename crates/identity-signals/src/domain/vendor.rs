//! Vendor answers mapped to signal bodies (OP-156 m.3 (r)): Microsoft Intune and Jamf Pro
//! device records to `posture_mdm`, Onfido checks and Persona inquiries to
//! `identity_proofing`. Each mapping reads only the fields named here; anything it cannot read
//! is no signal, never a favourable one. The source that relays the answer signs the Claim
//! under its own issuer key.

use access_internal_api::signals::{
    IdentityProofing, Method, PostureMdm, ProofingLevel, Signal, is_ref,
};
use serde_json::Value as Json;

use crate::domain::time::rfc3339_ms;

/// Why a vendor answer maps to no signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("vendor answer: {0}")]
pub struct VendorError(pub &'static str);

fn at<'a>(v: &'a Json, path: &[&str]) -> Option<&'a Json> {
    path.iter().try_fold(v, |v, k| v.get(*k))
}

fn provider(p: &str) -> Result<String, VendorError> {
    if is_ref(p) {
        Ok(String::from(p))
    } else {
        Err(VendorError("provider"))
    }
}

fn statement(parts: &[String]) -> String {
    let mut s = parts.join(", ");
    if s.is_empty() {
        s = String::from("No details");
    }
    s.chars().take(512).collect()
}

/// A Microsoft Graph `managedDevice`: managed when `managementState` is `managed`, compliant
/// only when `complianceState` is `compliant` (`inGracePeriod`, `unknown` and every other state
/// are not).
///
/// # Errors
/// [`VendorError`].
pub fn intune(device: &Json, provider_ref: &str) -> Result<Signal, VendorError> {
    let state = device
        .get("complianceState")
        .and_then(Json::as_str)
        .ok_or(VendorError("complianceState"))?;
    let management = device
        .get("managementState")
        .and_then(Json::as_str)
        .ok_or(VendorError("managementState"))?;
    let mut parts = vec![format!("Intune compliance state {state}")];
    if device.get("isEncrypted").and_then(Json::as_bool) == Some(true) {
        parts.push(String::from("disk encrypted"));
    }
    if let Some(os) = device.get("osVersion").and_then(Json::as_str) {
        parts.push(format!("OS {}", os.chars().take(32).collect::<String>()));
    }
    Ok(Signal::Posture(PostureMdm {
        managed: management == "managed",
        compliant: management == "managed" && state == "compliant",
        provider: provider(provider_ref)?,
        statement: statement(&parts),
    }))
}

/// A Jamf Pro computer inventory record: managed when
/// `general.remoteManagement.managed` is true; compliant only when it is managed, `FileVault`
/// reports the boot partition `ENCRYPTED` and System Integrity Protection is `ENABLED`.
///
/// # Errors
/// [`VendorError`].
pub fn jamf(computer: &Json, provider_ref: &str) -> Result<Signal, VendorError> {
    let managed = at(computer, &["general", "remoteManagement", "managed"])
        .and_then(Json::as_bool)
        .ok_or(VendorError("managed"))?;
    let encrypted = at(
        computer,
        &[
            "diskEncryption",
            "bootPartitionEncryptionDetails",
            "partitionFileVault2State",
        ],
    )
    .and_then(Json::as_str)
        == Some("ENCRYPTED");
    let sip = at(computer, &["security", "sipStatus"]).and_then(Json::as_str) == Some("ENABLED");
    let mut parts = Vec::new();
    parts.push(String::from(if encrypted {
        "FileVault on"
    } else {
        "FileVault off"
    }));
    parts.push(String::from(if sip {
        "SIP enabled"
    } else {
        "SIP disabled"
    }));
    if let Some(os) = at(computer, &["operatingSystem", "version"]).and_then(Json::as_str) {
        parts.push(format!("macOS {}", os.chars().take(32).collect::<String>()));
    }
    Ok(Signal::Posture(PostureMdm {
        managed,
        compliant: managed && encrypted && sip,
        provider: provider(provider_ref)?,
        statement: statement(&parts),
    }))
}

/// An Onfido check: only a `complete` check with result `clear` is a proofing. A document
/// report alone is IAL1; with a facial similarity report (the provider's own face match) it is
/// IAL2. Access matches no face itself (IDP-34).
///
/// # Errors
/// [`VendorError`]: also for a check that is not clear, which is no proofing.
pub fn onfido(check: &Json, provider_ref: &str) -> Result<Signal, VendorError> {
    if check.get("status").and_then(Json::as_str) != Some("complete") {
        return Err(VendorError("status"));
    }
    if check.get("result").and_then(Json::as_str) != Some("clear") {
        return Err(VendorError("result"));
    }
    let reports: Vec<&str> = check
        .get("report_names")
        .and_then(Json::as_array)
        .ok_or(VendorError("report_names"))?
        .iter()
        .filter_map(Json::as_str)
        .collect();
    let document = reports
        .iter()
        .any(|r| *r == "document" || *r == "document_with_nfc");
    if !document {
        return Err(VendorError("report_names"));
    }
    let face = reports.iter().any(|r| r.starts_with("facial_similarity"));
    let nfc = reports.contains(&"document_with_nfc");
    let verified_at = check
        .get("completed_at_iso8601")
        .or_else(|| check.get("created_at"))
        .and_then(Json::as_str)
        .and_then(rfc3339_ms)
        .ok_or(VendorError("created_at"))?;
    Ok(Signal::Proofing(IdentityProofing {
        provider: provider(provider_ref)?,
        method: if nfc {
            Method::DocumentNfc
        } else {
            Method::Document
        },
        level: ProofingLevel::Ial(if face { 2 } else { 1 }),
        verified_at,
    }))
}

/// A Persona inquiry: only an `approved` inquiry is a proofing. A passed government ID
/// verification is IAL1; with a passed selfie verification (the provider's own) it is IAL2.
///
/// # Errors
/// [`VendorError`]: also for an inquiry that is not approved.
pub fn persona(inquiry: &Json, provider_ref: &str) -> Result<Signal, VendorError> {
    let attributes = at(inquiry, &["data", "attributes"]).ok_or(VendorError("attributes"))?;
    if at(inquiry, &["data", "type"]).and_then(Json::as_str) != Some("inquiry")
        || attributes.get("status").and_then(Json::as_str) != Some("approved")
    {
        return Err(VendorError("status"));
    }
    let passed = |kind: &str| {
        inquiry
            .get("included")
            .and_then(Json::as_array)
            .is_some_and(|items| {
                items.iter().any(|i| {
                    i.get("type").and_then(Json::as_str) == Some(kind)
                        && at(i, &["attributes", "status"]).and_then(Json::as_str) == Some("passed")
                })
            })
    };
    if !passed("verification/government-id") {
        return Err(VendorError("government-id"));
    }
    let verified_at = attributes
        .get("completed-at")
        .and_then(Json::as_str)
        .and_then(rfc3339_ms)
        .ok_or(VendorError("completed-at"))?;
    Ok(Signal::Proofing(IdentityProofing {
        provider: provider(provider_ref)?,
        method: Method::Document,
        level: ProofingLevel::Ial(if passed("verification/selfie") { 2 } else { 1 }),
        verified_at,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    // OP-156 m.3 (r)
    #[test]
    fn device_records_map_to_posture() {
        let d = |compliance: &str| {
            json!({"id": "00000000-0000-0000-0000-000000000001", "deviceName": "laptop-1",
                   "managementState": "managed", "complianceState": compliance,
                   "isEncrypted": true, "osVersion": "10.0.22631"})
        };
        let Signal::Posture(p) = intune(&d("compliant"), "acme-mdm").unwrap() else {
            panic!();
        };
        assert!(p.managed && p.compliant);
        assert!(p.statement.contains("disk encrypted"), "{}", p.statement);
        for other in ["noncompliant", "inGracePeriod", "unknown", "error"] {
            let Signal::Posture(p) = intune(&d(other), "acme-mdm").unwrap() else {
                panic!();
            };
            assert!(!p.compliant, "{other}");
        }
        assert!(intune(&json!({"managementState": "managed"}), "acme-mdm").is_err());
        assert!(intune(&d("compliant"), "Acme MDM").is_err());

        let mac = |vault: &str, sip: &str| {
            json!({"general": {"name": "mac-1", "remoteManagement": {"managed": true}},
                   "diskEncryption": {"bootPartitionEncryptionDetails": {"partitionFileVault2State": vault}},
                   "security": {"sipStatus": sip},
                   "operatingSystem": {"version": "14.5"}})
        };
        let Signal::Posture(p) = jamf(&mac("ENCRYPTED", "ENABLED"), "jamf").unwrap() else {
            panic!();
        };
        assert!(p.compliant);
        let Signal::Posture(p) = jamf(&mac("NOT_ENCRYPTED", "ENABLED"), "jamf").unwrap() else {
            panic!();
        };
        assert!(p.managed && !p.compliant);
        assert!(jamf(&json!({"general": {}}), "jamf").is_err());
    }

    // IDP-34, OP-156 m.3 (r)
    #[test]
    fn verification_results_map_to_proofing_levels() {
        let check = |result: &str, reports: Json| {
            json!({"id": "chk-1", "status": "complete", "result": result,
                   "report_names": reports, "created_at": "2026-11-01T10:00:00Z"})
        };
        let Signal::Proofing(p) = onfido(
            &check("clear", json!(["document", "facial_similarity_photo"])),
            "onfido",
        )
        .unwrap() else {
            panic!();
        };
        assert_eq!(p.level, ProofingLevel::Ial(2));
        assert_eq!(p.verified_at, 1_793_527_200_000);
        let Signal::Proofing(p) =
            onfido(&check("clear", json!(["document_with_nfc"])), "onfido").unwrap()
        else {
            panic!();
        };
        assert_eq!(
            (p.level, p.method),
            (ProofingLevel::Ial(1), Method::DocumentNfc)
        );
        assert!(onfido(&check("consider", json!(["document"])), "onfido").is_err());
        assert!(
            onfido(
                &check("clear", json!(["facial_similarity_photo"])),
                "onfido"
            )
            .is_err()
        );

        let inquiry = |status: &str, selfie: &str| {
            json!({"data": {"type": "inquiry", "id": "inq_1",
                            "attributes": {"status": status, "completed-at": "2026-11-01T10:00:00.000Z"}},
                   "included": [
                       {"type": "verification/government-id", "attributes": {"status": "passed"}},
                       {"type": "verification/selfie", "attributes": {"status": selfie}}]})
        };
        let Signal::Proofing(p) = persona(&inquiry("approved", "passed"), "persona").unwrap()
        else {
            panic!();
        };
        assert_eq!(p.level, ProofingLevel::Ial(2));
        let Signal::Proofing(p) = persona(&inquiry("approved", "failed"), "persona").unwrap()
        else {
            panic!();
        };
        assert_eq!(p.level, ProofingLevel::Ial(1));
        assert!(persona(&inquiry("declined", "passed"), "persona").is_err());
        assert!(persona(&inquiry("completed", "passed"), "persona").is_err());
    }
}
