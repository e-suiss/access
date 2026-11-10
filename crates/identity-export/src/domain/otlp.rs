//! OTLP/HTTP log records of the copy (OTLP 1.x JSON encoding, OP-156 m.3 (s)): one log record per
//! audit event, its body the OCSF event, under the `access.audit` scope. This pipeline is the
//! audit copy, never the telemetry export (OP-44: the two do not share a pipeline).

use access_identity_audit::domain::record::AuditRecord;
use access_identity_audit::domain::taxonomy::{Outcome, TaxonomyError, entry};
use serde_json::{Value, json};

use super::copy;

/// The instrumentation scope of the copy.
pub const SCOPE: &str = "access.audit";

const fn severity(o: Outcome) -> (u8, &'static str) {
    match o {
        Outcome::Failure => (13, "WARN"),
        Outcome::Success | Outcome::Unknown => (9, "INFO"),
    }
}

fn attr(key: &str, v: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": v } })
}

fn nanos(ms: u64) -> String {
    u128::from(ms).saturating_mul(1_000_000).to_string()
}

/// The `ExportLogsServiceRequest` of `records`.
///
/// # Errors
/// [`TaxonomyError`]; nothing is rendered.
pub fn body(records: &[AuditRecord]) -> Result<Vec<u8>, TaxonomyError> {
    let mut logs = Vec::with_capacity(records.len());
    for r in records {
        let e = entry(&r.event)?;
        let (number, text) = severity(e.outcome);
        let event = copy::ocsf(r)?;
        logs.push(json!({
            "timeUnixNano": nanos(r.occurred_at_ms),
            "observedTimeUnixNano": nanos(r.recorded_at_ms),
            "severityNumber": number,
            "severityText": text,
            "eventName": r.event,
            "body": { "stringValue": event.to_string() },
            "attributes": [
                attr("event.name", &r.event),
                attr("access.txn", &r.txn),
                attr("access.event_id", &r.id),
                attr(copy::HEADER, copy::VALUE),
            ],
        }));
    }
    let req = json!({
        "resourceLogs": [{
            "resource": { "attributes": [attr("service.name", "access")] },
            "scopeLogs": [{ "scope": { "name": SCOPE }, "logRecords": logs }],
        }],
    });
    Ok(req.to_string().into_bytes())
}
