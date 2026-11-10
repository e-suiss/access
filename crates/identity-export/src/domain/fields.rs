//! The OCSF field table of the copy (OP-41, OP-156 m.3 (s), Ek B 5313): which OCSF field each
//! Access record field lands in, per OCSF class, derived from the audit taxonomy by rendering
//! each event. The canonical schema is Access's; OCSF is a field alignment only, pinned to
//! [`OCSF_VERSION`].

use std::collections::{BTreeMap, BTreeSet};

use access_identity_audit::domain::record::{AuditRecord, Scope};
use access_identity_audit::domain::taxonomy::{Plane, TaxonomyError, taxonomy};
use serde_json::Value;

use super::copy;

/// The OCSF schema version the copy aligns with; the taxonomy must name the same (OP-41).
pub const OCSF_VERSION: &str = "1.3.0";

/// Where each Access record field lands in OCSF, the same for every class.
pub const RECORD_FIELDS: &[(&str, &str)] = &[
    ("id", "metadata.uid"),
    ("event", "metadata.event_code"),
    ("txn", "metadata.correlation_uid"),
    ("occurred_at", "time"),
    ("recorded_at", "metadata.logged_time"),
    ("checkpoint_at", "unmapped.checkpoint_at"),
    ("tenant", "unmapped.tenant"),
    ("scope", "unmapped.scope"),
    ("actor", "actor.user.uid"),
    ("reason", "status_detail"),
    ("class", "unmapped.access_class"),
    ("outcome", "status"),
];

fn flatten(prefix: &str, v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(o) => {
            for (k, c) in o {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&p, c, out);
            }
        }
        Value::Array(a) => {
            for c in a {
                flatten(&format!("{prefix}[]"), c, out);
            }
        }
        _ => {
            out.insert(String::from(prefix));
        }
    }
}

/// A record of `event` with every optional field set.
#[must_use]
pub fn sample(event: &str) -> AuditRecord {
    AuditRecord {
        id: String::from("identity:1"),
        event: String::from(event),
        txn: String::from("txn"),
        occurred_at_ms: 1,
        recorded_at_ms: 2,
        checkpoint_at_ms: Some(3),
        tenant: Some([1; 16]),
        scope: Scope::Realm([2; 16]),
        actor: String::from("actor"),
        target: String::from("target"),
        reason: Some(String::from("reason")),
    }
}

/// The OCSF field paths of the identity events' copies, per OCSF `class_uid`; arrays as `[]`.
///
/// # Errors
/// [`TaxonomyError`].
pub fn table() -> Result<BTreeMap<u32, BTreeSet<String>>, TaxonomyError> {
    let mut out: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for e in taxonomy()?
        .events
        .iter()
        .filter(|e| e.plane == Plane::Identity)
    {
        let v = copy::ocsf(&sample(&e.event))?;
        flatten("", &v, out.entry(e.ocsf_class).or_default());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-41, Ek B 5313
    #[test]
    fn the_ocsf_version_is_pinned_and_every_record_field_is_aligned() {
        assert_eq!(taxonomy().unwrap().ocsf_version, OCSF_VERSION);
        let t = table().unwrap();
        assert!(!t.is_empty());
        for (class, fields) in &t {
            for (_, ocsf) in RECORD_FIELDS {
                assert!(fields.contains(*ocsf), "{class} lacks {ocsf}");
            }
            assert!(fields.contains("unmapped.access_record"), "{class}");
        }
    }
}
