//! OCSF 1.x JSON rendering of an audit record (OP-41, CMP-27, §17.6.8): the static mapping of
//! the taxonomy. Field names follow OCSF; what OCSF has no field for goes under `unmapped`.

use serde_json::{Map, Value, json};

use crate::domain::record::{AuditRecord, Scope, uuid_text};
use crate::domain::taxonomy::{Outcome, TaxonomyError, entry, taxonomy};

/// Product name in `metadata.product`.
pub const PRODUCT: &str = "Access";

/// Vendor name in `metadata.product`.
pub const VENDOR: &str = "Suiss";

const fn status_id(o: Outcome) -> u8 {
    match o {
        Outcome::Unknown => 0,
        Outcome::Success => 1,
        Outcome::Failure => 2,
    }
}

const fn severity_id(o: Outcome) -> u8 {
    match o {
        Outcome::Failure => 2,
        Outcome::Success | Outcome::Unknown => 1,
    }
}

/// The OCSF event of `record`.
///
/// # Errors
/// [`TaxonomyError::Unknown`] for an event outside the taxonomy; nothing is rendered.
pub fn render(record: &AuditRecord) -> Result<Value, TaxonomyError> {
    let e = entry(&record.event)?;
    let version = &taxonomy()?.ocsf_version;
    let mut out = Map::new();
    out.insert("class_uid".into(), e.ocsf_class.into());
    out.insert("category_uid".into(), e.ocsf_category().into());
    out.insert("activity_id".into(), e.ocsf_activity.into());
    out.insert(
        "type_uid".into(),
        e.ocsf_type()
            .ok_or(TaxonomyError::Source("OCSF type"))?
            .into(),
    );
    out.insert("severity_id".into(), severity_id(e.outcome).into());
    out.insert("status_id".into(), status_id(e.outcome).into());
    out.insert("status".into(), e.outcome.word().into());
    out.insert("time".into(), record.occurred_at_ms.into());
    out.insert(
        "metadata".into(),
        json!({
            "version": version,
            "product": {"name": PRODUCT, "vendor_name": VENDOR},
            "uid": record.id,
            "correlation_uid": record.txn,
            "logged_time": record.recorded_at_ms,
            "event_code": record.event,
        }),
    );
    out.insert("actor".into(), json!({"user": {"uid": record.actor}}));
    match e.ocsf_class {
        3001..=3006 => {
            out.insert("user".into(), json!({"uid": record.target}));
        }
        6001 => {
            out.insert("web_resources".into(), json!([{"uid": record.target}]));
        }
        _ => {
            out.insert("api".into(), json!({"operation": record.event}));
            out.insert("resources".into(), json!([{"uid": record.target}]));
        }
    }
    if let Some(r) = &record.reason {
        out.insert("status_detail".into(), r.as_str().into());
    }
    let mut unmapped = Map::new();
    if let Some(c) = record.checkpoint_at_ms {
        unmapped.insert("checkpoint_at".into(), c.into());
    }
    if let Some(t) = &record.tenant {
        unmapped.insert("tenant".into(), uuid_text(t).into());
    }
    if record.scope != Scope::None {
        unmapped.insert("scope".into(), record.scope.text().into());
    }
    unmapped.insert("access_class".into(), e.class.as_str().into());
    out.insert("unmapped".into(), Value::Object(unmapped));
    Ok(Value::Object(out))
}
