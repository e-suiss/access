//! "Copy — not the record" (X22, OP-41, §17.6.13): every exported event is labelled as a copy,
//! in each wire form, and the audit question is answered from the record. The OCSF event of a
//! copy is the taxonomy's static mapping with the label under `unmapped`.

use access_identity_audit::adapters::ocsf;
use access_identity_audit::domain::record::AuditRecord;
use access_identity_audit::domain::taxonomy::TaxonomyError;
use serde_json::Value;

/// The HTTP header every export request carries.
pub const HEADER: &str = "x-access-record";

/// Its value, and the label's value in every rendering.
pub const VALUE: &str = "copy";

/// The label's member under OCSF `unmapped`.
pub const UNMAPPED_MEMBER: &str = "access_record";

/// The OCSF event of `record`'s copy.
///
/// # Errors
/// [`TaxonomyError`] for an event outside the taxonomy; nothing is rendered.
pub fn ocsf(record: &AuditRecord) -> Result<Value, TaxonomyError> {
    let mut v = ocsf::render(record)?;
    if let Some(u) = v.get_mut("unmapped").and_then(Value::as_object_mut) {
        u.insert(UNMAPPED_MEMBER.into(), VALUE.into());
        u.insert("target".into(), record.target.as_str().into());
    }
    Ok(v)
}
