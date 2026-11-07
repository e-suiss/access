//! Common Event Format (CEF) rendering of an audit record (OP-41, CMP-27): one line for
//! syslog collectors, with header and extension values escaped as CEF requires.

use crate::domain::record::{AuditRecord, Scope, uuid_text};
use crate::domain::taxonomy::{Outcome, TaxonomyError, entry, taxonomy};

const fn severity(o: Outcome) -> u8 {
    match o {
        Outcome::Failure => 6,
        Outcome::Success | Outcome::Unknown => 3,
    }
}

/// A header field: backslash and pipe escaped, line breaks as spaces.
fn header(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\r' | '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// An extension value: backslash and equals sign escaped, line breaks as `\n` / `\r`.
fn value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

/// The CEF line of `record`.
///
/// # Errors
/// [`TaxonomyError::Unknown`] for an event outside the taxonomy; nothing is rendered.
pub fn render(record: &AuditRecord) -> Result<String, TaxonomyError> {
    let e = entry(&record.event)?;
    let version = taxonomy()?.version;
    let mut ext: Vec<(&str, String)> = vec![
        ("rt", record.recorded_at_ms.to_string()),
        ("end", record.occurred_at_ms.to_string()),
        ("externalId", record.txn.clone()),
        ("suser", record.actor.clone()),
        ("duser", record.target.clone()),
        ("outcome", e.outcome.word().to_owned()),
        ("cat", e.class.clone()),
        ("cn1Label", String::from("ocsfType")),
        (
            "cn1",
            e.ocsf_type()
                .ok_or(TaxonomyError::Source("OCSF type"))?
                .to_string(),
        ),
        ("cs1Label", String::from("eventId")),
        ("cs1", record.id.clone()),
    ];
    if let Some(c) = record.checkpoint_at_ms {
        ext.push(("cs2Label", String::from("checkpointAt")));
        ext.push(("cs2", c.to_string()));
    }
    if let Some(t) = &record.tenant {
        ext.push(("cs3Label", String::from("tenant")));
        ext.push(("cs3", uuid_text(t)));
    }
    if record.scope != Scope::None {
        ext.push(("cs4Label", String::from("scope")));
        ext.push(("cs4", record.scope.text()));
    }
    if let Some(r) = &record.reason {
        ext.push(("reason", r.clone()));
    }
    let extension: Vec<String> = ext
        .iter()
        .map(|(k, v)| format!("{k}={}", value(v)))
        .collect();
    Ok(format!(
        "CEF:0|{}|{}|{version}|{}|{}|{}|{}",
        header(super::ocsf::VENDOR),
        header(super::ocsf::PRODUCT),
        header(&record.event),
        header(&record.event),
        severity(e.outcome),
        extension.join(" "),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-41: CEF escaping keeps a value from forging a field or a header
    #[test]
    fn values_cannot_forge_fields() {
        assert_eq!(header("a|b\\c\nd"), "a\\|b\\\\c d");
        assert_eq!(value("x=1 y\\z\n"), "x\\=1 y\\\\z\\n");
    }
}
