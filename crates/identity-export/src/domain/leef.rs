//! LEEF 2.0 rendering of an audit record's copy (OP-41, OP-156 m.3 (s)): the header names the
//! vendor, product, taxonomy version and event, the delimiter is `^`, and no value can carry the
//! delimiter, a line break or `=` into a field of its own.

use access_identity_audit::adapters::ocsf::{PRODUCT, VENDOR};
use access_identity_audit::domain::record::{AuditRecord, Scope, uuid_text};
use access_identity_audit::domain::taxonomy::{Outcome, TaxonomyError, entry, taxonomy};

use super::copy;

/// The attribute delimiter.
pub const DELIMITER: char = '^';

const fn sev(o: Outcome) -> u8 {
    match o {
        Outcome::Failure => 6,
        Outcome::Success | Outcome::Unknown => 3,
    }
}

fn header(v: &str) -> String {
    v.chars()
        .map(|c| match c {
            '|' | '\r' | '\n' | DELIMITER => ' ',
            c => c,
        })
        .collect()
}

fn value(v: &str) -> String {
    v.chars()
        .map(|c| match c {
            DELIMITER | '\r' | '\n' | '\t' => ' ',
            '=' => ':',
            c => c,
        })
        .collect()
}

/// The LEEF line of `record`'s copy.
///
/// # Errors
/// [`TaxonomyError::Unknown`] for an event outside the taxonomy; nothing is rendered.
pub fn render(record: &AuditRecord) -> Result<String, TaxonomyError> {
    let e = entry(&record.event)?;
    let version = taxonomy()?.version;
    let mut attrs: Vec<(&str, String)> = vec![
        ("devTime", record.occurred_at_ms.to_string()),
        ("devTimeFormat", String::from("epochMillis")),
        ("cat", e.class.clone()),
        ("sev", sev(e.outcome).to_string()),
        ("usrName", record.actor.clone()),
        ("resource", record.target.clone()),
        ("outcome", String::from(e.outcome.word())),
        ("eventUid", record.id.clone()),
        ("txn", record.txn.clone()),
        ("recordedTime", record.recorded_at_ms.to_string()),
        (
            "ocsfType",
            e.ocsf_type()
                .ok_or(TaxonomyError::Source("OCSF type"))?
                .to_string(),
        ),
        ("accessRecord", String::from(copy::VALUE)),
    ];
    if let Some(c) = record.checkpoint_at_ms {
        attrs.push(("checkpointTime", c.to_string()));
    }
    if let Some(t) = &record.tenant {
        attrs.push(("tenant", uuid_text(t)));
    }
    if record.scope != Scope::None {
        attrs.push(("scope", record.scope.text()));
    }
    if let Some(r) = &record.reason {
        attrs.push(("reason", r.clone()));
    }
    let body: Vec<String> = attrs
        .iter()
        .map(|(k, v)| format!("{k}={}", value(v)))
        .collect();
    Ok(format!(
        "LEEF:2.0|{}|{}|{version}|{}|{DELIMITER}|{}",
        header(VENDOR),
        header(PRODUCT),
        header(&record.event),
        body.join(&DELIMITER.to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-41
    #[test]
    fn values_cannot_forge_attributes() {
        assert_eq!(value("a^b=c\nd"), "a b:c d");
        assert_eq!(header("x|y^z"), "x y z");
    }
}
