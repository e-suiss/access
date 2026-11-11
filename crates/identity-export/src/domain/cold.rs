//! The cold tier file of the identity audit log (OP-40, OP-41, OP-158 m.3 (w)): the OCSF
//! Parquet copy of each row, plus an `access` group with the row's own fields, so that the file
//! alone gives back the leaves its partition root was computed over.

use access_identity_audit::AuditError;
use access_identity_audit::domain::record::{AuditRecord, uuid_text};
use access_identity_audit::ports::ColdCodec;
use access_store::audit::AuditRow;
use parquet::file::reader::{FileReader as _, SerializedFileReader};
use parquet::record::{Field, Row};
use serde_json::{Value, json};

use super::copy;
use super::parquet::{MESSAGE, write};

/// The `access` group appended to the OCSF schema.
const ACCESS_GROUP: &str = "
  required group access {
    required binary tenant (STRING);
    required binary realm (STRING);
    required int64 at_ms;
    required int64 id;
    required int64 xid;
    required binary event_type (STRING);
    required binary actor (STRING);
    required binary target (STRING);
    required binary correlation (STRING);
  }
";

/// The cold tier's schema: [`MESSAGE`] with the `access` group.
#[must_use]
pub fn message() -> String {
    let body = MESSAGE.trim_end().strip_suffix('}').unwrap_or(MESSAGE);
    format!("{body}{ACCESS_GROUP}}}\n")
}

fn cold(e: impl std::fmt::Display) -> AuditError {
    AuditError::Cold(e.to_string())
}

fn value(row: &AuditRow) -> Result<Value, AuditError> {
    let mut v = copy::ocsf(&AuditRecord::identity(row, None)?).map_err(cold)?;
    let object = v
        .as_object_mut()
        .ok_or_else(|| AuditError::Cold(String::from("event shape")))?;
    object.insert(
        String::from("access"),
        json!({
            "tenant": uuid_text(&row.tenant),
            "realm": uuid_text(&row.realm),
            "at_ms": row.at_ms,
            "id": row.id,
            "xid": i64::try_from(row.xid).map_err(cold)?,
            "event_type": row.event_type,
            "actor": row.actor,
            "target": row.target,
            "correlation": row.correlation,
        }),
    );
    Ok(v)
}

fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || text.len() != 36 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (b, pair) in out.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        *b = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn group(row: &Row) -> Option<&Row> {
    row.get_column_iter().find_map(|(name, f)| match f {
        Field::Group(g) if name == "access" => Some(g),
        _ => None,
    })
}

fn text(g: &Row, key: &str) -> Option<String> {
    g.get_column_iter().find_map(|(name, f)| match f {
        Field::Str(s) if name == key => Some(s.clone()),
        _ => None,
    })
}

fn long(g: &Row, key: &str) -> Option<i64> {
    g.get_column_iter().find_map(|(name, f)| match f {
        Field::Long(n) if name == key => Some(*n),
        _ => None,
    })
}

fn row_of(row: &Row) -> Option<AuditRow> {
    let g = group(row)?;
    Some(AuditRow {
        tenant: uuid_bytes(&text(g, "tenant")?)?,
        realm: uuid_bytes(&text(g, "realm")?)?,
        at_ms: long(g, "at_ms")?,
        id: long(g, "id")?,
        xid: u64::try_from(long(g, "xid")?).ok()?,
        event_type: text(g, "event_type")?,
        actor: text(g, "actor")?,
        target: text(g, "target")?,
        correlation: text(g, "correlation")?,
    })
}

/// The cold tier codec.
#[derive(Clone, Copy, Debug, Default)]
pub struct ColdParquet;

impl ColdCodec for ColdParquet {
    fn encode(&self, rows: &[AuditRow]) -> Result<Vec<u8>, AuditError> {
        let values = rows.iter().map(value).collect::<Result<Vec<_>, _>>()?;
        write(&message(), &values).map_err(cold)
    }

    fn decode(&self, file: &[u8]) -> Result<Vec<AuditRow>, AuditError> {
        let reader = SerializedFileReader::new(bytes::Bytes::from(file.to_vec())).map_err(cold)?;
        let rows = reader.get_row_iter(None).map_err(cold)?;
        rows.map(|r| {
            r.map_err(cold)
                .and_then(|r| row_of(&r).ok_or_else(|| AuditError::Cold(String::from("row"))))
        })
        .collect()
    }
}

#[cfg(test)]
mod tests;
