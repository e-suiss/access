//! OCSF Parquet files of the copy (OP-156 m.3 (s)): one row per audit event, columns named and
//! nested as OCSF names them (the alignment of OP-41, version `ocsf_version`), Snappy pages.
//! Written with the `parquet` crate's column writers; no Arrow.

use std::sync::Arc;

use access_identity_audit::domain::record::AuditRecord;
use parquet::basic::{Compression, Repetition, Type as Physical};
use parquet::data_type::{ByteArray, ByteArrayType, Int32Type, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use parquet::schema::types::Type;
use serde_json::Value;

use super::copy;

/// The media type of an object.
pub const MEDIA_TYPE: &str = "application/vnd.apache.parquet";

/// The schema: OCSF names; `resources` and `web_resources` are lists (OCSF arrays).
pub const MESSAGE: &str = "
message ocsf_event {
  required int32 class_uid;
  required int32 category_uid;
  required int32 activity_id;
  required int64 type_uid;
  required int32 severity_id;
  required int32 status_id;
  required binary status (STRING);
  optional binary status_detail (STRING);
  required int64 time (TIMESTAMP(MILLIS,true));
  required group metadata {
    required binary version (STRING);
    required binary uid (STRING);
    required binary correlation_uid (STRING);
    required int64 logged_time (TIMESTAMP(MILLIS,true));
    required binary event_code (STRING);
    required group product {
      required binary name (STRING);
      required binary vendor_name (STRING);
    }
  }
  required group actor {
    required group user {
      required binary uid (STRING);
    }
  }
  optional group user {
    required binary uid (STRING);
  }
  optional group api {
    required binary operation (STRING);
  }
  optional group resources (LIST) {
    repeated group list {
      required group element {
        required binary uid (STRING);
      }
    }
  }
  optional group web_resources (LIST) {
    repeated group list {
      required group element {
        required binary uid (STRING);
      }
    }
  }
  required group unmapped {
    required binary access_class (STRING);
    required binary access_record (STRING);
    required binary target (STRING);
    optional binary scope (STRING);
    optional binary tenant (STRING);
    optional int64 checkpoint_at;
  }
}
";

/// Why a file could not be written.
#[derive(Debug, thiserror::Error)]
pub enum ParquetError {
    /// The event is outside the taxonomy.
    #[error("taxonomy: {0}")]
    Taxonomy(#[from] access_identity_audit::domain::taxonomy::TaxonomyError),
    /// A required OCSF member is missing or has the wrong type.
    #[error("event shape: {0}")]
    Shape(String),
    /// The writer failed.
    #[error("parquet: {0}")]
    Write(#[from] parquet::errors::ParquetError),
}

/// The schema of [`MESSAGE`].
///
/// # Errors
/// [`ParquetError::Write`] when it does not parse.
pub fn schema() -> Result<Type, ParquetError> {
    Ok(parse_message_type(MESSAGE)?)
}

#[derive(Clone, Debug)]
struct Entry {
    value: Option<Value>,
    def: i16,
    rep: i16,
}

/// The repetition of each node on `path` below `root`.
fn repetitions(root: &Type, path: &[String]) -> Result<Vec<Repetition>, ParquetError> {
    let mut node = root;
    let mut out = Vec::with_capacity(path.len());
    for name in path {
        node = node
            .get_fields()
            .iter()
            .find(|f| f.name() == name)
            .map(AsRef::as_ref)
            .ok_or_else(|| ParquetError::Shape(name.clone()))?;
        out.push(node.get_basic_info().repetition());
    }
    Ok(out)
}

fn walk(
    v: Option<&Value>,
    nodes: &[(&str, Repetition)],
    (def, rep, depth): (i16, i16, i16),
    out: &mut Vec<Entry>,
) -> Result<(), ParquetError> {
    let Some(((name, repetition), rest)) = nodes.split_first() else {
        out.push(Entry {
            value: v.cloned(),
            def,
            rep,
        });
        return Ok(());
    };
    let Some(v) = v else {
        out.push(Entry {
            value: None,
            def,
            rep,
        });
        return Ok(());
    };
    match repetition {
        Repetition::REPEATED => {
            let items = v
                .as_array()
                .ok_or_else(|| ParquetError::Shape(String::from(*name)))?;
            let rest = match rest.split_first() {
                Some((("element", _), after)) => after,
                _ => rest,
            };
            let level = depth.saturating_add(1);
            if items.is_empty() {
                out.push(Entry {
                    value: None,
                    def,
                    rep,
                });
            }
            for (i, item) in items.iter().enumerate() {
                let r = if i == 0 { rep } else { level };
                walk(Some(item), rest, (def.saturating_add(1), r, level), out)?;
            }
            Ok(())
        }
        Repetition::OPTIONAL => {
            let child = v.get(*name).filter(|c| !c.is_null());
            match child {
                None => {
                    out.push(Entry {
                        value: None,
                        def,
                        rep,
                    });
                    Ok(())
                }
                Some(c) => walk(Some(c), rest, (def.saturating_add(1), rep, depth), out),
            }
        }
        Repetition::REQUIRED => {
            let child = v
                .get(*name)
                .filter(|c| !c.is_null())
                .ok_or_else(|| ParquetError::Shape(String::from(*name)))?;
            walk(Some(child), rest, (def, rep, depth), out)
        }
    }
}

fn levels(entries: &[Entry], max: i16, f: fn(&Entry) -> i16) -> Option<Vec<i16>> {
    (max > 0).then(|| entries.iter().map(f).collect())
}

/// The OCSF Parquet file of `records`' copies, one row group.
///
/// # Errors
/// [`ParquetError`]; nothing is written.
pub fn file(records: &[AuditRecord]) -> Result<Vec<u8>, ParquetError> {
    let rows = records
        .iter()
        .map(copy::ocsf)
        .collect::<Result<Vec<_>, _>>()?;
    let schema = Arc::new(schema()?);
    let props = Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .set_created_by(String::from("Suiss Access"))
            .build(),
    );
    let mut w = SerializedFileWriter::new(Vec::new(), schema.clone(), props)?;
    let columns = w.schema_descr().columns().to_vec();
    let mut rg = w.next_row_group()?;
    for cd in &columns {
        let path = cd.path().parts().to_vec();
        let reps = repetitions(&schema, &path)?;
        let nodes: Vec<(&str, Repetition)> = path.iter().map(String::as_str).zip(reps).collect();
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            walk(Some(row), &nodes, (0, 0, 0), &mut entries)?;
        }
        let defs = levels(&entries, cd.max_def_level(), |e| e.def);
        let reps = levels(&entries, cd.max_rep_level(), |e| e.rep);
        let present = entries.iter().filter_map(|e| e.value.as_ref());
        let name = cd.path().string();
        let shape = || ParquetError::Shape(name.clone());
        let mut col = rg
            .next_column()?
            .ok_or_else(|| ParquetError::Shape(String::from("column")))?;
        match cd.physical_type() {
            Physical::INT32 => {
                let v = present
                    .map(|x| {
                        x.as_i64()
                            .and_then(|n| i32::try_from(n).ok())
                            .ok_or_else(shape)
                    })
                    .collect::<Result<Vec<i32>, _>>()?;
                col.typed::<Int32Type>()
                    .write_batch(&v, defs.as_deref(), reps.as_deref())?;
            }
            Physical::INT64 => {
                let v = present
                    .map(|x| x.as_i64().ok_or_else(shape))
                    .collect::<Result<Vec<i64>, _>>()?;
                col.typed::<Int64Type>()
                    .write_batch(&v, defs.as_deref(), reps.as_deref())?;
            }
            Physical::BYTE_ARRAY => {
                let v = present
                    .map(|x| {
                        x.as_str()
                            .map(|s| ByteArray::from(s.as_bytes().to_vec()))
                            .ok_or_else(shape)
                    })
                    .collect::<Result<Vec<ByteArray>, _>>()?;
                col.typed::<ByteArrayType>()
                    .write_batch(&v, defs.as_deref(), reps.as_deref())?;
            }
            _ => return Err(shape()),
        }
        col.close()?;
    }
    rg.close()?;
    Ok(w.into_inner()?)
}

#[cfg(test)]
mod tests;
