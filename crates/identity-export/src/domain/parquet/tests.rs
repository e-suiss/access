use bytes::Bytes;
use parquet::file::reader::{FileReader as _, SerializedFileReader};
use parquet::record::Field;

use super::*;
use crate::domain::fields::{sample, table};

fn record(event: &str, n: i64) -> AuditRecord {
    let mut r = sample(event);
    r.id = format!("identity:{n}");
    r.target = format!("t{n}");
    if n % 2 == 0 {
        r.reason = None;
        r.checkpoint_at_ms = None;
    }
    r
}

// OP-156 m.3 (s), OP-41, Ek B 5313
#[test]
fn the_file_reads_back_with_the_ocsf_schema() {
    let events = [
        "login.password.succeeded",
        "account.created",
        "audit.read",
        "export.batch_sent",
    ];
    let records: Vec<AuditRecord> = events
        .iter()
        .enumerate()
        .map(|(i, e)| record(e, i64::try_from(i).unwrap()))
        .collect();
    let bytes = file(&records).unwrap();
    let text = crate::testing::parquet_rows(&bytes).unwrap();
    assert!(
        text.iter()
            .all(|r| r.contains("access_record: \"copy\"") && r.contains("class_uid: ")),
        "{text:?}"
    );
    let reader = SerializedFileReader::new(Bytes::from(bytes)).unwrap();
    let meta = reader.metadata();
    assert_eq!(meta.file_metadata().num_rows(), 4);
    let cols: Vec<String> = meta
        .file_metadata()
        .schema_descr()
        .columns()
        .iter()
        .map(|c| c.path().string())
        .collect();
    let paths: Vec<String> = cols
        .iter()
        .map(|c| c.replace(".list.element", "[]"))
        .collect();
    for (class, fields) in table().unwrap() {
        for f in fields {
            assert!(paths.contains(&f), "class {class}: {f} has no column");
        }
    }
    let rows: Vec<_> = reader
        .get_row_iter(None)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for (row, rec) in rows.iter().zip(&records) {
        let get = |name: &str| {
            row.get_column_iter()
                .find(|(n, _)| n.as_str() == name)
                .map(|(_, f)| f.clone())
        };
        let Some(Field::Group(meta)) = get("metadata") else {
            panic!("metadata")
        };
        let uid = meta
            .get_column_iter()
            .find(|(n, _)| n.as_str() == "uid")
            .map(|(_, f)| f.clone());
        assert_eq!(uid, Some(Field::Str(rec.id.clone())));
        let Some(Field::Group(u)) = get("unmapped") else {
            panic!("unmapped")
        };
        let label = u
            .get_column_iter()
            .find(|(n, _)| n.as_str() == "access_record")
            .map(|(_, f)| f.clone());
        assert_eq!(label, Some(Field::Str(String::from("copy"))));
        assert!(matches!(get("time"), Some(Field::TimestampMillis(1))));
    }
}
