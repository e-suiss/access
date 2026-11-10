//! `idp.hr.*` changes (catalog 6, OP-156 m.3 (a), (q)): registering and retiring HR sources and
//! the connectors of `services/hr-connector`, and importing a JSONL batch or a CSV file into a
//! source. Sans-I/O: the REST body becomes one change, which the intent binds (EI-25). An import
//! names its file by SHA-256 and record count; the records travel beside the change, every one
//! read before the decision is drawn.

use access_identity_account::app::hr::{self as records, Format, Record};
use access_internal_api::idp::IdpAction;
use access_kernel::json::b64url_decode;
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// The HR systems `services/hr-connector` reads, in the order they ship (OP-156 m.3 (q)).
pub const VENDORS: [&str; 7] = [
    "personio",
    "bamboohr",
    "hibob",
    "workday",
    "successfactors",
    "kolayik",
    "logo",
];

/// Whether `name` is a source or connector name: a lower-case letter, then up to 62 lower-case
/// letters, digits and `-`.
#[must_use]
pub fn name_ok(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// One `idp.hr.import`: the file's digest and record count, which the intent binds, and its
/// records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HrImport {
    /// The source.
    pub source: String,
    /// The file's format.
    pub format: Format,
    /// SHA-256 of the file.
    pub file: [u8; 32],
    /// How many records it holds.
    pub records: u32,
    /// The records, every one checked.
    pub lines: Vec<Record>,
}

/// An `idp.hr.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HrChange {
    /// `idp.hr.source_register` (CT2): a new Claim issuer; its HR Claims select only through
    /// the domain's CT3 `subject-selection` Acceptance (TN-95).
    SourceRegister(String),
    /// `idp.hr.source_retire` (CT1): its records are no longer imported or stated.
    SourceRetire(String),
    /// `idp.hr.connector_register` (CT2): a connector that pushes `vendor`'s records to
    /// `source`.
    ConnectorRegister {
        /// Its name, never reused.
        name: String,
        /// The source it pushes to.
        source: String,
        /// The HR system it reads.
        vendor: String,
    },
    /// `idp.hr.connector_retire` (CT1).
    ConnectorRetire(String),
    /// `idp.hr.import` (CT2).
    Import(HrImport),
}

fn own(body: &Json) -> Result<&Map<String, Json>, Invalid> {
    body.as_object().ok_or(Invalid::Body)
}

fn only(m: &Map<String, Json>, keys: &[&str]) -> Result<(), Invalid> {
    if m.keys().all(|k| keys.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(Invalid::Body)
    }
}

fn text<'a>(m: &'a Map<String, Json>, key: &str, bad: Invalid) -> Result<&'a str, Invalid> {
    m.get(key).and_then(Json::as_str).ok_or(bad)
}

impl HrChange {
    /// `registerHrSource`: `{"name"}`.
    ///
    /// # Errors
    /// [`Invalid::HrSource`].
    pub fn register_source(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["name"]).map_err(|_| Invalid::HrSource)?;
        let c = Self::SourceRegister(String::from(text(m, "name", Invalid::HrSource)?));
        c.check()?;
        Ok(c)
    }

    /// `retireHrSource` of `name`: an empty body.
    ///
    /// # Errors
    /// [`Invalid::HrSource`].
    pub fn retire_source(name: &str, body: &Json) -> Result<Self, Invalid> {
        if !own(body)?.is_empty() {
            return Err(Invalid::HrSource);
        }
        let c = Self::SourceRetire(String::from(name));
        c.check()?;
        Ok(c)
    }

    /// `registerHrConnector`: `{"name", "source", "vendor"}`.
    ///
    /// # Errors
    /// [`Invalid::HrConnector`].
    pub fn register_connector(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["name", "source", "vendor"]).map_err(|_| Invalid::HrConnector)?;
        let c = Self::ConnectorRegister {
            name: String::from(text(m, "name", Invalid::HrConnector)?),
            source: String::from(text(m, "source", Invalid::HrConnector)?),
            vendor: String::from(text(m, "vendor", Invalid::HrConnector)?),
        };
        c.check()?;
        Ok(c)
    }

    /// `retireHrConnector` of `name`: an empty body.
    ///
    /// # Errors
    /// [`Invalid::HrConnector`].
    pub fn retire_connector(name: &str, body: &Json) -> Result<Self, Invalid> {
        if !own(body)?.is_empty() {
            return Err(Invalid::HrConnector);
        }
        let c = Self::ConnectorRetire(String::from(name));
        c.check()?;
        Ok(c)
    }

    /// `importHrBatch` or `importHrCsv` into `source`: `{"file", "records", "content"}`, where
    /// `content` is the file, `file` its SHA-256 (base64url) and `records` its record count.
    /// Every record is read; one bad record, an unknown column or a digest or count the
    /// content does not match refuses the whole file.
    ///
    /// # Errors
    /// [`Invalid::HrRecords`].
    pub fn import(source: &str, format: Format, body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["file", "records", "content"]).map_err(|_| Invalid::HrRecords)?;
        let content = text(m, "content", Invalid::HrRecords)?;
        let file = b64url_decode(text(m, "file", Invalid::HrRecords)?)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or(Invalid::HrRecords)?;
        let count = m
            .get("records")
            .and_then(Json::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(Invalid::HrRecords)?;
        if records::file_digest(content) != file {
            return Err(Invalid::HrRecords);
        }
        let lines = records::parse(format, content).map_err(|_| Invalid::HrRecords)?;
        if u32::try_from(lines.len()).ok() != Some(count) {
            return Err(Invalid::HrRecords);
        }
        let c = Self::Import(HrImport {
            source: String::from(source),
            format,
            file,
            records: count,
            lines,
        });
        c.check()?;
        Ok(c)
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::SourceRegister(_) => IdpAction::HrSourceRegister,
            Self::SourceRetire(_) => IdpAction::HrSourceRetire,
            Self::ConnectorRegister { .. } => IdpAction::HrConnectorRegister,
            Self::ConnectorRetire(_) => IdpAction::HrConnectorRetire,
            Self::Import(_) => IdpAction::HrImport,
        }
    }

    /// Whether it is inside the rules: names of lower-case letters, digits and `-`, a vendor
    /// `services/hr-connector` reads, and 1 to 10 000 records.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self) -> Result<(), Invalid> {
        let ok = match self {
            Self::SourceRegister(n) | Self::SourceRetire(n) | Self::ConnectorRetire(n) => {
                name_ok(n)
            }
            Self::ConnectorRegister {
                name,
                source,
                vendor,
            } => name_ok(name) && name_ok(source) && VENDORS.contains(&vendor.as_str()),
            Self::Import(i) => {
                if !name_ok(&i.source)
                    || i.records == 0
                    || usize::try_from(i.records).map_or(true, |n| n > records::MAX_RECORDS)
                {
                    return Err(Invalid::HrRecords);
                }
                true
            }
        };
        if ok {
            Ok(())
        } else if matches!(
            self,
            Self::ConnectorRegister { .. } | Self::ConnectorRetire(_)
        ) {
            Err(Invalid::HrConnector)
        } else {
            Err(Invalid::HrSource)
        }
    }

    /// The change's body, which the intent binds (EI-25): an import names its file, never its
    /// records.
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        match self {
            Self::SourceRegister(n) => m(vec![("name", Value::text(n))]),
            Self::SourceRetire(n) => m(vec![("retire", Value::text(n))]),
            Self::ConnectorRegister {
                name,
                source,
                vendor,
            } => m(vec![
                ("connector", Value::text(name)),
                ("source", Value::text(source)),
                ("vendor", Value::text(vendor)),
            ]),
            Self::ConnectorRetire(n) => m(vec![("retire_connector", Value::text(n))]),
            Self::Import(i) => m(vec![
                ("source", Value::text(&i.source)),
                ("format", Value::text(i.format.name())),
                ("file", Value::Bytes(i.file.to_vec())),
                ("records", Value::Unsigned(u64::from(i.records))),
            ]),
        }
    }

    /// Its resource path below the realm's slug.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        match self {
            Self::SourceRegister(n) | Self::SourceRetire(n) => {
                vec![String::from("hr-source"), n.clone()]
            }
            Self::Import(i) => vec![String::from("hr-source"), i.source.clone()],
            Self::ConnectorRegister { name, .. } | Self::ConnectorRetire(name) => {
                vec![String::from("hr-connector"), name.clone()]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_kernel::json::b64url_encode;
    use serde_json::json;

    use super::*;

    fn named(content: &str, records: u64) -> Json {
        json!({
            "file": b64url_encode(&records::file_digest(content)),
            "records": records,
            "content": content,
        })
    }

    // OP-156 m.3 (a), (q)
    #[test]
    fn rest_bodies_compile_to_their_catalog_six_action() {
        let s = HrChange::register_source(&json!({"name": "workday"})).unwrap();
        assert_eq!(s.action(), IdpAction::HrSourceRegister);
        assert_eq!(s.path(), vec!["hr-source", "workday"]);
        assert!(HrChange::register_source(&json!({"name": "Workday"})).is_err());
        assert_eq!(
            HrChange::retire_source("workday", &json!({}))
                .unwrap()
                .action(),
            IdpAction::HrSourceRetire
        );
        let c = HrChange::register_connector(
            &json!({"name": "personio-1", "source": "hr", "vendor": "personio"}),
        )
        .unwrap();
        assert_eq!(c.action(), IdpAction::HrConnectorRegister);
        assert_eq!(
            HrChange::register_connector(
                &json!({"name": "x", "source": "hr", "vendor": "spreadsheet"})
            ),
            Err(Invalid::HrConnector)
        );
    }

    // OP-156 m.3 (q), EI-25
    #[test]
    fn an_import_binds_its_file_and_is_refused_whole() {
        let jsonl = r#"{"employee_id":"E1","email":"ada@acme.example"}"#;
        let i = HrChange::import("hr", Format::Jsonl, &named(jsonl, 1)).unwrap();
        assert_eq!(i.action(), IdpAction::HrImport);
        let HrChange::Import(imported) = &i else {
            panic!("{i:?}");
        };
        assert_eq!(imported.lines.len(), 1);
        let other = HrChange::import(
            "hr",
            Format::Jsonl,
            &named(r#"{"employee_id":"E1","email":"bob@acme.example"}"#, 1),
        )
        .unwrap();
        assert_eq!(i.body(), i.body());
        assert_ne!(i.body(), other.body());
        assert_eq!(
            HrChange::import("hr", Format::Jsonl, &named(jsonl, 2)),
            Err(Invalid::HrRecords)
        );
        let mut wrong = named(jsonl, 1);
        wrong["content"] = Json::from(r#"{"employee_id":"E9","email":"eve@acme.example"}"#);
        assert_eq!(
            HrChange::import("hr", Format::Jsonl, &wrong),
            Err(Invalid::HrRecords)
        );
        let csv = "employee_id,email,salary\nE1,a@acme.example,1\n";
        assert_eq!(
            HrChange::import("hr", Format::Csv, &named(csv, 1)),
            Err(Invalid::HrRecords)
        );
    }
}
