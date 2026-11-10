//! The HTTP event collector's requests (OP-156 m.3 (s)): a plain collector takes a JSON array of
//! OCSF events; the presets shape the same events as each vendor's intake expects. Every request
//! carries `x-access-record: copy`.
//!
//! - Splunk HEC: one `{time, source, sourcetype, index?, event}` object per line,
//!   `Authorization: Splunk <token>`.
//! - Microsoft Sentinel, Logs Ingestion API: a JSON array to
//!   `{endpoint}/dataCollectionRules/{dcr}/streams/{stream}?api-version=2023-01-01` with a bearer
//!   token from the Entra client credentials grant.
//! - Datadog Logs v2: a JSON array of `{ddsource, service, ddtags, message}`, `DD-API-KEY`.
//! - Elastic `_bulk`: NDJSON `create` actions into the data stream, `Authorization: ApiKey`.

use access_identity_audit::domain::record::AuditRecord;
use access_identity_audit::domain::taxonomy::TaxonomyError;
use serde_json::{Map, Value, json};

use super::copy;
use super::sink::{Preset, SinkSecret, SinkSpec};

/// The Logs Ingestion API version.
pub const SENTINEL_API: &str = "2023-01-01";

/// The scope of a Logs Ingestion API token.
pub const SENTINEL_SCOPE: &str = "https://monitor.azure.com//.default";

/// One request of a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// `POST` or `PUT`.
    pub method: &'static str,
    /// The URL.
    pub url: String,
    /// `Content-Type`.
    pub content_type: &'static str,
    /// Extra headers, the secret's among them.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

fn text<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

fn trimmed(endpoint: &str) -> &str {
    endpoint.trim_end_matches('/')
}

fn events(records: &[AuditRecord]) -> Result<Vec<Value>, TaxonomyError> {
    records.iter().map(copy::ocsf).collect()
}

fn auth(spec: &SinkSpec, secret: Option<&SinkSecret>) -> Vec<(String, String)> {
    let mut h = vec![(String::from(copy::HEADER), String::from(copy::VALUE))];
    if let Some(s) = secret {
        match text(&spec.settings, "auth_header") {
            Some(name) => h.push((String::from(name), String::from(s.expose()))),
            None => h.push((
                String::from("Authorization"),
                format!("Bearer {}", s.expose()),
            )),
        }
    }
    h
}

/// The OAuth client credentials form of a Sentinel sink (RFC 6749 §4.4) and its token URL.
#[must_use]
pub fn sentinel_token(spec: &SinkSpec, secret: &SinkSecret) -> (String, String) {
    let m = &spec.settings;
    let tenant = text(m, "tenant_id").unwrap_or_default();
    let url = text(m, "token_url").map_or_else(
        || format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
        String::from,
    );
    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
        form_escape(text(m, "client_id").unwrap_or_default()),
        form_escape(secret.expose()),
        form_escape(SENTINEL_SCOPE),
    );
    (url, form)
}

/// `application/x-www-form-urlencoded` escaping.
#[must_use]
pub fn form_escape(v: &str) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn splunk(
    m: &Map<String, Value>,
    url: &str,
    key: &str,
    records: &[AuditRecord],
) -> Result<Request, TaxonomyError> {
    let mut body = Vec::new();
    for (r, e) in records.iter().zip(events(records)?) {
        let mut o = json!({
            "time": format!("{}.{:03}", r.occurred_at_ms / 1000, r.occurred_at_ms % 1000),
            "source": text(m, "source").unwrap_or("access"),
            "sourcetype": text(m, "sourcetype").unwrap_or("ocsf:access"),
            "event": e,
            "fields": { copy::UNMAPPED_MEMBER: copy::VALUE },
        });
        if let (Some(i), Some(obj)) = (text(m, "index"), o.as_object_mut()) {
            obj.insert("index".into(), i.into());
        }
        body.extend_from_slice(o.to_string().as_bytes());
        body.push(b'\n');
    }
    Ok(Request {
        method: "POST",
        url: String::from(url),
        content_type: "application/json",
        headers: vec![
            copy_header(),
            (String::from("Authorization"), format!("Splunk {key}")),
        ],
        body,
    })
}

fn sentinel(
    m: &Map<String, Value>,
    endpoint: &str,
    bearer: Option<&str>,
    records: &[AuditRecord],
) -> Result<Request, TaxonomyError> {
    let rows: Vec<Value> = records
        .iter()
        .zip(events(records)?)
        .map(|(r, mut e)| {
            if let Some(o) = e.as_object_mut() {
                o.insert(
                    "TimeGenerated".into(),
                    super::syslog::timestamp(r.occurred_at_ms).into(),
                );
            }
            e
        })
        .collect();
    Ok(Request {
        method: "POST",
        url: format!(
            "{}/dataCollectionRules/{}/streams/{}?api-version={SENTINEL_API}",
            trimmed(endpoint),
            text(m, "dcr_immutable_id").unwrap_or_default(),
            text(m, "stream").unwrap_or_default(),
        ),
        content_type: "application/json",
        headers: vec![
            copy_header(),
            (
                String::from("Authorization"),
                format!("Bearer {}", bearer.unwrap_or_default()),
            ),
        ],
        body: Value::Array(rows).to_string().into_bytes(),
    })
}

fn datadog(
    m: &Map<String, Value>,
    url: &str,
    key: &str,
    records: &[AuditRecord],
) -> Result<Request, TaxonomyError> {
    let tags = text(m, "tags").map_or_else(
        || format!("{}:{}", copy::HEADER, copy::VALUE),
        |t| format!("{t},{}:{}", copy::HEADER, copy::VALUE),
    );
    let rows: Vec<Value> = events(records)?
        .into_iter()
        .map(|e| {
            json!({
                "ddsource": "access",
                "service": text(m, "service").unwrap_or("access"),
                "ddtags": tags,
                "message": e.to_string(),
            })
        })
        .collect();
    Ok(Request {
        method: "POST",
        url: String::from(url),
        content_type: "application/json",
        headers: vec![
            copy_header(),
            (String::from("DD-API-KEY"), String::from(key)),
        ],
        body: Value::Array(rows).to_string().into_bytes(),
    })
}

fn elastic(
    m: &Map<String, Value>,
    endpoint: &str,
    key: &str,
    records: &[AuditRecord],
) -> Result<Request, TaxonomyError> {
    let mut body = Vec::new();
    for (r, mut e) in records.iter().zip(events(records)?) {
        body.extend_from_slice(b"{\"create\":{}}\n");
        if let Some(o) = e.as_object_mut() {
            o.insert(
                "@timestamp".into(),
                super::syslog::timestamp(r.occurred_at_ms).into(),
            );
        }
        body.extend_from_slice(e.to_string().as_bytes());
        body.push(b'\n');
    }
    Ok(Request {
        method: "POST",
        url: format!(
            "{}/{}/_bulk",
            trimmed(endpoint),
            text(m, "index").unwrap_or_default()
        ),
        content_type: "application/x-ndjson",
        headers: vec![
            copy_header(),
            (String::from("Authorization"), format!("ApiKey {key}")),
        ],
        body,
    })
}

fn copy_header() -> (String, String) {
    (String::from(copy::HEADER), String::from(copy::VALUE))
}

/// The request of `records` to the collector of `spec`; `bearer` is a Sentinel sink's token.
///
/// # Errors
/// [`TaxonomyError`]; nothing is sent.
pub fn request(
    spec: &SinkSpec,
    secret: Option<&SinkSecret>,
    bearer: Option<&str>,
    records: &[AuditRecord],
) -> Result<Request, TaxonomyError> {
    let m = &spec.settings;
    let key = secret.map(SinkSecret::expose).unwrap_or_default();
    match spec.preset {
        None => Ok(Request {
            method: "POST",
            url: spec.endpoint.clone(),
            content_type: "application/json",
            headers: auth(spec, secret),
            body: Value::Array(events(records)?).to_string().into_bytes(),
        }),
        Some(Preset::Splunk) => splunk(m, &spec.endpoint, key, records),
        Some(Preset::Sentinel) => sentinel(m, &spec.endpoint, bearer, records),
        Some(Preset::Datadog) => datadog(m, &spec.endpoint, key, records),
        Some(Preset::Elastic) => elastic(m, &spec.endpoint, key, records),
    }
}

/// Whether a `2xx` answer of `preset` accepted the whole batch: Elastic answers `200` with
/// `"errors": true` when any action failed.
#[must_use]
pub fn accepted(preset: Option<Preset>, status: u16, body: &[u8]) -> bool {
    if !(200..300).contains(&status) {
        return false;
    }
    match preset {
        Some(Preset::Elastic) => {
            serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|v| v.get("errors").and_then(Value::as_bool))
                == Some(false)
        }
        _ => true,
    }
}
