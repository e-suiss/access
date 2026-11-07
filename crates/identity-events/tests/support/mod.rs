#![allow(dead_code, reason = "each test file uses part of the support")]

pub mod schema;

use std::path::PathBuf;

use serde_json::Value as Json;

pub fn contracts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi/events")
}

pub fn load(file: &str) -> Json {
    let path = contracts().join(file);
    serde_json::from_slice(&std::fs::read(&path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn assert_valid(schema_file: &str, value: &Json) {
    let schema = load(schema_file);
    let errors = schema::Schema::new(&schema).errors(value);
    assert!(errors.is_empty(), "{schema_file}: {errors:?}\n{value}");
}

/// Checks a SET's claims against the SET schema and its one event against that event's schema.
pub fn assert_set(claims: &Json) -> String {
    assert_valid("set.schema.json", claims);
    let events = claims["events"].as_object().unwrap();
    assert_eq!(events.len(), 1);
    let (urn, payload) = events.iter().next().unwrap();
    assert_valid(&schema_of(urn), payload);
    urn.clone()
}

/// The schema file of an event type: an Access URN or a CAEP/RISC type URI.
pub fn schema_of(uri: &str) -> String {
    if let Some(name) = uri.strip_prefix("urn:suiss:access:event:") {
        return format!("{name}.schema.json");
    }
    let rest = uri
        .strip_prefix("https://schemas.openid.net/secevent/")
        .unwrap();
    let (family, name) = rest.split_once("/event-type/").unwrap();
    format!("{family}.{name}.schema.json")
}

/// Checks a webhook body: the `CloudEvent` envelope, its `data` SET and the event.
pub fn assert_cloud_event(ce: &Json) {
    assert_valid("cloudevent.schema.json", ce);
    let urn = assert_set(&ce["data"]);
    assert_eq!(ce["type"], urn.as_str());
    assert_eq!(ce["id"], ce["data"]["jti"]);
}
