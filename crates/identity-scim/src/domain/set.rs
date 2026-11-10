//! SCIM Security Event Tokens (RFC 9967 over RFC 8417; §10.6.2, IDP-23, Ek B 4817, 4927, 4951):
//! the claims set of one provisioning event, in `conformance/cddl/scim-set.cddl`'s shape. The
//! subject is `sub_id` of format `scim`; `txn` ties the event to the request that caused it and
//! to its `Set-Txn` answer header; a `full` event carries the resource or the `PatchOp`, a
//! `notice` only the changed attribute names. A password is never carried, not even in `full`.

use access_identity_events::domain::scim::{SUBJECT_FORMAT, ScimEvent};
use serde_json::{Map, Value, json};

use super::schema::Kind;

/// Whether a stream receives changed attribute names or the data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Attribute names only (the default).
    Notice,
    /// The resource or the `PatchOp`.
    Full,
}

/// What one event says.
#[derive(Clone, Debug, PartialEq)]
pub struct Facts<'a> {
    /// The issuer: the realm's SCIM base URL.
    pub iss: &'a str,
    /// The audience: the stream's receiver.
    pub aud: &'a str,
    /// The token id.
    pub jti: &'a str,
    /// The request's transaction id.
    pub txn: &'a str,
    /// Issued at, Unix seconds.
    pub iat: u64,
    /// The resource type.
    pub kind: Kind,
    /// The resource id.
    pub id: &'a str,
    /// Its `externalId`.
    pub external_id: Option<&'a str>,
    /// Its version after the change.
    pub version: &'a str,
    /// What happened.
    pub change: Change<'a>,
}

/// The change an event reports.
#[derive(Clone, Debug, PartialEq)]
pub enum Change<'a> {
    /// Created; the resource.
    Create(&'a Value),
    /// Patched; the changed attributes and the `PatchOp` body.
    Patch(&'a [String], &'a Value),
    /// Replaced; the changed attributes and the resource.
    Put(&'a [String], &'a Value),
    /// Soft-deleted.
    Delete,
    /// Became active.
    Activate,
    /// Became inactive.
    Deactivate,
}

fn without_secrets(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("password"))
                .map(|(k, x)| (k.clone(), without_secrets(x)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(without_secrets).collect()),
        other => other.clone(),
    }
}

fn patch_ops_without_secrets(body: &Value) -> Value {
    let mut b = without_secrets(body);
    if let Some(Value::Array(ops)) = b.get_mut("Operations") {
        ops.retain(|o| {
            !o.get("path")
                .and_then(Value::as_str)
                .is_some_and(|p| p.to_ascii_lowercase().contains("password"))
        });
    }
    b
}

/// The attribute names of `resource` a `notice` lists (never `password`).
#[must_use]
pub fn attribute_names(resource: &Value) -> Vec<String> {
    resource
        .as_object()
        .map(|o| {
            o.keys()
                .filter(|k| !matches!(k.as_str(), "schemas" | "id" | "meta" | "password"))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// The event of `change` in `mode`.
#[must_use]
pub fn event_of(change: &Change<'_>, mode: Mode) -> ScimEvent {
    match (change, mode) {
        (Change::Create(_), Mode::Notice) => ScimEvent::CreateNotice,
        (Change::Create(_), Mode::Full) => ScimEvent::CreateFull,
        (Change::Patch(..), Mode::Notice) => ScimEvent::PatchNotice,
        (Change::Patch(..), Mode::Full) => ScimEvent::PatchFull,
        (Change::Put(..), Mode::Notice) => ScimEvent::PutNotice,
        (Change::Put(..), Mode::Full) => ScimEvent::PutFull,
        (Change::Delete, _) => ScimEvent::Delete,
        (Change::Activate, _) => ScimEvent::Activate,
        (Change::Deactivate, _) => ScimEvent::Deactivate,
    }
}

/// The SET claims set of `f` in `mode`.
#[must_use]
pub fn claims(f: &Facts<'_>, mode: Mode) -> Value {
    let event = event_of(&f.change, mode);
    let payload = match (&f.change, mode) {
        (Change::Create(r), Mode::Notice) => {
            json!({ "attributes": attribute_names(r), "version": f.version })
        }
        (Change::Patch(names, _) | Change::Put(names, _), Mode::Notice) => {
            json!({ "attributes": names, "version": f.version })
        }
        (Change::Create(r) | Change::Put(_, r), Mode::Full) => {
            json!({ "data": without_secrets(r), "version": f.version })
        }
        (Change::Patch(_, body), Mode::Full) => {
            json!({ "data": patch_ops_without_secrets(body), "version": f.version })
        }
        (Change::Delete | Change::Activate | Change::Deactivate, _) => {
            json!({ "version": f.version })
        }
    };
    let mut sub = Map::new();
    sub.insert(String::from("format"), Value::from(SUBJECT_FORMAT));
    sub.insert(
        String::from("uri"),
        Value::from(format!("/{}/{}", f.kind.endpoint(), f.id)),
    );
    if let Some(e) = f.external_id {
        sub.insert(String::from("externalId"), Value::from(e));
    }
    let mut events = Map::new();
    events.insert(event.uri(), payload);
    json!({
        "iss": f.iss,
        "iat": f.iat,
        "jti": f.jti,
        "aud": f.aud,
        "txn": f.txn,
        "sub_id": Value::Object(sub),
        "events": Value::Object(events),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn facts(change: Change<'_>) -> Facts<'_> {
        Facts {
            iss: "https://acme.access.test/scim/v2",
            aud: "https://receiver.example",
            jti: "j1",
            txn: "t1",
            iat: 1_700_000_000,
            kind: Kind::User,
            id: "2819c223",
            external_id: Some("e-1"),
            version: "W/\"3\"",
            change,
        }
    }

    // IDP-23, Ek B 4817
    #[test]
    fn a_set_names_its_subject_by_scim_uri_and_never_carries_a_password() {
        let r = json!({ "userName": "bjensen", "password": "never", "active": true });
        let c = claims(&facts(Change::Create(&r)), Mode::Full);
        assert_eq!(c["sub_id"]["format"], "scim");
        assert_eq!(c["sub_id"]["uri"], "/Users/2819c223");
        assert_eq!(c["txn"], "t1");
        assert!(c.get("sub").is_none());
        let data = &c["events"]["urn:ietf:params:SCIM:event:prov:create:full"]["data"];
        assert_eq!(data["userName"], "bjensen");
        assert!(data.get("password").is_none());
        let n = claims(&facts(Change::Create(&r)), Mode::Notice);
        let names = &n["events"]["urn:ietf:params:SCIM:event:prov:create:notice"]["attributes"];
        assert!(!names.as_array().unwrap().iter().any(|x| x == "password"));
        let d = claims(&facts(Change::Deactivate), Mode::Notice);
        assert!(
            d["events"]
                .get("urn:ietf:params:SCIM:event:prov:deactivate")
                .is_some()
        );
    }
}
