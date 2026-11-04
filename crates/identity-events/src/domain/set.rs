//! The two wire forms of one event (OP-149 m.7): a Security Event Token (RFC 8417) for SSF,
//! and the same SET's claims as the `data` of a `CloudEvent` (`CloudEvents` 1.0 structured
//! JSON) for the Suiss webhook profile.

use serde_json::{Map, Value, json};

use crate::domain::Invalid;
use crate::domain::catalog::{Ready, urn, uuid};

/// The SET's JOSE `typ` (RFC 8417 §2.3).
pub const SET_TYP: &str = "secevent+jwt";

/// Media type of a SET.
pub const SET_CONTENT_TYPE: &str = "application/secevent+jwt";

/// Media type of a structured `CloudEvent`.
pub const CLOUDEVENT_CONTENT_TYPE: &str = "application/cloudevents+json; charset=utf-8";

/// `CloudEvents` `source` prefix; the realm's UUID follows (as for Relay, E42 m.4).
pub const SOURCE_PREFIX: &str = "urn:suiss:access:realm:";

/// The SET claims of `event` for one subscription: `iss` the realm issuer, `aud` the
/// subscriber, `iat` when it was queued, `jti` the event id, `sub_id` an opaque subject
/// identifier (SSF 1.0 §3) and one member of `events`.
#[must_use]
pub fn set_claims(event: &Ready, iss: &str, aud: &str, iat_s: u64) -> Value {
    let mut events = Map::new();
    events.insert(urn(event.name), event.payload.clone());
    json!({
        "iss": iss,
        "aud": aud,
        "iat": iat_s,
        "jti": event.id,
        "sub_id": {"format": "opaque", "id": event.sub_id},
        "events": events,
    })
}

/// What a stored SET says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetHead {
    /// `jti`.
    pub jti: String,
    /// The one event type URN.
    pub event_type: String,
    /// `sub_id.id`.
    pub subject: String,
}

/// Reads the head of stored SET claims.
///
/// # Errors
/// [`Invalid`].
pub fn head(claims: &Value) -> Result<SetHead, Invalid> {
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or(Invalid("jti"))?;
    let events = claims
        .get("events")
        .and_then(Value::as_object)
        .ok_or(Invalid("events"))?;
    let mut keys = events.keys();
    let (Some(event_type), None) = (keys.next(), keys.next()) else {
        return Err(Invalid("events"));
    };
    Ok(SetHead {
        jti: String::from(jti),
        event_type: event_type.clone(),
        subject: claims
            .pointer("/sub_id/id")
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_default(),
    })
}

/// The structured `CloudEvent` carrying `claims` as `data` (OP-149 m.7). `id` is the SET's
/// `jti`, so a receiver deduplicates both forms by the same value.
///
/// # Errors
/// [`Invalid`] when the claims have no head or a time is out of range.
pub fn cloud_event(
    claims: &Value,
    tenant: &[u8; 16],
    realm: &[u8; 16],
    occurred_ms: u64,
) -> Result<Vec<u8>, Invalid> {
    let h = head(claims)?;
    let time = access_identity_account::notify::message::rfc3339(occurred_ms)
        .map_err(|_| Invalid("time"))?;
    let mut e = Map::new();
    e.insert("specversion".into(), "1.0".into());
    e.insert("id".into(), h.jti.into());
    e.insert(
        "source".into(),
        format!("{SOURCE_PREFIX}{}", uuid(realm)).into(),
    );
    e.insert("type".into(), h.event_type.into());
    if !h.subject.is_empty() {
        e.insert("subject".into(), h.subject.into());
    }
    e.insert("time".into(), time.into());
    e.insert("datacontenttype".into(), "application/json".into());
    e.insert("accesstenant".into(), uuid(tenant).into());
    e.insert("accessrealm".into(), uuid(realm).into());
    e.insert("data".into(), claims.clone());
    serde_json::to_vec(&Value::Object(e)).map_err(|_| Invalid("encoding"))
}
