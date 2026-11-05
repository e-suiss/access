//! Streams (SSF 1.0 §8), their channel, the transmitter metadata (SSF 1.0 §7), RFC 8936 poll
//! bodies, and how a receiver's answer to a push is read.

use serde_json::{Map, Value, json};

use crate::domain::Invalid;
use crate::domain::catalog::{NAMES, name_of, urn, uuid};

/// RFC 8935 push delivery method.
pub const PUSH_METHOD: &str = "urn:ietf:rfc:8935";

/// RFC 8936 poll delivery method.
pub const POLL_METHOD: &str = "urn:ietf:rfc:8936";

/// The Suiss webhook profile as a delivery method (OP-149 m.4).
pub const WEBHOOK_METHOD: &str = "urn:suiss:access:delivery:webhook";

/// Path of the stream configuration endpoint under the issuer.
pub const STREAMS_PATH: &str = "/ssf/streams";

/// Path of the poll endpoint under the issuer.
pub const POLL_PATH: &str = "/ssf/poll";

/// Most events one poll returns (PD).
pub const MAX_POLL: u32 = 100;

/// Most ids one poll acknowledges or reports (PD).
pub const MAX_ACKS: usize = 1000;

/// The one channel of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// `CloudEvents` + Standard Webhooks.
    Webhook,
    /// RFC 8935.
    SsfPush,
    /// RFC 8936.
    SsfPoll,
}

impl Channel {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::SsfPush => "ssf_push",
            Self::SsfPoll => "ssf_poll",
        }
    }

    /// The channel of a stored name.
    #[must_use]
    pub fn from_name(n: &str) -> Option<Self> {
        [Self::Webhook, Self::SsfPush, Self::SsfPoll]
            .into_iter()
            .find(|c| c.name() == n)
    }

    /// The SSF delivery method URN.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Webhook => WEBHOOK_METHOD,
            Self::SsfPush => PUSH_METHOD,
            Self::SsfPoll => POLL_METHOD,
        }
    }

    fn from_method(m: &str) -> Option<Self> {
        [Self::Webhook, Self::SsfPush, Self::SsfPoll]
            .into_iter()
            .find(|c| c.method() == m)
    }
}

/// A stream as a subscriber asks for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamRequest {
    /// Its channel.
    pub channel: Channel,
    /// Where pushes go; absent for poll.
    pub endpoint: Option<String>,
    /// The SET `aud`.
    pub audience: String,
    /// Event type URNs, each in the catalog, sorted and unique.
    pub events: Vec<String>,
    /// Free text.
    pub description: Option<String>,
}

fn text<'a>(o: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, Invalid> {
    match o.get(k) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(Invalid("type")),
    }
}

/// The requested event URNs: every one in the catalog, sorted, unique, not empty.
///
/// # Errors
/// [`Invalid`].
pub fn requested(v: Option<&Value>) -> Result<Vec<String>, Invalid> {
    let list = v
        .and_then(Value::as_array)
        .ok_or(Invalid("events_requested"))?;
    let mut out = Vec::with_capacity(list.len());
    for e in list {
        let u = e.as_str().ok_or(Invalid("events_requested"))?;
        name_of(u).ok_or(Invalid("unsupported-event"))?;
        out.push(String::from(u));
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(Invalid("events_requested"));
    }
    Ok(out)
}

/// Reads a stream configuration request (SSF 1.0 §8.1.1.1): `delivery.method`,
/// `delivery.endpoint_url`, `events_requested`, `aud`, `description`.
///
/// # Errors
/// [`Invalid`].
pub fn parse_stream(body: &[u8]) -> Result<StreamRequest, Invalid> {
    let v: Value = serde_json::from_slice(body).map_err(|_| Invalid("json"))?;
    let o = v.as_object().ok_or(Invalid("json"))?;
    let delivery = o
        .get("delivery")
        .and_then(Value::as_object)
        .ok_or(Invalid("delivery"))?;
    let channel = text(delivery, "method")?
        .and_then(Channel::from_method)
        .ok_or(Invalid("delivery-method"))?;
    let endpoint = text(delivery, "endpoint_url")?.map(String::from);
    match (channel, &endpoint) {
        (Channel::SsfPoll, None) => {}
        (Channel::Webhook | Channel::SsfPush, Some(url))
            if access_identity_oauth::adapters::outbound::Target::parse(url).is_ok() => {}
        _ => return Err(Invalid("endpoint_url")),
    }
    let audience = text(o, "aud")?.ok_or(Invalid("aud"))?;
    if audience.is_empty() || audience.len() > 512 {
        return Err(Invalid("aud"));
    }
    let description = text(o, "description")?.map(String::from);
    if description.as_ref().is_some_and(|d| d.len() > 512) {
        return Err(Invalid("description"));
    }
    Ok(StreamRequest {
        channel,
        endpoint,
        audience: String::from(audience),
        events: requested(o.get("events_requested"))?,
        description,
    })
}

/// A stream's configuration as SSF 1.0 §8.1.1 shows it, with `status`.
#[must_use]
pub fn stream_json(
    issuer: &str,
    id: &[u8; 16],
    channel: Channel,
    endpoint: Option<&str>,
    audience: &str,
    events: &[String],
    status: &str,
) -> Value {
    let mut delivery = Map::new();
    delivery.insert("method".into(), channel.method().into());
    let url = match channel {
        Channel::SsfPoll => Some(format!("{issuer}{POLL_PATH}")),
        _ => endpoint.map(String::from),
    };
    if let Some(u) = url {
        delivery.insert("endpoint_url".into(), u.into());
    }
    json!({
        "stream_id": uuid(id),
        "iss": issuer,
        "aud": audience,
        "events_supported": supported(),
        "events_requested": events,
        "events_delivered": events,
        "delivery": delivery,
        "status": status,
    })
}

/// Every event type URN the transmitter supports.
#[must_use]
pub fn supported() -> Vec<String> {
    NAMES.iter().map(|n| urn(n)).collect()
}

/// The transmitter metadata at `/.well-known/ssf-configuration` (SSF 1.0 §7.1). Stream
/// management, status and verification take a stream's bearer credential (RFC 6750).
#[must_use]
pub fn ssf_configuration(issuer: &str, jwks_uri: &str) -> Value {
    json!({
        "spec_version": "1_0",
        "issuer": issuer,
        "jwks_uri": jwks_uri,
        "delivery_methods_supported": [PUSH_METHOD, POLL_METHOD, WEBHOOK_METHOD],
        "configuration_endpoint": format!("{issuer}{STREAMS_PATH}"),
        "status_endpoint": format!("{issuer}{}", crate::domain::control::STATUS_PATH),
        "verification_endpoint": format!("{issuer}{}", crate::domain::control::VERIFY_PATH),
        "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6750"}],
        "default_subjects": "NONE",
    })
}

/// A poll request (RFC 8936 §2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollRequest {
    /// SETs the receiver took.
    pub ack: Vec<String>,
    /// SETs the receiver reports an error for.
    pub errors: Vec<String>,
    /// Most SETs to return; 0 acknowledges only.
    pub max_events: u32,
}

/// Reads a poll request; `maxEvents` defaults to and is capped at [`MAX_POLL`].
///
/// # Errors
/// [`Invalid`].
pub fn parse_poll(body: &[u8]) -> Result<PollRequest, Invalid> {
    let v: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(body).map_err(|_| Invalid("json"))?
    };
    let o = v.as_object().ok_or(Invalid("json"))?;
    let ack = match o.get("ack") {
        None => Vec::new(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|j| j.as_str().map(String::from).ok_or(Invalid("ack")))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(Invalid("ack")),
    };
    let errors = match o.get("setErrs") {
        None => Vec::new(),
        Some(Value::Object(m)) => m.keys().cloned().collect(),
        Some(_) => return Err(Invalid("setErrs")),
    };
    if ack.len() > MAX_ACKS || errors.len() > MAX_ACKS {
        return Err(Invalid("too-many"));
    }
    let max_events = match o.get("maxEvents") {
        None => MAX_POLL,
        Some(n) => n
            .as_u64()
            .map(|n| u32::try_from(n.min(u64::from(MAX_POLL))).unwrap_or(MAX_POLL))
            .ok_or(Invalid("maxEvents"))?,
    };
    match o.get("returnImmediately") {
        None | Some(Value::Bool(_)) => {}
        Some(_) => return Err(Invalid("returnImmediately")),
    }
    Ok(PollRequest {
        ack,
        errors,
        max_events,
    })
}

/// A poll response (RFC 8936 §2.5): the SETs by `jti` and whether more wait.
#[must_use]
pub fn poll_response(sets: &[(String, String)], more: bool) -> Value {
    let mut m = Map::new();
    for (jti, token) in sets {
        m.insert(jti.clone(), token.clone().into());
    }
    json!({"sets": m, "moreAvailable": more})
}

/// What a receiver's answer to a push means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Taken; a duplicate the receiver already took is taken too.
    Delivered,
    /// Try again later.
    Transient {
        /// The receiver's `Retry-After`, ms.
        retry_after_ms: Option<u64>,
    },
    /// Refused for good.
    Rejected,
}

/// Reads a push answer: any `2xx` is taken (RFC 8935 §2.2 answers `202`); `408`, `425`,
/// `429` and `5xx` other than `501` are worth retrying; anything else is final.
#[must_use]
pub const fn classify(status: u16, retry_after_ms: Option<u64>) -> Answer {
    match status {
        200..=299 => Answer::Delivered,
        408 | 425 | 429 | 500 | 502..=599 => Answer::Transient { retry_after_ms },
        _ => Answer::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-149 m.7: one channel per stream, only catalog events, https endpoints
    #[test]
    fn stream_requests_are_checked() {
        let ok = br#"{"delivery":{"method":"urn:suiss:access:delivery:webhook","endpoint_url":"https://work.example/v1/access/events"},"aud":"work","events_requested":["urn:suiss:access:event:party.disabled","urn:suiss:access:event:authority-revoked","urn:suiss:access:event:party.disabled"]}"#;
        let s = parse_stream(ok).unwrap();
        assert_eq!(s.channel, Channel::Webhook);
        assert_eq!(s.events.len(), 2);
        for bad in [
            br#"{"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"https://a.example/"},"aud":"x","events_requested":["urn:suiss:access:event:party.disabled"]}"#.as_slice(),
            br#"{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"http://a.example/"},"aud":"x","events_requested":["urn:suiss:access:event:party.disabled"]}"#,
            br#"{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://a.example/"},"aud":"x","events_requested":["urn:other"]}"#,
            br#"{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://a.example/"},"aud":"x","events_requested":[]}"#,
            br#"{"delivery":{"method":"urn:x"},"aud":"x","events_requested":["urn:suiss:access:event:party.disabled"]}"#,
        ] {
            assert!(parse_stream(bad).is_err());
        }
    }

    // RFC 8936 §2.4
    #[test]
    fn poll_requests_are_bounded() {
        let p = parse_poll(br#"{"ack":["a"],"setErrs":{"b":{"err":"x","description":"y"}},"maxEvents":5000,"returnImmediately":true}"#).unwrap();
        assert_eq!(
            (p.ack, p.errors, p.max_events),
            (vec!["a".into()], vec!["b".into()], MAX_POLL)
        );
        assert_eq!(parse_poll(b"").unwrap().max_events, MAX_POLL);
        assert!(parse_poll(br#"{"ack":"a"}"#).is_err());
    }

    // OP-149 m.4, RFC 8935 §2.2
    #[test]
    fn answers_are_classified() {
        assert_eq!(classify(202, None), Answer::Delivered);
        assert_eq!(classify(204, None), Answer::Delivered);
        assert_eq!(
            classify(429, Some(5)),
            Answer::Transient {
                retry_after_ms: Some(5)
            }
        );
        assert_eq!(
            classify(503, None),
            Answer::Transient {
                retry_after_ms: None
            }
        );
        assert_eq!(classify(501, None), Answer::Rejected);
        assert_eq!(classify(400, None), Answer::Rejected);
        assert_eq!(classify(301, None), Answer::Rejected);
    }
}
