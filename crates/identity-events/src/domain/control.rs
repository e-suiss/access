//! Stream verification and status (SSF 1.0 §8.1.4, §8.1.2): the request bodies, the status
//! answer and the verification SET. A verification event only proves the stream delivers; like
//! every signal it is never authority and its loss widens nothing (§9.16.2, PI-9).

use serde_json::{Value, json};

use crate::domain::Invalid;

/// Path of the verification endpoint under the issuer.
pub const VERIFY_PATH: &str = "/ssf/verify";

/// Path of the status endpoint under the issuer.
pub const STATUS_PATH: &str = "/ssf/status";

/// Path of the semantic acknowledgement endpoint under the issuer (E30).
pub const ACK_PATH: &str = "/ssf/ack";

/// The SSF verification event type.
pub const VERIFICATION_EVENT: &str =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";

/// Longest `state` and `reason` a receiver may send.
pub const MAX_TEXT: usize = 256;

fn object(body: &[u8]) -> Result<serde_json::Map<String, Value>, Invalid> {
    let v: Value = serde_json::from_slice(body).map_err(|_| Invalid("json"))?;
    match v {
        Value::Object(o) => Ok(o),
        _ => Err(Invalid("json")),
    }
}

fn text<'a>(
    o: &'a serde_json::Map<String, Value>,
    k: &'static str,
) -> Result<Option<&'a str>, Invalid> {
    match o.get(k) {
        None => Ok(None),
        Some(Value::String(s)) if s.len() <= MAX_TEXT => Ok(Some(s)),
        Some(_) => Err(Invalid(k)),
    }
}

/// A verification request: the stream it names and the opaque `state` to echo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyRequest {
    /// `stream_id`.
    pub stream_id: String,
    /// `state`.
    pub state: Option<String>,
}

/// Reads a verification request (SSF 1.0 §8.1.4.2).
///
/// # Errors
/// [`Invalid`].
pub fn parse_verify(body: &[u8]) -> Result<VerifyRequest, Invalid> {
    let o = object(body)?;
    Ok(VerifyRequest {
        stream_id: text(&o, "stream_id")?
            .ok_or(Invalid("stream_id"))?
            .to_owned(),
        state: text(&o, "state")?.map(String::from),
    })
}

/// A receiver's semantic acknowledgement (E30): it applied or ignored the SET `jti`. Apart from
/// the delivery ack (push `2xx`, poll `ack`), and never a statement about authority state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticAck {
    /// The SET.
    pub jti: String,
    /// `applied` or `ignored`.
    pub state: &'static str,
}

/// Reads `{"jti", "state": "applied" | "ignored"}`.
///
/// # Errors
/// [`Invalid`].
pub fn parse_ack(body: &[u8]) -> Result<SemanticAck, Invalid> {
    let o = object(body)?;
    let state = match text(&o, "state")? {
        Some("applied") => "applied",
        Some("ignored") => "ignored",
        _ => return Err(Invalid("state")),
    };
    Ok(SemanticAck {
        jti: text(&o, "jti")?.ok_or(Invalid("jti"))?.to_owned(),
        state,
    })
}

/// A status update: the stream, its new status and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusUpdate {
    /// `stream_id`.
    pub stream_id: String,
    /// `enabled`, `paused` or `disabled`.
    pub status: String,
    /// `reason`.
    pub reason: Option<String>,
}

/// Reads a status update (SSF 1.0 §8.1.2.2); `disabled` ends the stream (OP-73: it stays as a
/// row).
///
/// # Errors
/// [`Invalid`].
pub fn parse_status(body: &[u8]) -> Result<StatusUpdate, Invalid> {
    let o = object(body)?;
    let status = match text(&o, "status")? {
        Some(s @ ("enabled" | "paused" | "disabled")) => s.to_owned(),
        _ => return Err(Invalid("status")),
    };
    Ok(StatusUpdate {
        stream_id: text(&o, "stream_id")?
            .ok_or(Invalid("stream_id"))?
            .to_owned(),
        status,
        reason: text(&o, "reason")?.map(String::from),
    })
}

/// The status answer (SSF 1.0 §8.1.2.1).
#[must_use]
pub fn status_json(stream_id: &str, status: &str) -> Value {
    json!({ "stream_id": stream_id, "status": status })
}

/// The claims of a verification SET for the stream `stream_id` (SSF 1.0 §8.1.4.1): its subject
/// is the stream and its one event echoes `state`.
#[must_use]
pub fn verification_claims(
    iss: &str,
    aud: &str,
    jti: &str,
    stream_id: &str,
    state: Option<&str>,
    iat_s: u64,
) -> Value {
    let event = state.map_or_else(|| json!({}), |s| json!({ "state": s }));
    json!({
        "iss": iss,
        "aud": aud,
        "iat": iat_s,
        "jti": jti,
        "txn": jti,
        "sub_id": { "format": "opaque", "id": stream_id },
        "events": { VERIFICATION_EVENT: event },
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // SSF 1.0 §8.1.4: a verification request names its stream; the SET's subject is the stream
    // and its one event echoes the state
    #[test]
    fn verification_echoes_the_state() {
        let r = parse_verify(br#"{"stream_id":"s-1","state":"abc"}"#).unwrap();
        assert_eq!(r.state.as_deref(), Some("abc"));
        assert_eq!(parse_verify(br"{}"), Err(Invalid("stream_id")));
        assert_eq!(
            parse_verify(br#"{"stream_id":1}"#),
            Err(Invalid("stream_id"))
        );
        let long = format!(
            r#"{{"stream_id":"s","state":"{}"}}"#,
            "x".repeat(MAX_TEXT + 1)
        );
        assert_eq!(parse_verify(long.as_bytes()), Err(Invalid("state")));
        let c = verification_claims("https://i", "rcv", "j", "s-1", Some("abc"), 7);
        assert_eq!(c["events"][VERIFICATION_EVENT]["state"], "abc");
        assert_eq!(c["sub_id"]["id"], "s-1");
        let c = verification_claims("https://i", "rcv", "j", "s-1", None, 7);
        assert_eq!(c["events"][VERIFICATION_EVENT], json!({}));
    }

    // E30: a semantic ack is applied or ignored, apart from delivery
    #[test]
    fn semantic_acks_are_closed() {
        let a = parse_ack(br#"{"jti":"j","state":"applied"}"#).unwrap();
        assert_eq!((a.jti.as_str(), a.state), ("j", "applied"));
        assert_eq!(
            parse_ack(br#"{"jti":"j","state":"current"}"#),
            Err(Invalid("state"))
        );
        assert_eq!(parse_ack(br#"{"state":"ignored"}"#), Err(Invalid("jti")));
    }

    // SSF 1.0 §8.1.2: a status update is enabled, paused or disabled
    #[test]
    fn a_status_update_is_closed() {
        let u = parse_status(br#"{"stream_id":"s","status":"paused","reason":"m"}"#).unwrap();
        assert_eq!(
            (u.status.as_str(), u.reason.as_deref()),
            ("paused", Some("m"))
        );
        assert_eq!(
            parse_status(br#"{"stream_id":"s","status":"on"}"#),
            Err(Invalid("status"))
        );
    }
}
