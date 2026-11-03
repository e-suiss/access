//! Delivery rules, free of I/O (OP-63, OP-131, E42 m.5): the `CloudEvent` Relay receives, how a
//! Relay answer is classified, and how long the courier waits before trying again.

use core::fmt;

use access_crypto::Secret;
use serde_json::{Map, Value};

use crate::notify::envelope::{EventId, Header};
use crate::notify::message::{Invalid, Message, rfc3339};

/// `CloudEvents` `source` prefix; the realm's UUID follows.
pub const SOURCE_PREFIX: &str = "urn:suiss:access:realm:";

/// One `CloudEvent` in structured JSON mode, ready to post. The bytes carry the secret and the
/// address, so they are a [`Secret`] and never printed.
pub struct CloudEvent {
    /// `id`, also the `Idempotency-Key`.
    pub id: EventId,
    /// `type`.
    pub kind: &'static str,
    body: Secret<Vec<u8>>,
}

impl fmt::Debug for CloudEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudEvent")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("body", &"[redacted]")
            .finish()
    }
}

impl CloudEvent {
    /// The `application/cloudevents+json` body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.expose()
    }
}

fn uuid(b: &[u8; 16]) -> String {
    EventId(*b).to_string()
}

/// Builds the `CloudEvent` (`CloudEvents` 1.0, structured JSON) for a message. Extension
/// attributes `accesstenant` and `accessrealm` are the tenant mapping both products share
/// (E42 m.4); `subject` is the subject's external id (OP-137).
///
/// # Errors
/// [`Invalid`] when a time is out of range.
pub fn cloud_event(
    header: &Header,
    subject_external: &str,
    message: &Message,
) -> Result<CloudEvent, Invalid> {
    let mut e = Map::new();
    e.insert("specversion".into(), "1.0".into());
    e.insert("id".into(), header.event.to_string().into());
    e.insert(
        "source".into(),
        format!("{SOURCE_PREFIX}{}", uuid(&header.realm)).into(),
    );
    e.insert("type".into(), message.body.kind().into());
    e.insert("subject".into(), subject_external.into());
    e.insert("time".into(), rfc3339(header.occurred_ms)?.into());
    e.insert("datacontenttype".into(), "application/json".into());
    e.insert("accesstenant".into(), uuid(&header.tenant).into());
    e.insert("accessrealm".into(), uuid(&header.realm).into());
    e.insert("data".into(), message.to_wire_data()?);
    let body = serde_json::to_vec(&Value::Object(e)).map_err(|_| Invalid("encoding"))?;
    Ok(CloudEvent {
        id: header.event,
        kind: message.body.kind(),
        body: Secret::new(body),
    })
}

/// Why Relay did not take a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendFailure {
    /// Try again: Relay or the network is down, overloaded or misconfigured. The message
    /// waits in the outbox (E42 m.5).
    Transient {
        /// Relay's `Retry-After`, in ms.
        retry_after_ms: Option<u64>,
    },
    /// Relay refused this message for good; sending it again cannot succeed.
    Rejected {
        /// HTTP status.
        status: u16,
    },
}

/// Relay's answer to a post, by HTTP status. Any 2xx is acceptance, `409` a duplicate of an
/// accepted id (idempotent redelivery). Authentication, routing and capacity failures are
/// transient: a misconfigured Relay must not cost messages.
///
/// # Errors
/// The [`SendFailure`] for any other status.
pub const fn classify(status: u16, retry_after_ms: Option<u64>) -> Result<(), SendFailure> {
    match status {
        200..=299 | 409 => Ok(()),
        400 | 413 | 415 | 422 => Err(SendFailure::Rejected { status }),
        _ => Err(SendFailure::Transient { retry_after_ms }),
    }
}

/// Exponential backoff with a ceiling (PD values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// First wait, ms.
    pub base_ms: u64,
    /// Longest wait, ms.
    pub max_ms: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base_ms: 1_000,
            max_ms: 300_000,
        }
    }
}

impl Backoff {
    /// The wait before attempt `failures + 1`; Relay's `Retry-After` wins when longer, up
    /// to the ceiling.
    #[must_use]
    pub fn wait_ms(&self, failures: u32, retry_after_ms: Option<u64>) -> u64 {
        let shift = failures.saturating_sub(1).min(32);
        let exp = 1_u64
            .checked_shl(shift)
            .and_then(|m| self.base_ms.checked_mul(m))
            .unwrap_or(self.max_ms)
            .min(self.max_ms);
        retry_after_ms.map_or(exp, |r| r.max(exp).min(self.max_ms))
    }
}

/// Why the courier passed a message without delivering it. The outbox row stays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Undeliverable {
    /// The payload does not parse or open.
    Malformed,
    /// The subject does not exist in the realm.
    NoSubject,
    /// The subject's key was shredded (OP-73).
    Shredded,
    /// The code or link expired before Relay could take it.
    Expired,
    /// Relay refused it for good.
    Rejected {
        /// HTTP status.
        status: u16,
    },
}

impl Undeliverable {
    /// The stored reason code.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NoSubject => "no_subject",
            Self::Shredded => "shredded",
            Self::Expired => "expired",
            Self::Rejected { .. } => "rejected",
        }
    }

    /// Relay's status, when Relay answered.
    #[must_use]
    pub const fn relay_status(self) -> Option<u16> {
        match self {
            Self::Rejected { status } => Some(status),
            _ => None,
        }
    }
}
