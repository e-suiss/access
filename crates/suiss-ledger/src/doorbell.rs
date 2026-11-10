//! The NATS `JetStream` doorbell (OP-23, T26, Access OP-156 m.3 (j)): after a record is durable,
//! a small message `{domain, pos, idx}` tells consumers that the outbox has something past
//! their cursor. It carries no event content, its loss is only delay, and consumers still read
//! the outbox from their own cursor, so polling keeps working without it.
//!
//! - [`proto`]: the NATS protocol, sans I/O.
//! - [`Ring`] and its CBOR payload; [`Gate`] lets a ring out only past the durability fence.
//! - [`client`]: a TLS 1.3 client with a client certificate (no plaintext, no tokens):
//!   [`client::Publisher`] waits for the `JetStream` acknowledgement, [`client::Listener`]
//!   receives rings.
//! - `testing`: an in-process twin of `nats-server` for tests.

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::fence::{Cursor, Fence};

pub mod client;
pub mod proto;
#[cfg(feature = "testing")]
pub mod testing;

/// One ring: the domain whose outbox moved, the position of its last durable event and that
/// event's id (the keyed HMAC the outbox already stores, T26), which is the `JetStream`
/// deduplication key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ring {
    /// The domain.
    pub domain: [u8; 32],
    /// The event's position.
    pub at: Cursor,
    /// The event's id.
    pub id: [u8; 32],
}

/// A payload that is not a ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed doorbell payload")]
pub struct Malformed;

impl Ring {
    /// The payload: deterministic CBOR `{"domain": bstr .size 32, "idx": uint, "pos": uint}`.
    /// The id is not in it; it travels as `Nats-Msg-Id`.
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        let v = Value::Map(alloc::vec![
            (Value::text("domain"), Value::Bytes(self.domain.to_vec())),
            (Value::text("pos"), Value::Unsigned(self.at.pos)),
            (Value::text("idx"), Value::Unsigned(u64::from(self.at.idx))),
        ]);
        dcbor::encode(&v, Limits::CEILING).unwrap_or_default()
    }

    /// The domain and position a payload names.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn read(payload: &[u8]) -> Result<([u8; 32], Cursor), Malformed> {
        let limits = Limits::tightened(1, 3, 32).ok_or(Malformed)?;
        let v = dcbor::decode(payload, limits).map_err(|_| Malformed)?;
        let Value::Map(entries) = &v else {
            return Err(Malformed);
        };
        if entries.len() != 3 {
            return Err(Malformed);
        }
        let domain = match v.get("domain") {
            Some(Value::Bytes(b)) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| Malformed)?,
            _ => return Err(Malformed),
        };
        let pos = match v.get("pos") {
            Some(Value::Unsigned(p)) => *p,
            _ => return Err(Malformed),
        };
        let idx = match v.get("idx") {
            Some(Value::Unsigned(i)) => u32::try_from(*i).map_err(|_| Malformed)?,
            _ => return Err(Malformed),
        };
        Ok((domain, Cursor { pos, idx }))
    }

    /// `Nats-Msg-Id`: the event id in lowercase hex.
    #[must_use]
    pub fn msg_id(&self) -> String {
        hex(&self.id)
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(n)) {
                s.push(char::from(*d));
            }
        }
    }
    s
}

/// Where rings go: one `JetStream` stream over a few partition subjects, not one per domain
/// (§17.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Topic {
    /// The stream name.
    pub stream: &'static str,
    /// The subject prefix; partition `n` is `<prefix>.<n>`.
    pub prefix: &'static str,
    /// How many partitions, 1 to 16.
    pub partitions: u8,
}

impl Topic {
    /// Access's authority doorbell: `ACCESS_DOORBELL` over `access.doorbell.0` … `.7`.
    pub const ACCESS: Self = Self {
        stream: "ACCESS_DOORBELL",
        prefix: "access.doorbell",
        partitions: 8,
    };

    /// The subject of `domain`'s rings.
    #[must_use]
    pub fn subject(&self, domain: &[u8; 32]) -> String {
        let n = self.partitions.clamp(1, 16);
        alloc::format!("{}.{}", self.prefix, domain[0].checked_rem(n).unwrap_or(0))
    }

    /// The filter that covers every partition.
    #[must_use]
    pub fn all(&self) -> String {
        alloc::format!("{}.*", self.prefix)
    }
}

/// Where a writer hands rings after a commit. It must not block or fail the commit: a ring it
/// cannot take is only delay.
pub trait Bell: Send + Sync {
    /// Takes one ring.
    fn ring(&self, ring: Ring);
}

/// The durability gate of a writer's rings (TI-6): a ring leaves only once the fence covers
/// its record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gate {
    fence: Fence,
}

impl Gate {
    /// A gate behind `fence`.
    #[must_use]
    pub const fn new(fence: Fence) -> Self {
        Self { fence }
    }

    /// The fence, for the writer to advance after a durable commit.
    pub const fn fence(&mut self) -> &mut Fence {
        &mut self.fence
    }

    /// Hands `ring` to `bell` if its record is durable; returns whether it did.
    pub fn release(&self, ring: Ring, bell: &dyn Bell) -> bool {
        if self.fence.allows(ring.at.pos) {
            bell.ring(ring);
            true
        } else {
            false
        }
    }
}

/// A `JetStream` publish acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    /// The stream that stored it.
    pub stream: String,
    /// Its sequence there.
    pub seq: u64,
    /// The stream had seen its `Nats-Msg-Id` already.
    pub duplicate: bool,
}

/// What a `JetStream` API answer said instead of success.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("jetstream error {code}: {description}")]
pub struct ApiError {
    /// The `JetStream` error code (`err_code`).
    pub code: u64,
    /// Its description.
    pub description: String,
}

/// Reads a `JetStream` answer: `Ok(value)`, or its `error` member.
///
/// # Errors
/// [`ApiError`]; code 0 for an answer that is not JSON.
pub fn api_answer(payload: &[u8]) -> Result<serde_json::Value, ApiError> {
    let v: serde_json::Value = serde_json::from_slice(payload).map_err(|_| ApiError {
        code: 0,
        description: String::from("not json"),
    })?;
    if let Some(e) = v.get("error") {
        return Err(ApiError {
            code: e
                .get("err_code")
                .or_else(|| e.get("code"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            description: String::from(
                e.get("description")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            ),
        });
    }
    Ok(v)
}

/// Reads a publish acknowledgement.
///
/// # Errors
/// [`ApiError`].
pub fn pub_ack(payload: &[u8]) -> Result<Ack, ApiError> {
    let v = api_answer(payload)?;
    let stream = v.get("stream").and_then(serde_json::Value::as_str);
    let seq = v.get("seq").and_then(serde_json::Value::as_u64);
    match (stream, seq) {
        (Some(stream), Some(seq)) => Ok(Ack {
            stream: String::from(stream),
            seq,
            duplicate: v
                .get("duplicate")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        }),
        _ => Err(ApiError {
            code: 0,
            description: String::from("not a publish acknowledgement"),
        }),
    }
}

#[cfg(test)]
mod tests;
