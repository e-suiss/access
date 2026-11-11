//! The Replica Mirror wire (`mirror.cddl`, T21, CMP-21, TI-13, OP-158 m.3 (f)): the frames a
//! log streams to a replica as a CBOR sequence (RFC 8742), and the signed acknowledgement a
//! replica answers once it holds a checkpoint's whole prefix durably.

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, TagAllowlist, Value};
use suiss_crypto::sig::{Backend, ed25519};

use crate::Hash;

/// Longest record envelope or body a frame carries.
pub const MAX_RECORD: usize = 1_048_576;

/// Longest checkpoint note.
pub const MAX_NOTE: usize = 65_536;

/// Longest cosignature line.
pub const MAX_COSIGNATURE: usize = 1_024;

/// Longest key excerpt a checkpoint frame carries.
pub const MAX_EXCERPT: usize = 65_536;

/// Most cosignatures one checkpoint frame carries.
pub const MAX_COSIGNATURES: usize = 64;

/// Longest replica name.
pub const MAX_NAME: usize = 255;

/// Digest context naming the body a redaction destroys (U22, OP-158 m.3 (f)).
pub const REDACTION_CONTEXT: &str = "access/redaction/v1";

/// Why a mirror frame or acknowledgement is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed mirror message")]
pub struct WireError;

/// One frame of the mirror stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// The record at `position`: its envelope and, when kept apart, its body.
    Record {
        /// Log position.
        position: u64,
        /// The record envelope.
        envelope: Vec<u8>,
        /// The body, when the log keeps it apart from the envelope.
        body: Option<Vec<u8>>,
    },
    /// A signed checkpoint, the witness cosignatures it has so far, and the key excerpt of
    /// the key that signed it.
    Checkpoint {
        /// The C2SP signed note.
        note: String,
        /// `tlog-cosignature/v1` lines.
        cosignatures: Vec<Vec<u8>>,
        /// The binding-signed excerpt of the signing key (CR-58 m.1).
        excerpt: Option<Vec<u8>>,
    },
    /// The body of the record at `position`, named by its redaction digest, was destroyed at
    /// the source; the replica may apply it to its copy (U22, N-11).
    Redaction {
        /// Log position.
        position: u64,
        /// [`redaction_digest`] of the destroyed body.
        dek: Hash,
    },
    /// Nothing new up to `size` at `at`.
    Heartbeat {
        /// The log size.
        size: u64,
        /// Unix milliseconds.
        at: u64,
    },
}

/// The digest a redaction names the body by (U22).
#[must_use]
pub fn redaction_digest(body: &[u8]) -> Hash {
    suiss_crypto::digest::context_digest(REDACTION_CONTEXT, body).0
}

fn map(entries: Vec<(&str, Option<Value>)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (Value::text(k), v)))
            .collect(),
    )
}

fn only(v: &Value, allowed: &[&str]) -> Result<(), WireError> {
    let Value::Map(entries) = v else {
        return Err(WireError);
    };
    let known = entries
        .iter()
        .all(|(k, _)| matches!(k, Value::Text(t) if allowed.contains(&t.as_str())));
    if known { Ok(()) } else { Err(WireError) }
}

fn uint(v: Option<&Value>) -> Result<u64, WireError> {
    match v {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(WireError),
    }
}

fn bytes(v: Option<&Value>, max: usize) -> Result<Vec<u8>, WireError> {
    match v {
        Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= max => Ok(b.clone()),
        _ => Err(WireError),
    }
}

fn text(v: Option<&Value>, max: usize) -> Result<String, WireError> {
    match v {
        Some(Value::Text(t)) if !t.is_empty() && t.len() <= max => Ok(t.clone()),
        _ => Err(WireError),
    }
}

fn hash(v: Option<&Value>) -> Result<Hash, WireError> {
    match v {
        Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| WireError),
        _ => Err(WireError),
    }
}

fn single(v: &Value) -> Result<(&str, &Value), WireError> {
    match v {
        Value::Map(entries) if entries.len() == 1 => match entries.first() {
            Some((Value::Text(k), inner)) => Ok((k.as_str(), inner)),
            _ => Err(WireError),
        },
        _ => Err(WireError),
    }
}

impl Frame {
    /// The frame as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let (name, inner) = match self {
            Self::Record {
                position,
                envelope,
                body,
            } => (
                "record",
                map(alloc::vec![
                    ("position", Some(Value::Unsigned(*position))),
                    ("envelope", Some(Value::Bytes(envelope.clone()))),
                    ("body", body.clone().map(Value::Bytes)),
                ]),
            ),
            Self::Checkpoint {
                note,
                cosignatures,
                excerpt,
            } => (
                "checkpoint",
                map(alloc::vec![
                    ("note", Some(Value::text(note))),
                    (
                        "cosignatures",
                        Some(Value::Array(
                            cosignatures.iter().cloned().map(Value::Bytes).collect(),
                        )),
                    ),
                    ("excerpt", excerpt.clone().map(Value::Bytes)),
                ]),
            ),
            Self::Redaction { position, dek } => (
                "redaction",
                map(alloc::vec![
                    ("position", Some(Value::Unsigned(*position))),
                    ("dek", Some(Value::Bytes(dek.to_vec()))),
                ]),
            ),
            Self::Heartbeat { size, at } => (
                "heartbeat",
                map(alloc::vec![
                    ("size", Some(Value::Unsigned(*size))),
                    ("at", Some(Value::Unsigned(*at))),
                ]),
            ),
        };
        Value::Map(alloc::vec![(Value::text(name), inner)])
    }

    /// The frame's deterministic CBOR bytes.
    ///
    /// # Errors
    /// [`WireError`] for a frame outside the CBOR profile.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        dcbor::encode(&self.to_value(), Limits::CEILING).map_err(|_| WireError)
    }

    /// A frame from its CBOR value.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_value(v: &Value) -> Result<Self, WireError> {
        let (name, inner) = single(v)?;
        match name {
            "record" => {
                only(inner, &["position", "envelope", "body"])?;
                Ok(Self::Record {
                    position: uint(inner.get("position"))?,
                    envelope: bytes(inner.get("envelope"), MAX_RECORD)?,
                    body: inner
                        .get("body")
                        .map(|b| bytes(Some(b), MAX_RECORD))
                        .transpose()?,
                })
            }
            "checkpoint" => {
                only(inner, &["note", "cosignatures", "excerpt"])?;
                let Some(Value::Array(lines)) = inner.get("cosignatures") else {
                    return Err(WireError);
                };
                if lines.len() > MAX_COSIGNATURES {
                    return Err(WireError);
                }
                Ok(Self::Checkpoint {
                    note: text(inner.get("note"), MAX_NOTE)?,
                    cosignatures: lines
                        .iter()
                        .map(|l| bytes(Some(l), MAX_COSIGNATURE))
                        .collect::<Result<_, _>>()?,
                    excerpt: inner
                        .get("excerpt")
                        .map(|e| bytes(Some(e), MAX_EXCERPT))
                        .transpose()?,
                })
            }
            "redaction" => {
                only(inner, &["position", "dek"])?;
                Ok(Self::Redaction {
                    position: uint(inner.get("position"))?,
                    dek: hash(inner.get("dek"))?,
                })
            }
            "heartbeat" => {
                only(inner, &["size", "at"])?;
                Ok(Self::Heartbeat {
                    size: uint(inner.get("size"))?,
                    at: uint(inner.get("at"))?,
                })
            }
            _ => Err(WireError),
        }
    }

    /// The first frame of `input` and the bytes it took: the next item of a CBOR sequence.
    ///
    /// # Errors
    /// [`WireError`]; a frame cut short is an error too, so a reader keeps the rest for the
    /// next read only when it knows more bytes follow.
    pub fn read(input: &[u8]) -> Result<(Self, usize), WireError> {
        let (v, used) = dcbor::decode_prefix(input, Limits::CEILING, &TagAllowlist::none())
            .map_err(|_| WireError)?;
        Ok((Self::from_value(&v)?, used))
    }
}

/// Every frame of a whole CBOR sequence.
///
/// # Errors
/// [`WireError`] at the first malformed frame.
pub fn read_all(mut input: &[u8]) -> Result<Vec<Frame>, WireError> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (f, used) = Frame::read(input)?;
        out.push(f);
        input = input.get(used..).ok_or(WireError)?;
    }
    Ok(out)
}

/// What a replica says it holds (`replica-ack`): the whole prefix of `domain`'s log up to
/// `size`, whose root is `root`, at `at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaAck {
    /// `DomainID`.
    pub domain: Hash,
    /// The replica's declared name.
    pub replica: String,
    /// Records held.
    pub size: u64,
    /// RFC 9162 root over them.
    pub root: Hash,
    /// Unix milliseconds.
    pub at: u64,
}

impl ReplicaAck {
    fn to_value(&self) -> Value {
        map(alloc::vec![
            ("domain", Some(Value::Bytes(self.domain.to_vec()))),
            ("replica", Some(Value::text(&self.replica))),
            ("size", Some(Value::Unsigned(self.size))),
            ("root", Some(Value::Bytes(self.root.to_vec()))),
            ("at", Some(Value::Unsigned(self.at))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        only(v, &["domain", "replica", "size", "root", "at"])?;
        let size = uint(v.get("size"))?;
        if size == 0 {
            return Err(WireError);
        }
        Ok(Self {
            domain: hash(v.get("domain"))?,
            replica: text(v.get("replica"), MAX_NAME)?,
            size,
            root: hash(v.get("root"))?,
            at: uint(v.get("at"))?,
        })
    }

    /// The bytes the replica signs: the ack's deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn message(&self) -> Result<Vec<u8>, WireError> {
        dcbor::encode(&self.to_value(), Limits::CEILING).map_err(|_| WireError)
    }
}

/// A [`ReplicaAck`] with the replica's Ed25519 signature over [`ReplicaAck::message`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReplicaAck {
    /// The acknowledgement.
    pub ack: ReplicaAck,
    /// The signature.
    pub sig: [u8; 64],
}

impl SignedReplicaAck {
    /// The deterministic CBOR bytes (`signed-replica-ack`).
    ///
    /// # Errors
    /// [`WireError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        let v = map(alloc::vec![
            ("ack", Some(self.ack.to_value())),
            ("sig", Some(Value::Bytes(self.sig.to_vec()))),
        ]);
        dcbor::encode(&v, Limits::CEILING).map_err(|_| WireError)
    }

    /// Parses `signed-replica-ack` bytes; the signature is not checked.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, WireError> {
        let v = dcbor::decode(input, Limits::CEILING).map_err(|_| WireError)?;
        only(&v, &["ack", "sig"])?;
        let ack = ReplicaAck::from_value(v.get("ack").ok_or(WireError)?)?;
        let sig = match v.get("sig") {
            Some(Value::Bytes(b)) => <[u8; 64]>::try_from(b.as_slice()).map_err(|_| WireError)?,
            _ => return Err(WireError),
        };
        Ok(Self { ack, sig })
    }

    /// Whether the signature verifies under the replica's declared Ed25519 key `key`.
    ///
    /// # Errors
    /// [`WireError`] when it does not.
    pub fn verify(&self, backend: &impl Backend, key: &[u8; 32]) -> Result<(), WireError> {
        let message = self.ack.message()?;
        ed25519(backend, key, &message, &self.sig).map_err(|_| WireError)
    }
}

#[cfg(test)]
mod tests;
