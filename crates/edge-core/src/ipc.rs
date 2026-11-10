//! The parser worker's wire (OP-155 m.3 (c), MD-18, U43): one request, one reply, each a
//! deterministic CBOR header and a raw byte segment, both length-prefixed with a big-endian
//! `u32`. The header names the operation or the outcome; the segment carries the untrusted
//! document or the parsed result, which can exceed the CBOR profile's string ceiling. Sans-I/O.

use suiss_crypto::dcbor::{self, Limits, Value};

/// Largest header.
pub const MAX_HEADER: usize = 4 * 1024;

/// Largest segment: one document of the largest kind (XML, 1 MB inflated) with room.
pub const MAX_SEGMENT: usize = 1024 * 1024;

/// Largest frame on the wire.
pub const MAX_FRAME: usize = 8 + MAX_HEADER + MAX_SEGMENT;

/// What the worker is asked to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// Checks an XML document against the parser limits and returns it.
    XmlCheck,
    /// Inflates a raw DEFLATE stream (HTTP-Redirect binding), then [`Op::XmlCheck`].
    XmlInflate,
    /// Checks a DER element tree against the parser limits and returns it.
    DerCheck,
    /// Makes the worker abort, as a memory-corruption crash would (U43 test hook; a release
    /// worker refuses it).
    Abort,
    /// Reads an ETSI TS 119 612 trusted list into its CBOR summary (OP-155 m.3 (p)); the
    /// segment of the reply is the summary.
    TlRead,
    /// Reads a SAML request and verifies its enveloped signature (`crate::saml::Context`, then
    /// the message); answers `crate::saml::Facts` (§10.6.1, IDI-8).
    SamlRequest,
    /// Verifies a detached HTTP-Redirect signature (`crate::saml::Redirect`).
    SamlRedirect,
    /// Reads a Kerberos `Negotiate` token (SPNEGO or a raw Kerberos initial context token) into
    /// its [`crate::spnego::Token`] (OP-155 m.3 (o)); the segment of the reply is the summary.
    SpnegoRead,
}

const OPS: [(&str, Op); 8] = [
    ("xml.check", Op::XmlCheck),
    ("xml.inflate", Op::XmlInflate),
    ("der.check", Op::DerCheck),
    ("test.abort", Op::Abort),
    ("tl.read", Op::TlRead),
    ("saml.request", Op::SamlRequest),
    ("saml.redirect", Op::SamlRedirect),
    ("spnego.read", Op::SpnegoRead),
];

impl Op {
    /// The operation's name on the wire.
    #[must_use]
    pub fn name(self) -> &'static str {
        OPS.iter().find(|(_, o)| *o == self).map_or("", |(n, _)| n)
    }

    /// The operation named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        OPS.iter().find(|(n, _)| *n == name).map(|(_, o)| *o)
    }
}

/// One request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The operation.
    pub op: Op,
    /// The untrusted input.
    pub input: Vec<u8>,
}

/// What the parser found in an accepted document.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Elements read.
    pub elements: u64,
    /// Deepest nesting.
    pub depth: u64,
    /// Local name of the XML root element; empty for DER.
    pub root: String,
}

/// One reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Accepted; `output` is the checked (for [`Op::XmlInflate`], inflated) document.
    Ok {
        /// What was found.
        summary: Summary,
        /// The document.
        output: Vec<u8>,
    },
    /// Refused by a limit or as malformed, by stable code; the worker is recycled.
    Refused(String),
    /// The worker crashed, overran a limit or answered outside the protocol; it was replaced
    /// (U43).
    WorkerFailed,
}

/// Stable code of [`Reply::WorkerFailed`].
pub const WORKER_FAILED: &str = "worker-failed";

/// Why a frame was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// A length is above its ceiling.
    #[error("frame too large")]
    TooLarge,
    /// The frame ended early.
    #[error("truncated frame")]
    Truncated,
    /// Not a frame of this protocol.
    #[error("malformed frame")]
    Malformed,
}

fn put(out: &mut Vec<u8>, part: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(part.len()).map_err(|_| FrameError::TooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(part);
    Ok(())
}

fn frame(header: &Value, segment: &[u8]) -> Result<Vec<u8>, FrameError> {
    let header = dcbor::encode(header, Limits::CEILING).map_err(|_| FrameError::Malformed)?;
    if header.len() > MAX_HEADER || segment.len() > MAX_SEGMENT {
        return Err(FrameError::TooLarge);
    }
    let mut out = Vec::new();
    put(&mut out, &header)?;
    put(&mut out, segment)?;
    Ok(out)
}

/// Reads one length prefix and checks it against `max` before anything is allocated.
///
/// # Errors
/// [`FrameError::TooLarge`].
pub fn length(prefix: [u8; 4], max: usize) -> Result<usize, FrameError> {
    let n = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| FrameError::TooLarge)?;
    if n > max {
        return Err(FrameError::TooLarge);
    }
    Ok(n)
}

fn take(input: &[u8], max: usize) -> Result<(&[u8], &[u8]), FrameError> {
    let (prefix, rest) = input
        .split_first_chunk::<4>()
        .ok_or(FrameError::Truncated)?;
    let n = length(*prefix, max)?;
    if rest.len() < n {
        return Err(FrameError::Truncated);
    }
    Ok(rest.split_at(n))
}

fn split(input: &[u8]) -> Result<(Value, &[u8]), FrameError> {
    let (header, rest) = take(input, MAX_HEADER)?;
    let (segment, rest) = take(rest, MAX_SEGMENT)?;
    if !rest.is_empty() {
        return Err(FrameError::Malformed);
    }
    let header = dcbor::decode(header, Limits::CEILING).map_err(|_| FrameError::Malformed)?;
    Ok((header, segment))
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn only(v: &Value, keys: &[&str]) -> Result<(), FrameError> {
    let Value::Map(entries) = v else {
        return Err(FrameError::Malformed);
    };
    if entries
        .iter()
        .all(|(k, _)| matches!(k, Value::Text(t) if keys.contains(&t.as_str())))
    {
        Ok(())
    } else {
        Err(FrameError::Malformed)
    }
}

fn text(v: &Value, key: &str) -> Result<String, FrameError> {
    match v.get(key) {
        Some(Value::Text(t)) => Ok(t.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn uint(v: &Value, key: &str) -> Result<u64, FrameError> {
    match v.get(key) {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(FrameError::Malformed),
    }
}

impl Request {
    /// The request frame.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`] for an input above [`MAX_SEGMENT`].
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        frame(&map(vec![("op", Value::text(self.op.name()))]), &self.input)
    }

    /// Reads a request frame.
    ///
    /// # Errors
    /// [`FrameError`].
    pub fn decode(input: &[u8]) -> Result<Self, FrameError> {
        let (header, segment) = split(input)?;
        only(&header, &["op"])?;
        Ok(Self {
            op: Op::parse(&text(&header, "op")?).ok_or(FrameError::Malformed)?,
            input: segment.to_vec(),
        })
    }
}

impl Reply {
    /// The reply frame.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`] for an output above [`MAX_SEGMENT`].
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        match self {
            Self::Ok { summary, output } => frame(
                &map(vec![
                    ("status", Value::text("ok")),
                    ("elements", Value::Unsigned(summary.elements)),
                    ("depth", Value::Unsigned(summary.depth)),
                    ("root", Value::text(&summary.root)),
                ]),
                output,
            ),
            Self::Refused(code) => frame(
                &map(vec![
                    ("status", Value::text("refused")),
                    ("code", Value::text(code)),
                ]),
                &[],
            ),
            Self::WorkerFailed => frame(&map(vec![("status", Value::text(WORKER_FAILED))]), &[]),
        }
    }

    /// Reads a reply frame.
    ///
    /// # Errors
    /// [`FrameError`].
    pub fn decode(input: &[u8]) -> Result<Self, FrameError> {
        let (header, segment) = split(input)?;
        match text(&header, "status")?.as_str() {
            "ok" => {
                only(&header, &["status", "elements", "depth", "root"])?;
                Ok(Self::Ok {
                    summary: Summary {
                        elements: uint(&header, "elements")?,
                        depth: uint(&header, "depth")?,
                        root: text(&header, "root")?,
                    },
                    output: segment.to_vec(),
                })
            }
            "refused" => {
                only(&header, &["status", "code"])?;
                Ok(Self::Refused(text(&header, "code")?))
            }
            WORKER_FAILED => {
                only(&header, &["status"])?;
                Ok(Self::WorkerFailed)
            }
            _ => Err(FrameError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (c)
    #[test]
    fn frames_round_trip() {
        let r = Request {
            op: Op::XmlCheck,
            input: b"<a/>".to_vec(),
        };
        assert_eq!(Request::decode(&r.encode().unwrap()).unwrap(), r);
        for reply in [
            Reply::Ok {
                summary: Summary {
                    elements: 1,
                    depth: 1,
                    root: String::from("a"),
                },
                output: b"<a/>".to_vec(),
            },
            Reply::Refused(String::from("xml-doctype")),
            Reply::WorkerFailed,
        ] {
            assert_eq!(Reply::decode(&reply.encode().unwrap()).unwrap(), reply);
        }
    }

    // OP-155 m.3 (c), OP-125
    #[test]
    fn lengths_are_checked_before_allocation() {
        assert_eq!(
            length(u32::MAX.to_be_bytes(), MAX_SEGMENT),
            Err(FrameError::TooLarge)
        );
        let big = Request {
            op: Op::XmlCheck,
            input: vec![b' '; MAX_SEGMENT + 1],
        };
        assert_eq!(big.encode(), Err(FrameError::TooLarge));
        assert_eq!(Request::decode(&[]), Err(FrameError::Truncated));
        assert_eq!(
            Request::decode(&[0, 0, 0, 9, 1]),
            Err(FrameError::Truncated)
        );
        let ok = Request {
            op: Op::DerCheck,
            input: vec![0x30, 0],
        }
        .encode()
        .unwrap();
        let mut trailing = ok.clone();
        trailing.push(0);
        assert_eq!(Request::decode(&trailing), Err(FrameError::Malformed));
    }
}
