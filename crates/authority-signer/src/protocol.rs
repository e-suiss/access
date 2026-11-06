//! The signer's wire protocol over a Unix domain socket: one request, one response, each a
//! big-endian `u32` length and a deterministic CBOR body (OP-143 m.4). Sans-I/O.

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::{Hybrid, KeyUsage, SpecVersions, VerifierCaps};
use suiss_crypto::cose::Algorithm;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::domain::Template;

/// Largest frame body.
pub const MAX_FRAME: usize = 1 << 20;

/// A request to the signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Opens the keyring of a domain; repeating it changes nothing.
    Open(Box<Template>),
    /// Signs an artefact of a domain whose signing time is `at`.
    Sign {
        /// Domain.
        domain: Digest,
        /// What the artefact is.
        usage: KeyUsage,
        /// `COSE_Sign1` content type.
        content_type: String,
        /// Payload.
        payload: Vec<u8>,
        /// The artefact's signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
    /// The current Domain Metadata of a domain.
    Metadata(Digest),
    /// Signs a checkpoint body of a domain's log as a C2SP note at `at` (usage `checkpoint`).
    SignNote {
        /// Domain.
        domain: Digest,
        /// Checkpoint body whose origin is the domain's.
        body: String,
        /// The signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
    /// The binding-signed Genesis statement of a domain.
    Genesis(Digest),
    /// Signs an authority-carrying access token of a domain (usage `token`, `typ` `at+jwt`,
    /// §9.9.3 rule 7): `claims` is its JSON claims set, holder-bound by `cnf` (PI-11), with an
    /// `exp` no later than the time the signing key stays published (CR-19).
    SignToken {
        /// Domain.
        domain: Digest,
        /// The JSON claims set.
        claims: Vec<u8>,
        /// The signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
}

/// The signer's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The keyring is open.
    Opened,
    /// An artefact signature.
    Signed {
        /// `COSE_Sign1`.
        sign1: Vec<u8>,
        /// Binding-signed excerpt.
        excerpt: Vec<u8>,
    },
    /// Binding-signed Domain Metadata.
    Metadata(Vec<u8>),
    /// A note signature.
    Noted {
        /// The signature line, newline included.
        line: String,
        /// Binding-signed excerpt.
        excerpt: Vec<u8>,
    },
    /// Binding-signed Genesis statement.
    Genesis(Vec<u8>),
    /// A signed access token.
    Token {
        /// The compact JWS.
        jws: String,
        /// Binding-signed excerpt of the key that signed it.
        excerpt: Vec<u8>,
    },
    /// A refusal, by stable code.
    Error(String),
}

/// Why a frame was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Larger than [`MAX_FRAME`].
    #[error("frame too large")]
    TooLarge,
    /// Not a message of this protocol.
    #[error("malformed frame")]
    Malformed,
}

const USAGES: [(&str, KeyUsage); 8] = [
    ("receipt", KeyUsage::Receipt),
    ("pap", KeyUsage::Pap),
    ("token", KeyUsage::Token),
    ("checkpoint", KeyUsage::Checkpoint),
    ("set", KeyUsage::Set),
    ("status-list", KeyUsage::StatusList),
    ("key-lookup", KeyUsage::KeyLookup),
    ("party-lookup", KeyUsage::PartyLookup),
];

fn usage_name(u: KeyUsage) -> &'static str {
    USAGES
        .iter()
        .find(|(_, x)| *x == u)
        .map_or("receipt", |(n, _)| n)
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn text(v: Option<&Value>) -> Result<String, FrameError> {
    match v {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn bytes(v: Option<&Value>) -> Result<Vec<u8>, FrameError> {
    match v {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn uint(v: Option<&Value>) -> Result<u64, FrameError> {
    match v {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(FrameError::Malformed),
    }
}

fn digest(v: Option<&Value>) -> Result<Digest, FrameError> {
    v.and_then(Digest::from_value).ok_or(FrameError::Malformed)
}

const HYBRIDS: [(&str, Hybrid); 3] = [
    ("classic", Hybrid::Classic),
    ("both", Hybrid::Both),
    ("pq", Hybrid::Pq),
];

/// The template as a request carries it.
fn template_value(t: &Template) -> Value {
    let mut entries = vec![
        ("domain", t.domain.to_value()),
        ("genesis", t.genesis.to_value()),
        (
            "algorithms",
            Value::Array(t.algorithms.iter().map(|a| Value::int(a.cose())).collect()),
        ),
        ("alg", Value::int(t.operational_alg.cose())),
        (
            "operational_window_max_ms",
            Value::Unsigned(t.operational_window_max_ms),
        ),
        ("min_versions", t.min_versions.to_value()),
        ("adopted", t.adopted.to_value()),
    ];
    if let Some(c) = &t.caps {
        entries.push(("caps", c.to_value()));
    }
    if let Some(h) = t.hybrid
        && let Some((n, _)) = HYBRIDS.iter().find(|(_, x)| *x == h)
    {
        entries.push(("hybrid", Value::text(n)));
    }
    if let Some(d) = &t.discovery {
        entries.push(("discovery", Value::Bytes(d.clone())));
    }
    map(entries)
}

fn alg(v: &Value) -> Result<Algorithm, FrameError> {
    v.as_i64()
        .and_then(Algorithm::from_cose)
        .ok_or(FrameError::Malformed)
}

fn template_of(v: &Value) -> Result<Template, FrameError> {
    let field = |k: &str| v.get(k).ok_or(FrameError::Malformed);
    let Value::Array(algs) = field("algorithms")? else {
        return Err(FrameError::Malformed);
    };
    let versions = |k: &str| SpecVersions::from_value(field(k)?).map_err(|_| FrameError::Malformed);
    Ok(Template {
        domain: digest(v.get("domain"))?,
        genesis: digest(v.get("genesis"))?,
        algorithms: algs.iter().map(alg).collect::<Result<_, _>>()?,
        operational_alg: alg(field("alg")?)?,
        operational_window_max_ms: match field("operational_window_max_ms")? {
            Value::Unsigned(n) => *n,
            _ => return Err(FrameError::Malformed),
        },
        min_versions: versions("min_versions")?,
        adopted: versions("adopted")?,
        caps: v
            .get("caps")
            .map(|c| VerifierCaps::from_value(c).map_err(|_| FrameError::Malformed))
            .transpose()?,
        hybrid: match v.get("hybrid") {
            None => None,
            Some(Value::Text(t)) => Some(
                HYBRIDS
                    .iter()
                    .find(|(n, _)| n == t)
                    .map(|(_, h)| *h)
                    .ok_or(FrameError::Malformed)?,
            ),
            Some(_) => return Err(FrameError::Malformed),
        },
        discovery: v.get("discovery").map(|d| bytes(Some(d))).transpose()?,
    })
}

impl Request {
    fn to_value(&self) -> Value {
        match self {
            Self::Open(t) => map(vec![("open", template_value(t))]),
            Self::Sign {
                domain,
                usage,
                content_type,
                payload,
                at,
            } => map(vec![(
                "sign",
                map(vec![
                    ("domain", domain.to_value()),
                    ("usage", Value::text(usage_name(*usage))),
                    ("content_type", Value::text(content_type)),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::Metadata(d) => map(vec![("metadata", d.to_value())]),
            Self::SignNote { domain, body, at } => map(vec![(
                "sign_note",
                map(vec![
                    ("domain", domain.to_value()),
                    ("body", Value::text(body)),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::Genesis(d) => map(vec![("genesis", d.to_value())]),
            Self::SignToken { domain, claims, at } => map(vec![(
                "sign_token",
                map(vec![
                    ("domain", domain.to_value()),
                    ("claims", Value::Bytes(claims.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, FrameError> {
        if let Some(s) = v.get("sign_token") {
            return Ok(Self::SignToken {
                domain: digest(s.get("domain"))?,
                claims: bytes(s.get("claims"))?,
                at: uint(s.get("at"))?,
            });
        }
        if let Some(t) = v.get("open") {
            return Ok(Self::Open(Box::new(template_of(t)?)));
        }
        if let Some(d) = v.get("metadata") {
            return Ok(Self::Metadata(digest(Some(d))?));
        }
        if let Some(d) = v.get("genesis") {
            return Ok(Self::Genesis(digest(Some(d))?));
        }
        if let Some(s) = v.get("sign_note") {
            return Ok(Self::SignNote {
                domain: digest(s.get("domain"))?,
                body: text(s.get("body"))?,
                at: uint(s.get("at"))?,
            });
        }
        let s = v.get("sign").ok_or(FrameError::Malformed)?;
        let usage = text(s.get("usage"))?;
        Ok(Self::Sign {
            domain: digest(s.get("domain"))?,
            usage: USAGES
                .iter()
                .find(|(n, _)| *n == usage)
                .map(|(_, u)| *u)
                .ok_or(FrameError::Malformed)?,
            content_type: text(s.get("content_type"))?,
            payload: bytes(s.get("payload"))?,
            at: uint(s.get("at"))?,
        })
    }
}

impl Response {
    fn to_value(&self) -> Value {
        match self {
            Self::Opened => map(vec![("opened", Value::Bool(true))]),
            Self::Signed { sign1, excerpt } => map(vec![(
                "signed",
                map(vec![
                    ("sign1", Value::Bytes(sign1.clone())),
                    ("excerpt", Value::Bytes(excerpt.clone())),
                ]),
            )]),
            Self::Metadata(b) => map(vec![("metadata", Value::Bytes(b.clone()))]),
            Self::Noted { line, excerpt } => map(vec![(
                "noted",
                map(vec![
                    ("line", Value::text(line)),
                    ("excerpt", Value::Bytes(excerpt.clone())),
                ]),
            )]),
            Self::Genesis(b) => map(vec![("genesis", Value::Bytes(b.clone()))]),
            Self::Token { jws, excerpt } => map(vec![(
                "token",
                map(vec![
                    ("jws", Value::text(jws)),
                    ("excerpt", Value::Bytes(excerpt.clone())),
                ]),
            )]),
            Self::Error(code) => map(vec![("error", Value::text(code))]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, FrameError> {
        if v.get("opened").is_some() {
            return Ok(Self::Opened);
        }
        if let Some(s) = v.get("signed") {
            return Ok(Self::Signed {
                sign1: bytes(s.get("sign1"))?,
                excerpt: bytes(s.get("excerpt"))?,
            });
        }
        if let Some(m) = v.get("metadata") {
            return Ok(Self::Metadata(bytes(Some(m))?));
        }
        if let Some(n) = v.get("noted") {
            return Ok(Self::Noted {
                line: text(n.get("line"))?,
                excerpt: bytes(n.get("excerpt"))?,
            });
        }
        if let Some(g) = v.get("genesis") {
            return Ok(Self::Genesis(bytes(Some(g))?));
        }
        if let Some(t) = v.get("token") {
            return Ok(Self::Token {
                jws: text(t.get("jws"))?,
                excerpt: bytes(t.get("excerpt"))?,
            });
        }
        Ok(Self::Error(text(v.get("error"))?))
    }
}

fn frame(v: &Value) -> Result<Vec<u8>, FrameError> {
    let body = dcbor::encode(v, Limits::CEILING).map_err(|_| FrameError::Malformed)?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    let mut out = len.to_be_bytes().to_vec();
    out.extend(body);
    Ok(out)
}

/// The length a frame header announces.
///
/// # Errors
/// [`FrameError::TooLarge`].
pub fn frame_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = usize::try_from(u32::from_be_bytes(header)).map_err(|_| FrameError::TooLarge)?;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    Ok(len)
}

fn body(bytes: &[u8]) -> Result<Value, FrameError> {
    dcbor::decode(bytes, Limits::CEILING).map_err(|_| FrameError::Malformed)
}

/// A request as a frame.
///
/// # Errors
/// [`FrameError`].
pub fn encode_request(r: &Request) -> Result<Vec<u8>, FrameError> {
    frame(&r.to_value())
}

/// A request from a frame body (after its header).
///
/// # Errors
/// [`FrameError::Malformed`].
pub fn decode_request(b: &[u8]) -> Result<Request, FrameError> {
    Request::from_value(&body(b)?)
}

/// A response as a frame.
///
/// # Errors
/// [`FrameError`].
pub fn encode_response(r: &Response) -> Result<Vec<u8>, FrameError> {
    frame(&r.to_value())
}

/// A response from a frame body (after its header).
///
/// # Errors
/// [`FrameError::Malformed`].
pub fn decode_response(b: &[u8]) -> Result<Response, FrameError> {
    Response::from_value(&body(b)?)
}

#[cfg(test)]
mod tests;
