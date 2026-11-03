//! The identity signer's wire protocol over a Unix domain socket, framed as the authority
//! signer's is: one request, one response, each a big-endian `u32` length and a deterministic
//! CBOR body (CMP-22b, OP-143 m.4, m.9 (e)). Sans-I/O.

use access_crypto::jose::JwsAlg;
use suiss_crypto::dcbor::{self, Limits, Value};

/// Largest frame body.
pub const MAX_FRAME: usize = 1 << 20;

/// A realm, by its identifier's 16 bytes; the signer's key sets are keyed by it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Realm(pub [u8; 16]);

impl core::fmt::Debug for Realm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Realm(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A request to the identity signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Whether the signer answers.
    Ping,
    /// Opens the key set of a realm whose new keys use `alg`; repeating it changes nothing.
    Open {
        /// Realm.
        realm: Realm,
        /// ES256 by default, Ed25519 when the realm selects it (CR-2, MD-3).
        alg: JwsAlg,
    },
    /// The realm's JWKS.
    Jwks(Realm),
    /// Signs a JSON object as a compact JWS of type `typ` at `at`.
    Sign {
        /// Realm.
        realm: Realm,
        /// JWS `typ`.
        typ: String,
        /// JSON payload.
        payload: Vec<u8>,
        /// Signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
}

/// The identity signer's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The signer answers.
    Pong,
    /// The key set is open.
    Opened,
    /// The realm's JWKS document.
    Jwks(String),
    /// A compact JWS.
    Signed {
        /// The token.
        token: String,
        /// Its key's `kid`.
        kid: [u8; 32],
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

fn realm(v: Option<&Value>) -> Result<Realm, FrameError> {
    bytes(v)?
        .try_into()
        .map(Realm)
        .map_err(|_| FrameError::Malformed)
}

/// The algorithm by its JOSE name.
#[must_use]
pub fn alg_of(name: &str) -> Option<JwsAlg> {
    [JwsAlg::Es256, JwsAlg::Ed25519]
        .into_iter()
        .find(|a| a.name() == name)
}

impl Request {
    fn to_value(&self) -> Value {
        match self {
            Self::Ping => map(vec![("ping", Value::Bool(true))]),
            Self::Open { realm, alg } => map(vec![(
                "open",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("alg", Value::text(alg.name())),
                ]),
            )]),
            Self::Jwks(r) => map(vec![("jwks", Value::Bytes(r.0.to_vec()))]),
            Self::Sign {
                realm,
                typ,
                payload,
                at,
            } => map(vec![(
                "sign",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("typ", Value::text(typ)),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, FrameError> {
        if v.get("ping").is_some() {
            return Ok(Self::Ping);
        }
        if let Some(o) = v.get("open") {
            return Ok(Self::Open {
                realm: realm(o.get("realm"))?,
                alg: alg_of(&text(o.get("alg"))?).ok_or(FrameError::Malformed)?,
            });
        }
        if let Some(r) = v.get("jwks") {
            return Ok(Self::Jwks(realm(Some(r))?));
        }
        let s = v.get("sign").ok_or(FrameError::Malformed)?;
        Ok(Self::Sign {
            realm: realm(s.get("realm"))?,
            typ: text(s.get("typ"))?,
            payload: bytes(s.get("payload"))?,
            at: uint(s.get("at"))?,
        })
    }
}

impl Response {
    fn to_value(&self) -> Value {
        match self {
            Self::Pong => map(vec![("pong", Value::Bool(true))]),
            Self::Opened => map(vec![("opened", Value::Bool(true))]),
            Self::Jwks(doc) => map(vec![("jwks", Value::text(doc))]),
            Self::Signed { token, kid } => map(vec![(
                "signed",
                map(vec![
                    ("token", Value::text(token)),
                    ("kid", Value::Bytes(kid.to_vec())),
                ]),
            )]),
            Self::Error(code) => map(vec![("error", Value::text(code))]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, FrameError> {
        if v.get("pong").is_some() {
            return Ok(Self::Pong);
        }
        if v.get("opened").is_some() {
            return Ok(Self::Opened);
        }
        if let Some(d) = v.get("jwks") {
            return Ok(Self::Jwks(text(Some(d))?));
        }
        if let Some(s) = v.get("signed") {
            return Ok(Self::Signed {
                token: text(s.get("token"))?,
                kid: bytes(s.get("kid"))?
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
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
