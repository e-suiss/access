//! The two binding-signed statements of a handover batch (`handover.cddl`, §16.6 HO-6,
//! §16.6.1 RB-4, OP-158 m.3 (l)): the outgoing binding's no-write statement and the incoming
//! binding's continuation statement. Both cite `C_k`, so the old and the new binding are bound
//! to the same checkpoint and the change is double-signed.

use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::BindingKey;
use suiss_crypto::cose::{KeySet, verify_sign1};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::sig::Backend;

/// `COSE_Sign1` content type of a no-write statement.
pub const NO_WRITE: &str = "application/access-no-write+cbor";

/// `COSE_Sign1` content type of a continuation statement.
pub const CONTINUATION: &str = "application/access-continuation+cbor";

/// The only payloads a binding key signs besides metadata, excerpts and the Genesis statement.
pub const STATEMENTS: [&str; 2] = [NO_WRITE, CONTINUATION];

/// Longest provider name.
pub const MAX_PROVIDER: usize = 255;

/// Why a statement is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StatementError {
    /// Not a statement of this kind, or a field out of range.
    #[error("malformed")]
    Malformed,
    /// Not signed by the expected binding key.
    #[error("signature")]
    Signature,
}

/// A checkpoint by size and root.
pub type Cited = (u64, [u8; 32]);

/// The outgoing provider wrote nothing after `C_k` and froze the domain at `frozen_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoWrite {
    /// The domain.
    pub domain: Digest,
    /// The outgoing provider.
    pub provider: String,
    /// `C_k`.
    pub last: Cited,
    /// The freeze (Unix ms).
    pub frozen_at: u64,
    /// Signing time (Unix ms).
    pub at: u64,
}

/// The incoming provider folded the export up to `C_k`, reproduced its root and passed the
/// provider conformance profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation {
    /// The domain.
    pub domain: Digest,
    /// The incoming provider.
    pub provider: String,
    /// `C_k`.
    pub from: Cited,
    /// Digest of the passing conformance profile run.
    pub conformance: Digest,
    /// Signing time (Unix ms).
    pub at: u64,
}

fn cited(c: Cited) -> Value {
    Value::Map(vec![
        (Value::text("root"), Value::Bytes(c.1.to_vec())),
        (Value::text("size"), Value::Unsigned(c.0)),
    ])
}

fn entries(e: Vec<(&str, Value)>) -> Value {
    let mut e: Vec<(Value, Value)> = e.into_iter().map(|(k, v)| (Value::text(k), v)).collect();
    e.sort_by(|a, b| {
        dcbor::encode(&a.0, Limits::CEILING)
            .unwrap_or_default()
            .cmp(&dcbor::encode(&b.0, Limits::CEILING).unwrap_or_default())
    });
    Value::Map(e)
}

fn fields<'a>(v: &'a Value, names: &[&str]) -> Result<Vec<&'a Value>, StatementError> {
    let Value::Map(m) = v else {
        return Err(StatementError::Malformed);
    };
    if m.len() != names.len() {
        return Err(StatementError::Malformed);
    }
    names
        .iter()
        .map(|n| v.get(n).ok_or(StatementError::Malformed))
        .collect()
}

fn uint(v: &Value) -> Result<u64, StatementError> {
    match v {
        Value::Unsigned(n) => Ok(*n),
        _ => Err(StatementError::Malformed),
    }
}

fn digest(v: &Value) -> Result<Digest, StatementError> {
    Digest::from_value(v).ok_or(StatementError::Malformed)
}

fn provider(v: &Value) -> Result<String, StatementError> {
    match v {
        Value::Text(t) if !t.is_empty() && t.len() <= MAX_PROVIDER => Ok(t.clone()),
        _ => Err(StatementError::Malformed),
    }
}

fn cited_of(v: &Value) -> Result<Cited, StatementError> {
    let f = fields(v, &["size", "root"])?;
    let root = match f.get(1) {
        Some(Value::Bytes(b)) => <[u8; 32]>::try_from(b.as_slice()).ok(),
        _ => None,
    }
    .ok_or(StatementError::Malformed)?;
    Ok((uint(f.first().ok_or(StatementError::Malformed)?)?, root))
}

fn encode(v: &Value) -> Result<Vec<u8>, StatementError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| StatementError::Malformed)
}

fn decode(b: &[u8]) -> Result<Value, StatementError> {
    dcbor::decode(b, Limits::CEILING).map_err(|_| StatementError::Malformed)
}

fn at<'a>(f: &'a [&'a Value], i: usize) -> Result<&'a Value, StatementError> {
    f.get(i).copied().ok_or(StatementError::Malformed)
}

impl NoWrite {
    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`StatementError::Malformed`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, StatementError> {
        encode(&entries(vec![
            ("domain", self.domain.to_value()),
            ("provider", Value::text(&self.provider)),
            ("last", cited(self.last)),
            ("frozen_at", Value::Unsigned(self.frozen_at)),
            ("at", Value::Unsigned(self.at)),
        ]))
    }

    /// Decodes one.
    ///
    /// # Errors
    /// [`StatementError::Malformed`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, StatementError> {
        let v = decode(b)?;
        let f = fields(&v, &["domain", "provider", "last", "frozen_at", "at"])?;
        Ok(Self {
            domain: digest(at(&f, 0)?)?,
            provider: provider(at(&f, 1)?)?,
            last: cited_of(at(&f, 2)?)?,
            frozen_at: uint(at(&f, 3)?)?,
            at: uint(at(&f, 4)?)?,
        })
    }
}

impl Continuation {
    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`StatementError::Malformed`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, StatementError> {
        encode(&entries(vec![
            ("domain", self.domain.to_value()),
            ("provider", Value::text(&self.provider)),
            ("from", cited(self.from)),
            ("conformance", self.conformance.to_value()),
            ("at", Value::Unsigned(self.at)),
        ]))
    }

    /// Decodes one.
    ///
    /// # Errors
    /// [`StatementError::Malformed`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, StatementError> {
        let v = decode(b)?;
        let f = fields(&v, &["domain", "provider", "from", "conformance", "at"])?;
        Ok(Self {
            domain: digest(at(&f, 0)?)?,
            provider: provider(at(&f, 1)?)?,
            from: cited_of(at(&f, 2)?)?,
            conformance: digest(at(&f, 3)?)?,
            at: uint(at(&f, 4)?)?,
        })
    }
}

/// The content type of a statement's `COSE_Sign1`, if it is one of [`STATEMENTS`].
#[must_use]
pub fn kind_of(sign1: &[u8]) -> Option<&'static str> {
    let parsed = suiss_crypto::cose::parse_sign1(sign1).ok()?;
    let Ok(Value::Map(header)) = dcbor::decode(&parsed.protected, Limits::CEILING) else {
        return None;
    };
    let ct = header.iter().find_map(|(k, v)| match (k, v) {
        (Value::Unsigned(3), Value::Text(t)) => Some(t.as_str()),
        _ => None,
    })?;
    STATEMENTS.into_iter().find(|s| *s == ct)
}

/// Verifies `sign1` as a statement of `content_type` signed by one of `keys`; its payload and
/// the signing key's `kid`.
///
/// # Errors
/// [`StatementError`].
pub fn verify(
    backend: &impl Backend,
    sign1: &[u8],
    keys: &[BindingKey],
    content_type: &str,
) -> Result<(Vec<u8>, [u8; 32]), StatementError> {
    let mut set = KeySet::default();
    for k in keys {
        set.allowed.insert(k.alg);
        set.insert(k.kid, k.key.clone())
            .map_err(|_| StatementError::Signature)?;
    }
    let v =
        verify_sign1(backend, sign1, &set, content_type).map_err(|_| StatementError::Signature)?;
    Ok((v.payload, v.kid))
}
