//! The SAML operations of the parser worker (OP-155 m.3 (c), (d), §10.6.1, IDI-8): what a gateway
//! asks a worker to read and verify, and the facts the worker returns. The worker reads the
//! untrusted message, verifies its signature against the certificates the gateway names (the
//! service provider's pinned ones, never a certificate the message carries) and returns facts
//! read from the very element whose signature it verified. Sans-I/O.

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::ipc::FrameError;

pub use access_internal_api::saml::{
    AssertionFacts, Facts, Kind, MAX_ATTRIBUTES, MAX_CERT, MAX_CERTS, MAX_LIST, MAX_TEXT, Signed,
    decode_verified, encode_verified,
};

/// What a gateway asks the worker to do with one SAML message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// The message is raw DEFLATE (HTTP-Redirect binding) and is inflated first.
    pub inflate: bool,
    /// The service provider's pinned certificates, DER; empty when it is not known yet.
    pub certs: Vec<Vec<u8>>,
    /// A message without a valid enveloped signature is refused.
    pub require_signature: bool,
}

/// A detached HTTP-Redirect signature to verify (SAML Bindings §3.4.4.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Redirect {
    /// The service provider's pinned certificates, DER.
    pub certs: Vec<Vec<u8>>,
    /// `SigAlg`, decoded.
    pub sig_alg: String,
    /// The signed octets: the original URL-encoded `SAMLRequest`, `RelayState` and `SigAlg`.
    pub signed: Vec<u8>,
    /// `Signature`, base64-decoded.
    pub signature: Vec<u8>,
}

fn put(out: &mut Vec<u8>, part: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(part.len()).map_err(|_| FrameError::TooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(part);
    Ok(())
}

fn split(input: &[u8]) -> Result<(Value, &[u8]), FrameError> {
    let (prefix, rest) = input
        .split_first_chunk::<4>()
        .ok_or(FrameError::Truncated)?;
    let n = crate::ipc::length(*prefix, crate::ipc::MAX_HEADER.saturating_mul(32))?;
    if rest.len() < n {
        return Err(FrameError::Truncated);
    }
    let (head, doc) = rest.split_at(n);
    let v = dcbor::decode(head, Limits::CEILING).map_err(|_| FrameError::Malformed)?;
    Ok((v, doc))
}

fn certs_value(certs: &[Vec<u8>]) -> Value {
    Value::Array(certs.iter().map(|c| Value::Bytes(c.clone())).collect())
}

fn certs_of(v: &Value) -> Result<Vec<Vec<u8>>, FrameError> {
    let Some(Value::Array(list)) = v.get("certs") else {
        return Err(FrameError::Malformed);
    };
    if list.len() > MAX_CERTS {
        return Err(FrameError::TooLarge);
    }
    list.iter()
        .map(|c| match c {
            Value::Bytes(b) if !b.is_empty() && b.len() <= MAX_CERT => Ok(b.clone()),
            _ => Err(FrameError::Malformed),
        })
        .collect()
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn encoded(v: &Value) -> Result<Vec<u8>, FrameError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| FrameError::TooLarge)
}

fn flag(v: &Value, key: &str) -> Result<bool, FrameError> {
    match v.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(FrameError::Malformed),
    }
}

fn bytes(v: &Value, key: &str) -> Result<Vec<u8>, FrameError> {
    match v.get(key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn text(v: &Value, key: &str) -> Result<String, FrameError> {
    match v.get(key) {
        Some(Value::Text(t)) if t.len() <= MAX_TEXT => Ok(t.clone()),
        _ => Err(FrameError::Malformed),
    }
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

impl Context {
    /// The worker input: this context, then the message.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`].
    pub fn encode(&self, message: &[u8]) -> Result<Vec<u8>, FrameError> {
        let head = encoded(&map(vec![
            ("inflate", Value::Bool(self.inflate)),
            ("certs", certs_value(&self.certs)),
            ("require_signature", Value::Bool(self.require_signature)),
        ]))?;
        let mut out = Vec::new();
        put(&mut out, &head)?;
        out.extend_from_slice(message);
        Ok(out)
    }

    /// Reads a worker input.
    ///
    /// # Errors
    /// [`FrameError`].
    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), FrameError> {
        let (v, message) = split(input)?;
        only(&v, &["inflate", "certs", "require_signature"])?;
        Ok((
            Self {
                inflate: flag(&v, "inflate")?,
                certs: certs_of(&v)?,
                require_signature: flag(&v, "require_signature")?,
            },
            message,
        ))
    }
}

impl Redirect {
    /// The worker input.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`].
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let head = encoded(&map(vec![
            ("certs", certs_value(&self.certs)),
            ("sig_alg", Value::text(&self.sig_alg)),
            ("signed", Value::Bytes(self.signed.clone())),
            ("signature", Value::Bytes(self.signature.clone())),
        ]))?;
        let mut out = Vec::new();
        put(&mut out, &head)?;
        Ok(out)
    }

    /// Reads a worker input.
    ///
    /// # Errors
    /// [`FrameError`].
    pub fn decode(input: &[u8]) -> Result<Self, FrameError> {
        let (v, rest) = split(input)?;
        if !rest.is_empty() {
            return Err(FrameError::Malformed);
        }
        only(&v, &["certs", "sig_alg", "signed", "signature"])?;
        Ok(Self {
            certs: certs_of(&v)?,
            sig_alg: text(&v, "sig_alg")?,
            signed: bytes(&v, "signed")?,
            signature: bytes(&v, "signature")?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (c)
    #[test]
    fn inputs_and_facts_round_trip() {
        let c = Context {
            inflate: true,
            certs: vec![vec![0x30, 0x00]],
            require_signature: true,
        };
        let input = c.encode(b"<a/>").unwrap();
        let (back, doc) = Context::decode(&input).unwrap();
        assert_eq!(back, c);
        assert_eq!(doc, b"<a/>");
        let r = Redirect {
            certs: vec![vec![1]],
            sig_alg: String::from("urn:x"),
            signed: b"SAMLRequest=x".to_vec(),
            signature: vec![2; 3],
        };
        assert_eq!(Redirect::decode(&r.encode().unwrap()).unwrap(), r);
        let f = crate::saml::Facts {
            kind: Kind::Authn,
            id: String::from("_1"),
            issue_instant: String::from("2026-01-01T00:00:00Z"),
            destination: Some(String::from("https://idp/sso")),
            issuer: String::from("https://sp"),
            acs_url: None,
            acs_index: Some(1),
            protocol_binding: None,
            force_authn: true,
            is_passive: false,
            nameid_format: None,
            allow_create: Some(false),
            sp_name_qualifier: None,
            requester_ids: vec![String::from("urn:r")],
            proxy_count: Some(0),
            signed: Signed::Verified(String::from("urn:alg")),
            name_id: None,
            session_indexes: vec![],
            soap: false,
        };
        assert_eq!(Facts::decode(&f.encode().unwrap()).unwrap(), f);
        assert_eq!(
            decode_verified(&encode_verified("a").unwrap()).unwrap(),
            "a"
        );
        let too_many = Context {
            certs: vec![vec![1]; MAX_CERTS + 1],
            ..Context::default()
        };
        assert_eq!(
            Context::decode(&too_many.encode(b"").unwrap()),
            Err(FrameError::TooLarge)
        );
    }
}
