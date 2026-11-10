//! The cell's ACME account key (OP-156 m.3 (i)): one ECDSA P-256 key per cell, made on its
//! first request and kept sealed in the vault, which signs nothing but the JWS of an RFC 8555
//! request: a protected header of exactly `alg: ES256`, `nonce`, `url` and one of `jwk` or `kid`.

use access_crypto::jose::JwsAlg;
use access_kernel::json::b64url_decode;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::signer::Signer;

use crate::ports::KeyFactory;
use crate::protocol::{FrameError, Realm};

/// The key's label in the vault and in the protocol.
pub const LABEL: &str = "acme";

/// Largest signing input signed: an ACME request body is small (PD).
pub const MAX_INPUT: usize = 64 * 1024;

/// The vault slot the key is stored under, apart from every realm's.
#[must_use]
pub fn slot() -> Realm {
    let d = suiss_crypto::digest::context_digest("access/identity-signer/acme/v1", b"cell");
    let mut out = [0; 16];
    out.copy_from_slice(d.0.get(..16).unwrap_or(&[0; 16]));
    Realm(out)
}

/// A request about the ACME account key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcmeRequest {
    /// The account key's public point.
    Key,
    /// Signs the JWS signing input of an ACME request.
    Sign {
        /// `BASE64URL(protected) || '.' || BASE64URL(payload)`.
        input: Vec<u8>,
    },
}

/// An answer about the ACME account key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcmeResponse {
    /// The uncompressed SEC1 public point.
    Key {
        /// The point.
        point: Vec<u8>,
    },
    /// The raw `r ‖ s` signature.
    Signed {
        /// The signature.
        signature: Vec<u8>,
    },
}

impl AcmeRequest {
    /// The protocol value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Key => Value::Map(vec![(Value::text("key"), Value::Bool(true))]),
            Self::Sign { input } => {
                Value::Map(vec![(Value::text("sign"), Value::Bytes(input.clone()))])
            }
        }
    }

    /// The request of a protocol value.
    ///
    /// # Errors
    /// [`FrameError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, FrameError> {
        if v.get("key").is_some() {
            return Ok(Self::Key);
        }
        match v.get("sign") {
            Some(Value::Bytes(b)) => Ok(Self::Sign { input: b.clone() }),
            _ => Err(FrameError::Malformed),
        }
    }
}

impl AcmeResponse {
    /// The protocol value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Key { point } => {
                Value::Map(vec![(Value::text("key"), Value::Bytes(point.clone()))])
            }
            Self::Signed { signature } => Value::Map(vec![(
                Value::text("signed"),
                Value::Bytes(signature.clone()),
            )]),
        }
    }

    /// The answer of a protocol value.
    ///
    /// # Errors
    /// [`FrameError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, FrameError> {
        match (v.get("key"), v.get("signed")) {
            (Some(Value::Bytes(point)), None) => Ok(Self::Key {
                point: point.clone(),
            }),
            (None, Some(Value::Bytes(signature))) => Ok(Self::Signed {
                signature: signature.clone(),
            }),
            _ => Err(FrameError::Malformed),
        }
    }
}

/// Why the ACME key refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AcmeKeyError {
    /// The input is not the signing input of an ACME request.
    #[error("not an acme request")]
    NotAcme,
    /// The stored key cannot be read, or none could be made or stored.
    #[error("acme key unusable")]
    Stored,
    /// The key could not sign.
    #[error("sign")]
    Sign,
}

impl AcmeKeyError {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotAcme => "signer-acme-input",
            Self::Stored => "signer-acme-key",
            Self::Sign => "signer-sign",
        }
    }
}

/// Whether `input` is the signing input of an RFC 8555 request (§6.2).
#[must_use]
pub fn acme_input(input: &[u8]) -> bool {
    if input.len() > MAX_INPUT {
        return false;
    }
    let Ok(text) = core::str::from_utf8(input) else {
        return false;
    };
    let Some((protected, payload)) = text.split_once('.') else {
        return false;
    };
    let b64 = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if !b64(payload) {
        return false;
    }
    let Ok(header) = b64url_decode(protected) else {
        return false;
    };
    let Ok(access_kernel::json::Json::Object(members)) =
        access_kernel::json::parse(&header, MAX_INPUT)
    else {
        return false;
    };
    let mut names: Vec<&str> = members.iter().map(|(k, _)| k.as_str()).collect();
    names.sort_unstable();
    let text_of = |name: &str| {
        members.iter().find_map(|(k, v)| match v {
            access_kernel::json::Json::Str(s) if k == name => Some(s.as_str()),
            _ => None,
        })
    };
    let who = matches!(names.as_slice(), ["alg", "jwk", "nonce", "url"])
        || (matches!(names.as_slice(), ["alg", "kid", "nonce", "url"])
            && text_of("kid").is_some_and(|k| k.starts_with("https://")));
    who && text_of("alg") == Some("ES256")
        && text_of("nonce").is_some_and(|n| !n.is_empty())
        && text_of("url").is_some_and(|u| u.starts_with("https://"))
}

/// The cell's ACME account key.
pub struct AcmeKey {
    signer: Box<dyn Signer + Send>,
    sealed: Vec<u8>,
}

fn point(signer: &dyn Signer) -> Option<Vec<u8>> {
    match signer.public_key() {
        PublicKey::P256(p) if p.len() == 65 => Some(p),
        _ => None,
    }
}

impl AcmeKey {
    /// A new key, sealed by the factory.
    ///
    /// # Errors
    /// [`AcmeKeyError::Stored`].
    pub fn generate<F: KeyFactory + ?Sized>(factory: &mut F) -> Result<Self, AcmeKeyError> {
        let g = factory
            .generate(JwsAlg::Es256)
            .map_err(|_| AcmeKeyError::Stored)?;
        point(g.signer.as_ref()).ok_or(AcmeKeyError::Stored)?;
        Ok(Self {
            signer: g.signer,
            sealed: g.sealed,
        })
    }

    /// The key of its stored form; the stored point must match the unsealed key.
    ///
    /// # Errors
    /// [`AcmeKeyError::Stored`].
    pub fn restore<F: KeyFactory + ?Sized>(
        stored: &[u8],
        factory: &mut F,
    ) -> Result<Self, AcmeKeyError> {
        let v = dcbor::decode(stored, Limits::CEILING).map_err(|_| AcmeKeyError::Stored)?;
        let (Some(Value::Text(label)), Some(Value::Bytes(key)), Some(Value::Bytes(sealed))) =
            (v.get("label"), v.get("key"), v.get("sealed"))
        else {
            return Err(AcmeKeyError::Stored);
        };
        if label != LABEL {
            return Err(AcmeKeyError::Stored);
        }
        let signer = factory
            .load(JwsAlg::Es256, sealed)
            .map_err(|_| AcmeKeyError::Stored)?;
        if point(signer.as_ref()).as_ref() != Some(key) {
            return Err(AcmeKeyError::Stored);
        }
        Ok(Self {
            signer,
            sealed: sealed.clone(),
        })
    }

    /// The stored form: label, public point and sealed private material, never plaintext.
    #[must_use]
    pub fn stored(&self) -> Option<Vec<u8>> {
        let v = Value::Map(vec![
            (Value::text("label"), Value::text(LABEL)),
            (
                Value::text("key"),
                Value::Bytes(point(self.signer.as_ref())?),
            ),
            (Value::text("sealed"), Value::Bytes(self.sealed.clone())),
        ]);
        dcbor::encode(&v, Limits::CEILING).ok()
    }

    /// Answers `request`.
    ///
    /// # Errors
    /// [`AcmeKeyError::NotAcme`] for input that is not an ACME request; [`AcmeKeyError`] when
    /// the key cannot answer.
    pub fn answer(&self, request: &AcmeRequest) -> Result<AcmeResponse, AcmeKeyError> {
        match request {
            AcmeRequest::Key => Ok(AcmeResponse::Key {
                point: point(self.signer.as_ref()).ok_or(AcmeKeyError::Stored)?,
            }),
            AcmeRequest::Sign { input } => {
                if !acme_input(input) {
                    return Err(AcmeKeyError::NotAcme);
                }
                let signature = self.signer.sign(input).map_err(|_| AcmeKeyError::Sign)?;
                Ok(AcmeResponse::Signed { signature })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use access_kernel::json::b64url_encode;

    fn input(header: &str) -> Vec<u8> {
        format!(
            "{}.{}",
            b64url_encode(header.as_bytes()),
            b64url_encode(b"{}")
        )
        .into_bytes()
    }

    // OP-156 m.3 (i), CR-21
    #[test]
    fn only_acme_request_headers_are_signed() {
        assert!(acme_input(&input(
            r#"{"alg":"ES256","kid":"https://acme.example/acct/1","nonce":"n","url":"https://acme.example/order"}"#
        )));
        assert!(acme_input(&input(
            r#"{"alg":"ES256","jwk":{"kty":"EC"},"nonce":"n","url":"https://acme.example/acct"}"#
        )));
        for bad in [
            r#"{"alg":"ES256","kid":"k","typ":"JWT","nonce":"n","url":"https://a.example/"}"#,
            r#"{"alg":"ES256","nonce":"n","url":"https://a.example/"}"#,
            r#"{"alg":"EdDSA","kid":"https://a.example/a","nonce":"n","url":"https://a.example/"}"#,
            r#"{"alg":"ES256","kid":"https://a.example/a","nonce":"n","url":"http://a.example/"}"#,
            r#"{"typ":"JWT","alg":"ES256"}"#,
        ] {
            assert!(!acme_input(&input(bad)), "{bad}");
        }
        assert!(!acme_input(b"not.base64!"));
        let req = AcmeRequest::Sign { input: vec![1, 2] };
        assert_eq!(AcmeRequest::from_value(&req.to_value()).unwrap(), req);
        let res = AcmeResponse::Key { point: vec![4; 65] };
        assert_eq!(AcmeResponse::from_value(&res.to_value()).unwrap(), res);
    }
}
